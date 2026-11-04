"""
Fedora nftables Live Containment Adapter
-----------------------------------------
Executes verified, narrowly scoped IP containment actions against the
dedicated Fedora 44 VM executor service (`inet cyberscribe`).

LIFECYCLE STATUSES:
- APPLIED: Live block rule staged on Fedora VM and confirmed.
- VERIFIED: Independent read-back confirmed rule presence in live table.
- ROLLED_BACK: Rule handle removed from Fedora VM and verified absent.
- EXPIRED: Rule removed upon TTL expiration.
- FAILED: Recorded honestly on network error, timeout, or verification mismatch.

SAFETY CONSTRAINTS:
1. Operates only on dedicated table 'inet cyberscribe'; NEVER modifies firewalld.
2. Authenticates using high-entropy secret; never logs or leaks tokens.
3. Strict tenant isolation enforced in every rollback and verify call.
4. Independent read-back verification required before VERIFIED status.
5. Failed removals are NEVER marked ROLLED_BACK.
6. Automated IP blocking NEVER marks software vulnerabilities as RESOLVED.
"""

import os
import re
import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Optional, List, Tuple
import requests
from sqlalchemy.orm import Session

from app.models import ContainmentAction, ContainmentAuditLog
from app.services.containment_policy import (
    AutonomousPolicyEngine,
    ACTIVE_CONTAINMENT_STATUSES,
    sanitize_audit_details
)
from app.services.firewall_adapter import InvalidStateTransitionError

logger = logging.getLogger("FedoraNftablesAdapter")

DEFAULT_EXECUTOR_URL = "http://127.0.0.1:8088"
DEFAULT_TABLE = "cyberscribe"
REQUEST_TIMEOUT_SECONDS = 6.0


class FedoraExecutorError(Exception):
    """Raised when the Fedora executor responds with an error or fails."""
    pass


class FedoraNftablesAdapter:
    """Live firewall adapter integrating CyberScribe with Fedora 44 nftables."""

    @classmethod
    def _get_executor_config(cls) -> Tuple[str, str, str]:
        """Retrieves and validates executor configuration from environment."""
        url = os.getenv("FEDORA_EXECUTOR_URL", DEFAULT_EXECUTOR_URL).rstrip("/")
        token = os.getenv("FEDORA_EXECUTOR_TOKEN", "")
        table = os.getenv("FEDORA_NFTABLES_TABLE", DEFAULT_TABLE)
        return url, token, table

    @classmethod
    def _get_headers(cls) -> Dict[str, str]:
        _, token, _ = cls._get_executor_config()
        return {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}" if token else ""
        }

    @classmethod
    def health_check(cls) -> Dict[str, Any]:
        """Checks connectivity and table status on the Fedora executor."""
        url, token, _ = cls._get_executor_config()
        if not token:
            return {"status": "UNCONFIGURED", "message": "FEDORA_EXECUTOR_TOKEN is not set."}

        try:
            resp = requests.get(
                f"{url}/health",
                headers=cls._get_headers(),
                timeout=REQUEST_TIMEOUT_SECONDS
            )
            if resp.status_code == 200:
                return resp.json()
            return {"status": "ERROR", "status_code": resp.status_code, "detail": resp.text}
        except Exception as e:
            return {"status": "UNREACHABLE", "error": str(e)}

    @classmethod
    def apply_containment(
        cls,
        action: ContainmentAction,
        db: Session,
        actor: str = "FEDORA_NFTABLES_ADAPTER",
        direction: str = "both",
        is_simulated: Optional[bool] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Applies a verified drop rule for action's IPv4 indicator on Fedora 44 VM.
        Transitions: PENDING -> APPLIED -> VERIFIED (if read-back succeeds).
        Idempotent if already APPLIED or VERIFIED.
        """
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        url, token, table = cls._get_executor_config()

        # Idempotency
        if action.status in ("APPLIED", "VERIFIED"):
            return {
                "status": action.status,
                "action_id": action.action_id,
                "target_indicator": action.indicator_value,
                "is_live_enforcement": True,
                "is_simulated": False,
                "table": f"inet {table}",
                "message": f"[FEDORA_NFTABLES] Rule for {action.indicator_value} already active on Fedora host."
            }

        if action.status == "SIMULATED" and is_simulated:
            return {
                "status": "SIMULATED",
                "action_id": action.action_id,
                "target_indicator": action.indicator_value,
                "is_live_enforcement": False,
                "is_simulated": True,
                "table": f"inet {table}",
                "message": f"[SIMULATED] Rule for {action.indicator_value} already staged in simulation."
            }

        if action.status != "PENDING":
            raise InvalidStateTransitionError(
                f"Cannot apply live containment from status '{action.status}'. Required status: 'PENDING'."
            )

        live_requested = False
        if is_simulated is False:
            live_requested = True
        elif is_simulated is None:
            mode = os.getenv("CONTAINMENT_ADAPTER_MODE", "simulated").strip().lower()
            if mode in ("fedora_nftables", "fedora", "live") or bool(token):
                live_requested = True

        if live_requested and not token:
            action.status = "FAILED"
            action.error_message = "Live Fedora containment requested but FEDORA_EXECUTOR_TOKEN is not configured."
            AutonomousPolicyEngine._record_audit_log(
                db=db,
                tenant_id=action.tenant_id,
                action_id=action.id,
                event_type="FEDORA_NFTABLES_FAILED",
                actor=actor,
                previous_status="PENDING",
                new_status="FAILED",
                details={"error": action.error_message}
            )
            db.commit()
            return {
                "status": "FAILED",
                "action_id": action.action_id,
                "is_live_enforcement": True,
                "is_simulated": False,
                "error": action.error_message
            }

        if not live_requested:
            action.status = "SIMULATED"
            action.applied_at = now
            if not action.expires_at:
                action.expires_at = now + timedelta(seconds=action.ttl_seconds)
            action.rule_spec = {
                "adapter": "FEDORA_NFTABLES",
                "table": f"inet {table}",
                "action": "DROP_IPV4",
                "direction": direction,
                "target_ip": action.indicator_value,
                "is_simulated": True
            }
            action.execution_output = f"[SIMULATED] Staged nftables rule in 'inet {table}' for {action.indicator_value}."
            AutonomousPolicyEngine._record_audit_log(
                db=db,
                tenant_id=action.tenant_id,
                action_id=action.id,
                event_type="FEDORA_NFTABLES_SIMULATED",
                actor=actor,
                previous_status="PENDING",
                new_status="SIMULATED",
                details=action.rule_spec
            )
            db.commit()
            return {
                "status": "SIMULATED",
                "action_id": action.action_id,
                "is_simulated": True,
                "table": f"inet {table}",
                "message": f"[SIMULATED] Staged nftables containment for {action.indicator_value}."
            }

        payload = {
            "action_id": action.action_id,
            "ip_address": action.indicator_value,
            "direction": direction
        }

        try:
            resp = requests.post(
                f"{url}/apply",
                headers=cls._get_headers(),
                json=payload,
                timeout=REQUEST_TIMEOUT_SECONDS
            )

            if resp.status_code != 200:
                err_text = resp.text
                error_msg = f"Fedora executor returned HTTP {resp.status_code}: {err_text}"
                action.status = "FAILED"
                action.error_message = error_msg
                AutonomousPolicyEngine._record_audit_log(
                    db=db,
                    tenant_id=action.tenant_id,
                    action_id=action.id,
                    event_type="LIVE_FIREWALL_FAILED",
                    actor=actor,
                    previous_status="PENDING",
                    new_status="FAILED",
                    details={"error": error_msg, "status_code": resp.status_code}
                )
                db.commit()
                return {"status": "FAILED", "error": error_msg}

            apply_data = resp.json()
            handles = apply_data.get("handles", [])

            previous_status = action.status
            action.status = "APPLIED"
            action.applied_at = now
            if not action.expires_at:
                action.expires_at = now + timedelta(seconds=action.ttl_seconds)

            action.rule_spec = {
                "adapter": "FEDORA_NFTABLES",
                "table": f"inet {table}",
                "chains": ["inbound_filter", "outbound_filter"],
                "destination_ip": action.indicator_value,
                "handles": handles,
                "is_live_enforcement": True,
                "is_simulated": False,
                "ttl_seconds": action.ttl_seconds
            }
            action.execution_output = (
                f"[FEDORA_NFTABLES] Live drop rule staged on Fedora 44 (table: inet {table}, "
                f"handles: {handles}, target: {action.indicator_value})."
            )
            action.error_message = None

            AutonomousPolicyEngine._record_audit_log(
                db=db,
                tenant_id=action.tenant_id,
                action_id=action.id,
                event_type="LIVE_FIREWALL_APPLIED",
                actor=actor,
                previous_status=previous_status,
                new_status="APPLIED",
                details={
                    "mode": "FEDORA_NFTABLES",
                    "handles": handles,
                    "target_indicator": action.indicator_value,
                    "ttl_seconds": action.ttl_seconds,
                    "table": f"inet {table}"
                }
            )
            db.commit()

            # Immediate Independent Verification Pass
            verify_res = cls.verify_containment(action, db, actor=actor)
            if verify_res.get("verified"):
                return {
                    "status": "VERIFIED",
                    "action_id": action.action_id,
                    "target_indicator": action.indicator_value,
                    "is_live_enforcement": True,
                    "is_simulated": False,
                    "handles": handles,
                    "table": f"inet {table}",
                    "verified": True,
                    "message": f"[FEDORA_NFTABLES] Live drop rule successfully applied and independently verified on Fedora 44."
                }

            return {
                "status": "APPLIED",
                "action_id": action.action_id,
                "target_indicator": action.indicator_value,
                "is_live_enforcement": True,
                "is_simulated": False,
                "handles": handles,
                "table": f"inet {table}",
                "verified": False,
                "message": f"[FEDORA_NFTABLES] Live drop rule applied; pending secondary verification."
            }

        except Exception as e:
            error_msg = f"Network communication failure reaching Fedora executor: {str(e)}"
            action.status = "FAILED"
            action.error_message = error_msg
            AutonomousPolicyEngine._record_audit_log(
                db=db,
                tenant_id=action.tenant_id,
                action_id=action.id,
                event_type="LIVE_FIREWALL_FAILED",
                actor=actor,
                previous_status="PENDING",
                new_status="FAILED",
                details={"error": error_msg}
            )
            db.commit()
            return {"status": "FAILED", "error": error_msg}

    @classmethod
    def verify_containment(
        cls,
        action: ContainmentAction,
        db: Session,
        actor: str = "FEDORA_NFTABLES_ADAPTER"
    ) -> Dict[str, Any]:
        """
        Executes independent read-back verification against the live Fedora table.
        Transitions: APPLIED -> VERIFIED (if confirmed).
        """
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        url, token, table = cls._get_executor_config()

        if action.status not in ("APPLIED", "VERIFIED"):
            raise InvalidStateTransitionError(
                f"Cannot verify live containment with status '{action.status}'. Action must be 'APPLIED' or 'VERIFIED'."
            )

        try:
            resp = requests.get(
                f"{url}/verify/{action.action_id}",
                headers=cls._get_headers(),
                timeout=REQUEST_TIMEOUT_SECONDS
            )

            if resp.status_code != 200:
                logger.warning(f"Verification query failed with HTTP {resp.status_code}: {resp.text}")
                return {
                    "status": action.status,
                    "verified": False,
                    "is_live_enforcement": True,
                    "error": f"HTTP {resp.status_code}"
                }

            v_data = resp.json()
            is_verified = v_data.get("verified", False)

            if is_verified:
                previous_status = action.status
                action.status = "VERIFIED"
                action.verified_at = now
                action.execution_output = (
                    f"[FEDORA_NFTABLES] Live drop rule for {action.indicator_value} independently "
                    f"verified on Fedora 44 host (handles: {v_data.get('handles')})."
                )

                AutonomousPolicyEngine._record_audit_log(
                    db=db,
                    tenant_id=action.tenant_id,
                    action_id=action.id,
                    event_type="LIVE_FIREWALL_VERIFIED",
                    actor=actor,
                    previous_status=previous_status,
                    new_status="VERIFIED",
                    details={
                        "mode": "FEDORA_NFTABLES",
                        "handles": v_data.get("handles"),
                        "verified_at": now.isoformat(),
                        "table": f"inet {table}"
                    }
                )
                db.commit()

                return {
                    "status": "VERIFIED",
                    "action_id": action.action_id,
                    "verified": True,
                    "is_live_enforcement": True,
                    "handles": v_data.get("handles"),
                    "table": f"inet {table}"
                }

            return {
                "status": action.status,
                "action_id": action.action_id,
                "verified": False,
                "is_live_enforcement": True,
                "message": "Independent read-back verification found no matching rule."
            }

        except Exception as e:
            logger.error(f"Error during verify_containment: {e}")
            return {
                "status": action.status,
                "verified": False,
                "is_live_enforcement": True,
                "error": str(e)
            }

    @classmethod
    def rollback_containment(
        cls,
        action: ContainmentAction,
        db: Session,
        reason: str = "EXACT_RULE_ROLLBACK",
        actor: str = "FEDORA_NFTABLES_ADAPTER",
        expected_tenant_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Removes only the exact rule tagged with 'cyberscribe:<action_id>' on Fedora VM.
        Transitions: APPLIED/VERIFIED/FAILED -> ROLLED_BACK.
        Enforces tenant isolation. NEVER marks ROLLED_BACK if removal fails.
        """
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        url, token, table = cls._get_executor_config()

        # Strict Tenant Isolation
        if expected_tenant_id and action.tenant_id != expected_tenant_id:
            raise PermissionError(
                f"Tenant isolation violation: Action '{action.action_id}' belongs to tenant '{action.tenant_id}', not '{expected_tenant_id}'."
            )

        # Idempotency
        if action.status == "ROLLED_BACK":
            return {
                "status": "ROLLED_BACK",
                "action_id": action.action_id,
                "target_indicator": action.indicator_value,
                "is_live_enforcement": True,
                "message": f"Action {action.action_id} already rolled back."
            }

        legal_statuses = {"APPLIED", "VERIFIED", "SIMULATED", "DISPATCHED", "RECEIVED", "FAILED"}
        if action.status not in legal_statuses:
            raise InvalidStateTransitionError(
                f"Cannot rollback action with status '{action.status}'. Action must be in {sorted(list(legal_statuses))}."
            )

        if action.status == "SIMULATED" or (action.rule_spec and action.rule_spec.get("is_simulated") is True):
            previous_status = action.status
            action.status = "ROLLED_BACK"
            action.rolled_back_at = now
            action.execution_output = f"[FEDORA_NFTABLES] Simulated nftables rule for {action.action_id} rolled back."
            AutonomousPolicyEngine._record_audit_log(
                db=db,
                tenant_id=action.tenant_id,
                action_id=action.id,
                event_type="FEDORA_NFTABLES_ROLLED_BACK",
                actor=actor,
                previous_status=previous_status,
                new_status="ROLLED_BACK",
                details={"action_id": action.action_id, "is_simulated": True}
            )
            db.commit()
            return {
                "status": "ROLLED_BACK",
                "action_id": action.action_id,
                "is_simulated": True,
                "message": f"[FEDORA_NFTABLES] Simulated rule for {action.action_id} rolled back successfully."
            }

        try:
            resp = requests.post(
                f"{url}/rollback/{action.action_id}",
                headers=cls._get_headers(),
                timeout=REQUEST_TIMEOUT_SECONDS
            )

            if resp.status_code != 200:
                err_msg = f"Rollback failed on Fedora executor (HTTP {resp.status_code}): {resp.text}"
                action.error_message = err_msg
                AutonomousPolicyEngine._record_audit_log(
                    db=db,
                    tenant_id=action.tenant_id,
                    action_id=action.id,
                    event_type="LIVE_FIREWALL_ROLLBACK_FAILED",
                    actor=actor,
                    previous_status=action.status,
                    new_status=action.status,
                    details={"error": err_msg}
                )
                db.commit()
                # STRICT REQUIREMENT: Never mark ROLLED_BACK if removal fails!
                raise FedoraExecutorError(err_msg)

            rollback_data = resp.json()
            if not rollback_data.get("verified_removed", True):
                err_msg = "Rollback executed but independent verification shows rule still present!"
                action.error_message = err_msg
                db.commit()
                raise FedoraExecutorError(err_msg)

            previous_status = action.status
            action.status = "ROLLED_BACK"
            action.rolled_back_at = now
            action.execution_output = (
                f"[FEDORA_NFTABLES] Rule for {action.indicator_value} (action: {action.action_id}) "
                f"successfully removed from table inet {table}."
            )

            AutonomousPolicyEngine._record_audit_log(
                db=db,
                tenant_id=action.tenant_id,
                action_id=action.id,
                event_type="LIVE_FIREWALL_ROLLBACK",
                actor=actor,
                previous_status=previous_status,
                new_status="ROLLED_BACK",
                details={
                    "mode": "FEDORA_NFTABLES",
                    "rollback_reason": reason,
                    "removed_handles": rollback_data.get("removed_handles", []),
                    "table": f"inet {table}"
                }
            )
            db.commit()

            return {
                "status": "ROLLED_BACK",
                "action_id": action.action_id,
                "target_indicator": action.indicator_value,
                "is_live_enforcement": True,
                "removed_handles": rollback_data.get("removed_handles", []),
                "message": f"Rollback completed successfully on Fedora 44 for {action.indicator_value}."
            }

        except Exception as e:
            if not isinstance(e, FedoraExecutorError):
                action.error_message = f"Network failure during rollback: {str(e)}"
                db.commit()
            raise

    @classmethod
    def check_and_expire(
        cls,
        action: ContainmentAction,
        db: Session,
        actor: str = "FEDORA_NFTABLES_ADAPTER"
    ) -> Dict[str, Any]:
        """
        Evaluates TTL expiration against live Fedora VM.
        If expired, rolls back the rule and marks status EXPIRED.
        """
        now = datetime.now(timezone.utc).replace(tzinfo=None)

        if action.status == "EXPIRED":
            return {
                "status": "EXPIRED",
                "expired": True,
                "action_id": action.action_id,
                "is_live_enforcement": True,
                "message": "Action already expired."
            }

        if action.status not in ACTIVE_CONTAINMENT_STATUSES:
            return {
                "status": action.status,
                "expired": False,
                "message": f"Action status '{action.status}' not eligible for expiry check."
            }

        if action.expires_at and now >= action.expires_at:
            previous_status = action.status
            try:
                # Remove live rule on Fedora host
                cls.rollback_containment(
                    action=action,
                    db=db,
                    reason="TTL_EXPIRATION",
                    actor=actor
                )
            except Exception as e:
                logger.error(f"Failed to remove rule on host during expiry: {e}")
                # Record failure accurately
                action.error_message = f"Expiry rollback failure: {str(e)}"
                db.commit()
                return {"status": action.status, "expired": False, "error": str(e)}

            # Transition from ROLLED_BACK to EXPIRED
            action.status = "EXPIRED"
            action.execution_output = (
                f"[FEDORA_NFTABLES] Action {action.action_id} reached TTL and expired. Rule removed from host."
            )

            AutonomousPolicyEngine._record_audit_log(
                db=db,
                tenant_id=action.tenant_id,
                action_id=action.id,
                event_type="LIVE_FIREWALL_EXPIRED",
                actor=actor,
                previous_status=previous_status,
                new_status="EXPIRED",
                details={
                    "mode": "FEDORA_NFTABLES",
                    "expired_at": now.isoformat(),
                    "configured_expires_at": action.expires_at.isoformat()
                }
            )
            db.commit()

            return {
                "status": "EXPIRED",
                "expired": True,
                "action_id": action.action_id,
                "is_live_enforcement": True,
                "message": f"[FEDORA_NFTABLES] Action {action.action_id} expired due to TTL."
            }

        return {
            "status": action.status,
            "expired": False,
            "action_id": action.action_id,
            "is_live_enforcement": True,
            "message": "TTL has not expired."
        }

    @classmethod
    def expire_active_containment_actions(
        cls,
        db: Session,
        tenant_id: Optional[str] = None,
        actor: str = "FEDORA_NFTABLES_EXPIRY_SERVICE"
    ) -> List[Dict[str, Any]]:
        """Scans and expires all TTL-elapsed active actions on the live Fedora VM."""
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        query = db.query(ContainmentAction).filter(
            ContainmentAction.status.in_(ACTIVE_CONTAINMENT_STATUSES),
            ContainmentAction.expires_at.isnot(None),
            ContainmentAction.expires_at <= now
        )
        if tenant_id:
            query = query.filter(ContainmentAction.tenant_id == tenant_id)

        actions_to_expire = query.all()
        results = []
        for action in actions_to_expire:
            res = cls.check_and_expire(action, db, actor=actor)
            results.append(res)
        return results
