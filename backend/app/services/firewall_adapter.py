"""
Simulated Firewall Adapter (Phase 1)
------------------------------------
Executes safe, simulated containment lifecycle operations:
  - apply_containment (status: SIMULATED)
  - verify_containment (status remains SIMULATED; sets verified_at)
  - rollback_containment (status: ROLLED_BACK)
  - check_and_expire (status: EXPIRED)

SAFETY CONSTRAINTS:
1. No host firewall commands, no raw iptables/nftables, and no privileged subprocesses.
2. Results are strictly labelled SIMULATED; never labelled ENFORCED or VERIFIED as real enforcement.
3. Strict state transition validation with InvalidStateTransitionError.
4. Idempotency guarantees for repeated apply or rollback calls.
5. All operations create immutable audit logs in `_containment_audit_logs`.
"""

import os
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Optional, List
from sqlalchemy.orm import Session

from app.models import ContainmentAction, ContainmentAuditLog
from app.services.containment_policy import AutonomousPolicyEngine, sanitize_audit_details, ACTIVE_CONTAINMENT_STATUSES


class InvalidStateTransitionError(Exception):
    """Raised when an illegal containment state transition is attempted."""
    pass


class SimulatedFirewallAdapter:
    """Safe simulated firewall adapter enforcing Phase 1 containment lifecycle."""

    @classmethod
    def apply_containment(
        cls,
        action: ContainmentAction,
        db: Session,
        actor: str = "SIMULATED_FIREWALL_ADAPTER",
        is_simulated: Optional[bool] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Simulates staging an egress drop rule for the action's IPv4 indicator.
        Transition: PENDING -> SIMULATED.
        Idempotent if already SIMULATED.
        """
        now = datetime.now(timezone.utc).replace(tzinfo=None)

        # Idempotency: If already simulated, return current simulated state
        if action.status == "SIMULATED":
            return {
                "status": "SIMULATED",
                "action_id": action.action_id,
                "target_indicator": action.indicator_value,
                "target_ip": action.indicator_value,
                "target_port": 8000,
                "is_live_enforcement": False,
                "is_simulated": True,
                "rule_spec": action.rule_spec,
                "message": f"[SIMULATED] Containment rule for {action.indicator_value} already active in simulated state."
            }

        # Validate legal starting state
        if action.status != "PENDING":
            raise InvalidStateTransitionError(
                f"Cannot apply containment from status '{action.status}'. Required status: 'PENDING'."
            )

        # Resolve traffic direction (inbound exploit source vs outbound C2 destination)
        direction = AutonomousPolicyEngine.resolve_containment_direction(action)
        if direction is None:
            reason = (
                "CONTAINMENT_DIRECTION_UNRESOLVED: Unable to establish whether IP is an inbound exploit source "
                "or outbound C2 destination from threat evidence and policy rules. Rule application rejected."
            )
            action.status = "REJECTED"
            action.error_message = reason
            AutonomousPolicyEngine._record_audit_log(
                db=db,
                tenant_id=action.tenant_id,
                action_id=action.id,
                event_type="CONTAINMENT_DIRECTION_UNRESOLVED",
                actor=actor,
                previous_status=action.status,
                new_status="REJECTED",
                details={"reason": reason, "requires_further_evidence_or_approval": True}
            )
            db.commit()
            return {
                "status": "REJECTED",
                "action_id": action.action_id,
                "error": reason,
                "direction": None,
                "is_live_enforcement": False,
                "is_simulated": True,
                "requires_further_evidence_or_approval": True
            }

        is_outbound = (direction == "out")

        try:
            rule_id = f"SIM-RULE-{action.action_id.upper()}"
            simulated_rule_spec = {
                "adapter": "SIMULATED_FIREWALL",
                "action": "DROP_EGRESS_IPV4" if is_outbound else "DROP_INGRESS_IPV4",
                "direction": "OUTBOUND" if is_outbound else "INBOUND",
                "rule_id": rule_id,
                "destination_ip": action.indicator_value if is_outbound else None,
                "source_ip": action.indicator_value if not is_outbound else None,
                "tenant_id": action.tenant_id,
                "is_simulated": True,
                "enforcement_tier": "PHASE_1_SIMULATED",
                "ttl_seconds": action.ttl_seconds
            }
            if not is_outbound:
                simulated_rule_spec["target_port"] = 8000

            previous_status = action.status
            action.status = "SIMULATED"
            action.applied_at = now
            if not action.expires_at:
                action.expires_at = now + timedelta(seconds=action.ttl_seconds)
            action.rule_spec = simulated_rule_spec
            if is_outbound:
                action.execution_output = (
                    f"[SIMULATED] Successfully staged egress drop rule for C2 destination {action.indicator_value} "
                    f"(rule: {rule_id}, ttl: {action.ttl_seconds}s). No host commands executed."
                )
            else:
                action.execution_output = (
                    f"[SIMULATED] Successfully staged ingress drop rule for exploit source {action.indicator_value} "
                    f"on port 8000 (rule: {rule_id}, ttl: {action.ttl_seconds}s). No host commands executed."
                )
            action.error_message = None

            AutonomousPolicyEngine._record_audit_log(
                db=db,
                tenant_id=action.tenant_id,
                action_id=action.id,
                event_type="SIMULATION_APPLIED",
                actor=actor,
                previous_status=previous_status,
                new_status="SIMULATED",
                details={
                    "mode": "SIMULATED",
                    "rule_id": rule_id,
                    "target_indicator": action.indicator_value,
                    "direction": "OUTBOUND" if is_outbound else "INBOUND",
                    "ttl_seconds": action.ttl_seconds,
                    "expires_at": action.expires_at.isoformat() if action.expires_at else None,
                    "is_live_enforcement": False
                }
            )
            db.commit()

            return {
                "status": "SIMULATED",
                "action_id": action.action_id,
                "target_indicator": action.indicator_value,
                "target_ip": action.indicator_value,
                "target_port": None if is_outbound else 8000,
                "direction": "OUTBOUND" if is_outbound else "INBOUND",
                "is_live_enforcement": False,
                "is_simulated": True,
                "rule_spec": simulated_rule_spec,
                "message": (
                    f"[SIMULATED] Containment successfully applied in simulation mode for C2 destination {action.indicator_value}."
                    if is_outbound else
                    f"[SIMULATED] Containment successfully applied in simulation mode for inbound source {action.indicator_value}."
                )
            }
        except Exception as err:
            action.status = "FAILED"
            action.error_message = f"Simulation execution failure: {str(err)}"
            AutonomousPolicyEngine._record_audit_log(
                db=db,
                tenant_id=action.tenant_id,
                action_id=action.id,
                event_type="SIMULATION_FAILED",
                actor=actor,
                previous_status="PENDING",
                new_status="FAILED",
                details={"error": str(err), "mode": "SIMULATED"}
            )
            db.commit()
            raise

    @classmethod
    def verify_containment(
        cls,
        action: ContainmentAction,
        db: Session,
        actor: str = "SIMULATED_FIREWALL_ADAPTER"
    ) -> Dict[str, Any]:
        """
        Verifies that a simulated rule is active and matches the indicator.
        Transition: SIMULATED -> SIMULATED (updates verified_at).
        NOTE: Results remain strictly labelled SIMULATED; never labelled ENFORCED or VERIFIED.
        """
        now = datetime.now(timezone.utc).replace(tzinfo=None)

        if action.status != "SIMULATED":
            raise InvalidStateTransitionError(
                f"Cannot verify containment with status '{action.status}'. Action must be 'SIMULATED'."
            )

        # Integrity verification of simulated rule specification
        rule_spec = action.rule_spec or {}
        rule_valid = (
            rule_spec.get("is_simulated") is True and
            rule_spec.get("destination_ip") == action.indicator_value and
            rule_spec.get("action") == "DROP_EGRESS_IPV4"
        )

        if not rule_valid:
            action.status = "FAILED"
            action.error_message = "[SIMULATED] Rule specification integrity verification failed."
            AutonomousPolicyEngine._record_audit_log(
                db=db,
                tenant_id=action.tenant_id,
                action_id=action.id,
                event_type="SIMULATION_FAILED",
                actor=actor,
                previous_status="SIMULATED",
                new_status="FAILED",
                details={"error": "Simulated rule spec corrupted or mismatched", "mode": "SIMULATED"}
            )
            db.commit()
            return {
                "status": "FAILED",
                "verified": False,
                "is_live_enforcement": False,
                "is_simulated": True,
                "message": "[SIMULATED] Verification failed: rule spec mismatch."
            }

        action.verified_at = now
        AutonomousPolicyEngine._record_audit_log(
            db=db,
            tenant_id=action.tenant_id,
            action_id=action.id,
            event_type="SIMULATION_VERIFIED",
            actor=actor,
            previous_status="SIMULATED",
            new_status="SIMULATED",
            details={
                "mode": "SIMULATED",
                "verified_at": now.isoformat(),
                "rule_id": rule_spec.get("rule_id"),
                "is_live_enforcement": False
            }
        )
        db.commit()

        return {
            "status": "SIMULATED",
            "verified": True,
            "is_live_enforcement": False,
            "is_simulated": True,
            "verified_at": now.isoformat(),
            "message": f"[SIMULATED] Simulated containment verified for {action.indicator_value}."
        }

    @classmethod
    def rollback_containment(
        cls,
        action: ContainmentAction,
        db: Session,
        reason: str = "EXACT_RULE_ROLLBACK",
        actor: str = "SIMULATED_FIREWALL_ADAPTER",
        expected_tenant_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Executes exact-rule rollback of a managed containment action with tenant verification.
        Transition: SIMULATED/RECEIVED/DISPATCHED/APPLIED/VERIFIED -> ROLLED_BACK.
        Idempotent if already ROLLED_BACK.
        """
        now = datetime.now(timezone.utc).replace(tzinfo=None)

        # Enforce tenant isolation
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
                "is_live_enforcement": False,
                "is_simulated": True,
                "message": f"[SIMULATED] Action for {action.indicator_value} already rolled back."
            }

        legal_rollback_statuses = {"SIMULATED", "RECEIVED", "DISPATCHED", "APPLIED", "VERIFIED"}
        if action.status not in legal_rollback_statuses:
            raise InvalidStateTransitionError(
                f"Cannot rollback action with status '{action.status}'. Action must be active in one of {sorted(list(legal_rollback_statuses))}."
            )

        previous_status = action.status
        rule_spec = action.rule_spec or {}
        rollback_spec = {
            "adapter": "SIMULATED_FIREWALL",
            "action": "DELETE_SIMULATED_RULE",
            "reversed_rule_id": rule_spec.get("rule_id", f"SIM-RULE-{action.action_id.upper()}"),
            "target_ip": action.indicator_value,
            "rollback_reason": reason,
            "is_simulated": True
        }

        action.status = "ROLLED_BACK"
        action.rolled_back_at = now
        action.execution_output = (
            f"[SIMULATED] Exact rule rollback applied for rule {rollback_spec['reversed_rule_id']} "
            f"(target: {action.indicator_value}). Managed egress drop removed in simulation."
        )

        AutonomousPolicyEngine._record_audit_log(
            db=db,
            tenant_id=action.tenant_id,
            action_id=action.id,
            event_type="SIMULATION_ROLLBACK",
            actor=actor,
            previous_status=previous_status,
            new_status="ROLLED_BACK",
            details={
                "mode": "SIMULATED",
                "rollback_reason": reason,
                "reversed_rule_id": rollback_spec["reversed_rule_id"],
                "is_live_enforcement": False
            }
        )
        db.commit()

        return {
            "status": "ROLLED_BACK",
            "action_id": action.action_id,
            "target_indicator": action.indicator_value,
            "rollback_rule": rollback_spec,
            "is_live_enforcement": False,
            "is_simulated": True,
            "message": f"[SIMULATED] Rollback successfully completed for {action.indicator_value}."
        }

    @classmethod
    def check_and_expire(
        cls,
        action: ContainmentAction,
        db: Session,
        actor: str = "SIMULATED_FIREWALL_ADAPTER"
    ) -> Dict[str, Any]:
        """
        Evaluates action TTL and transitions to EXPIRED if now >= expires_at.
        Transition: ACTIVE (SIMULATED, DISPATCHED, RECEIVED, etc.) -> EXPIRED.
        Idempotent if already EXPIRED.
        """
        now = datetime.now(timezone.utc).replace(tzinfo=None)

        if action.status == "EXPIRED":
            return {
                "status": "EXPIRED",
                "expired": True,
                "action_id": action.action_id,
                "is_live_enforcement": False,
                "is_simulated": True,
                "message": "Action already expired."
            }

        if action.status not in ACTIVE_CONTAINMENT_STATUSES:
            return {
                "status": action.status,
                "expired": False,
                "message": f"Action status is '{action.status}', not eligible for expiry check."
            }

        if action.expires_at and now >= action.expires_at:
            previous_status = action.status
            rule_id = action.rule_spec.get('rule_id') if action.rule_spec else f"SIM-RULE-{action.action_id.upper()}"
            action.status = "EXPIRED"
            action.execution_output = (
                f"[SIMULATED] Action {action.action_id} (rule: {rule_id}) "
                f"expired at {action.expires_at.isoformat()} (TTL reached). No live firewall changes."
            )

            AutonomousPolicyEngine._record_audit_log(
                db=db,
                tenant_id=action.tenant_id,
                action_id=action.id,
                event_type="SIMULATION_EXPIRED",
                actor=actor,
                previous_status=previous_status,
                new_status="EXPIRED",
                details={
                    "mode": "SIMULATED",
                    "expired_at": now.isoformat(),
                    "configured_expires_at": action.expires_at.isoformat(),
                    "is_live_enforcement": False
                }
            )
            db.commit()

            return {
                "status": "EXPIRED",
                "expired": True,
                "action_id": action.action_id,
                "is_live_enforcement": False,
                "is_simulated": True,
                "message": f"[SIMULATED] Action {action.action_id} expired due to TTL."
            }

        return {
            "status": action.status,
            "expired": False,
            "action_id": action.action_id,
            "is_live_enforcement": False,
            "is_simulated": True,
            "message": "TTL has not expired."
        }

    @classmethod
    def expire_active_containment_actions(
        cls,
        db: Session,
        tenant_id: Optional[str] = None,
        actor: str = "CONTAINMENT_EXPIRY_SERVICE"
    ) -> List[Dict[str, Any]]:
        """
        Scans all active containment actions past their expires_at timestamp
        and transitions them to EXPIRED idempotently.
        Supports tenant filtering for isolated multi-tenant operations.
        """
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


def get_containment_adapter(mode_override: Optional[str] = None):
    """
    Returns the active containment adapter class based on environment configuration.
    Defaults to SimulatedFirewallAdapter (simulation mode).
    Returns FedoraNftablesAdapter when configured via CONTAINMENT_ADAPTER_MODE='fedora_nftables'.
    Returns WindowsFirewallAdapter when configured via CONTAINMENT_ADAPTER_MODE='windows_firewall'.
    """
    mode = (mode_override or os.getenv("CONTAINMENT_ADAPTER_MODE", "simulated")).strip().lower()
    if mode in ("fedora_nftables", "fedora"):
        from app.services.fedora_nftables_adapter import FedoraNftablesAdapter
        return FedoraNftablesAdapter
    elif mode in ("windows_firewall", "windows_defender", "windows_live", "windows"):
        from app.services.windows_firewall_adapter import WindowsFirewallAdapter
        return WindowsFirewallAdapter
    return SimulatedFirewallAdapter


def get_adapter_for_action(action: ContainmentAction):
    """
    Resolves the appropriate containment adapter for an existing action
    based on its rule_spec, action_id, or action_type.
    """
    rule_spec = getattr(action, "rule_spec", None) or {}
    adapter_name = rule_spec.get("adapter", "").upper()
    act_id = getattr(action, "action_id", "").lower()

    if "FEDORA" in adapter_name or "NFTABLES" in adapter_name or act_id.startswith("act-fed"):
        from app.services.fedora_nftables_adapter import FedoraNftablesAdapter
        return FedoraNftablesAdapter
    elif "WINDOWS" in adapter_name or act_id.startswith("act-win") or getattr(action, "action_type", "") == "BLOCK_INBOUND_PORT_8000":
        from app.services.windows_firewall_adapter import WindowsFirewallAdapter
        return WindowsFirewallAdapter
    elif "SIMULATED" in adapter_name or act_id.startswith("act-sim") or act_id.startswith("sim-"):
        return SimulatedFirewallAdapter

    return get_containment_adapter()
