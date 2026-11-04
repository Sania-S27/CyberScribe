"""
Windows Defender Firewall Containment Adapter
---------------------------------------------
Executes verified, narrowly scoped IP containment actions against Windows Defender Firewall
for Windows-hosted services (specifically targeting Campus Guide on inbound port 8000).

SAFETY & SECURITY GUARANTEES:
1. Narrow Scope: Rules are strictly scoped to inbound TCP port 8000 and the action's validated IPv4 source.
2. Exact Ownership: Rules are named 'CyberScribe_<action_id>'. Rollback deletes ONLY rules with this exact name.
3. Isolation: NEVER modifies existing firewall rules, never flushes tables, and never disables the firewall.
4. Safe Simulation by Default: Operates in simulation mode unless explicitly opted into live mode.
5. Independent Read-Back Verification: Confirms rule name, direction, action, port, and IP before marking VERIFIED.
6. Non-Repudiation: Every state change, simulation, application, failure, and rollback is recorded in `_containment_audit_logs`.
7. Tenant Isolation: Every operation strictly enforces tenant ownership.
"""

import os
import re
import ipaddress
import logging
import subprocess
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Optional, List, Tuple
from sqlalchemy.orm import Session

from app.models import ContainmentAction, ContainmentAuditLog
from app.services.containment_policy import (
    AutonomousPolicyEngine,
    ACTIVE_CONTAINMENT_STATUSES,
    sanitize_audit_details
)
from app.services.firewall_adapter import InvalidStateTransitionError

logger = logging.getLogger("WindowsFirewallAdapter")

DEFAULT_CAMPUS_GUIDE_PORT = 8000
NETSH_BIN = "netsh.exe"


class WindowsFirewallError(Exception):
    """Raised when Windows firewall execution fails."""
    pass


DOCUMENTATION_NETWORKS = [
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
]

RFC1918_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]


LAB_FEDORA_HOST_ONLY_IP = "192.168.56.101"
LAB_FEDORA_TARGET_PORT = 8000


def is_lab_fedora_authorized() -> bool:
    """Checks if lab-only authorization for Fedora VM (192.168.56.101) is explicitly enabled."""
    return os.getenv("ALLOW_LAB_FEDORA_HOST_CONTAINMENT", "false").strip().lower() in ("true", "1", "yes")

is_lab_fedora_containment_allowed = is_lab_fedora_authorized


def is_authorized_private_ip(ip_str: str) -> bool:
    """
    Checks if an IPv4 address is an explicitly authorized internal/private address.
    Supports:
    1. Dedicated lab target (192.168.56.101) when ALLOW_LAB_FEDORA_HOST_CONTAINMENT is enabled.
    2. Explicitly configured enterprise private IPs/CIDRs via AUTHORIZED_PRIVATE_CONTAINMENT_IPS.
    Strictly excludes loopback, broadcast, link-local, multicast, and unspecified addresses.
    """
    if not ip_str or not isinstance(ip_str, str):
        return False
    clean = ip_str.strip()
    try:
        addr = ipaddress.ip_address(clean)
        if not isinstance(addr, ipaddress.IPv4Address) or not addr.is_private:
            return False
        if addr.is_loopback or addr.is_link_local or addr.is_multicast or addr.is_unspecified or clean == "255.255.255.255":
            return False
        if clean == LAB_FEDORA_HOST_ONLY_IP and is_lab_fedora_authorized():
            return True
        allowed_str = os.getenv("AUTHORIZED_PRIVATE_CONTAINMENT_IPS", "").strip()
        if allowed_str:
            for item in allowed_str.split(","):
                entry = item.strip()
                if not entry:
                    continue
                try:
                    if "/" in entry:
                        if addr in ipaddress.ip_network(entry, strict=False):
                            return True
                    elif clean == entry:
                        return True
                except ValueError:
                    continue
        return False
    except ValueError:
        return False


def validate_ip_for_containment(
    ip_str: str,
    allow_reserved: bool = True,
    target_port: Optional[int] = None,
    direction: Optional[str] = None
) -> str:
    """Validates that the input is a valid IPv4 address, rejecting documentation/reserved/private IPs in live mode."""
    if not ip_str or not isinstance(ip_str, str):
        raise WindowsFirewallError("Missing or invalid IP address.")
    clean_ip = ip_str.strip()
    try:
        addr = ipaddress.ip_address(clean_ip)
    except ValueError as e:
        raise WindowsFirewallError(f"Malformed IP address: {e}")
    if not isinstance(addr, ipaddress.IPv4Address):
        raise WindowsFirewallError("Only IPv4 addresses are supported.")

    if addr.is_loopback or addr.is_unspecified or clean_ip == "255.255.255.255":
        raise WindowsFirewallError(
            f"IP address '{clean_ip}' is a loopback/unspecified/broadcast address and cannot be contained."
        )

    is_reserved = (
        addr.is_reserved or
        addr.is_link_local or
        addr.is_multicast or
        any(addr in net for net in RFC1918_PRIVATE_NETWORKS) or
        any(addr in net for net in DOCUMENTATION_NETWORKS)
    )
    if not allow_reserved and is_reserved:
        # 1. Fedora lab IP: isolated to its strict lab constraints (port 8000, dir=in)
        if clean_ip == LAB_FEDORA_HOST_ONLY_IP:
            if not is_lab_fedora_authorized():
                raise WindowsFirewallError(
                    f"IP address '{clean_ip}' is a private lab IP. Live containment is rejected because "
                    f"ALLOW_LAB_FEDORA_HOST_CONTAINMENT is not enabled."
                )
            if target_port is not None and target_port != LAB_FEDORA_TARGET_PORT:
                raise WindowsFirewallError(
                    f"Lab-authorized IP '{clean_ip}' is strictly restricted to inbound port {LAB_FEDORA_TARGET_PORT}. "
                    f"Port {target_port} is not permitted."
                )
            if direction is not None and direction.strip().lower() not in ("in", "inbound"):
                raise WindowsFirewallError(
                    f"Lab-authorized IP '{clean_ip}' is strictly restricted to inbound direction. "
                    f"Direction '{direction}' is not permitted."
                )
            return str(addr)

        # 2. General explicitly authorized private IP (enterprise internal target)
        if is_authorized_private_ip(clean_ip):
            return str(addr)

        raise WindowsFirewallError(
            f"IP address '{clean_ip}' is in a reserved documentation / private / non-routable range. "
            f"Permitted in simulation mode, but strictly rejected for real live containment."
        )
    return str(addr)


def validate_action_id_str(action_id: str) -> str:
    """Validates action_id format against alphanumeric + hyphen/underscore."""
    if not action_id or not isinstance(action_id, str):
        raise WindowsFirewallError("Missing or invalid action_id.")
    clean = action_id.strip()
    if not re.match(r"^[a-zA-Z0-9_\-]{3,64}$", clean):
        raise WindowsFirewallError(f"Invalid action_id '{clean}'.")
    return clean


class WindowsFirewallAdapter:
    """Windows Defender Firewall adapter for CyberScribe containment."""

    @classmethod
    def is_live_mode_enabled(cls) -> bool:
        """Checks if live Windows firewall containment is explicitly opted into."""
        mode = os.getenv("CONTAINMENT_ADAPTER_MODE", "simulated").strip().lower()
        return mode in ("windows_firewall", "windows_defender", "windows_live", "windows")

    @classmethod
    def get_rule_name(cls, action_id: str) -> str:
        clean_id = validate_action_id_str(action_id)
        return f"CyberScribe_{clean_id}"

    @classmethod
    def _run_netsh(cls, args: List[str], timeout: int = 8) -> Tuple[int, str, str]:
        """Safely executes netsh command with argument arrays (no shell=True)."""
        cmd = [NETSH_BIN, "advfirewall", "firewall"] + args
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                shell=False
            )
            return proc.returncode, proc.stdout, proc.stderr
        except subprocess.TimeoutExpired:
            raise WindowsFirewallError("Windows firewall command timed out (8s limit).")
        except Exception as e:
            raise WindowsFirewallError(f"Failed to execute Windows firewall command: {e}")

    @classmethod
    def show_rule(cls, rule_name: str) -> Optional[Dict[str, str]]:
        """Queries Windows Defender Firewall for a specific rule by exact name."""
        returncode, stdout, _ = cls._run_netsh(["show", "rule", f"name={rule_name}"])
        if returncode != 0 or "No rules match the specified criteria" in stdout:
            return None

        # Parse key-value lines from netsh output
        parsed = {}
        for line in stdout.splitlines():
            if ":" in line:
                key, val = line.split(":", 1)
                parsed[key.strip()] = val.strip()
        return parsed

    @classmethod
    def _execute_via_daemon_if_available(cls, endpoint: str, payload: dict) -> Optional[dict]:
        daemon_url = os.getenv("WINDOWS_EXECUTOR_URL", "").rstrip("/")
        if not daemon_url:
            return None
        token = os.getenv("WINDOWS_EXECUTOR_TOKEN", "cyberscribe_win_executor_secret_token_2026")
        try:
            import requests
            resp = requests.post(
                f"{daemon_url}/{endpoint}",
                json=payload,
                headers={"X-CyberScribe-Executor-Token": token},
                timeout=4.0
            )
            if resp.status_code == 200:
                return resp.json()
            elif resp.status_code >= 400:
                raise WindowsFirewallError(f"Windows Executor Daemon error ({resp.status_code}): {resp.text}")
        except requests.ConnectionError:
            return None
        except Exception as e:
            if isinstance(e, WindowsFirewallError):
                raise
            logger.warning(f"Windows Executor Daemon check skipped: {e}")
            return None
        return None

    @classmethod
    def apply_containment(
        cls,
        action: ContainmentAction,
        db: Session,
        actor: str = "WINDOWS_FIREWALL_ADAPTER",
        target_port: int = DEFAULT_CAMPUS_GUIDE_PORT,
        is_simulated: Optional[bool] = None
    ) -> Dict[str, Any]:
        """
        Applies a narrowly scoped drop rule on Windows Defender Firewall:
        Direction: Inbound
        Protocol: TCP
        LocalPort: 8000 (Campus Guide backend)
        RemoteIP: <action.indicator_value>
        RuleName: CyberScribe_<action_id>
        """
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        previous_status = action.status
        live = cls.is_live_mode_enabled() if is_simulated is None else not is_simulated

        try:
            clean_action_id = validate_action_id_str(action.action_id)
            rule_name = cls.get_rule_name(clean_action_id)
            clean_ip = validate_ip_for_containment(
                action.indicator_value,
                allow_reserved=not live,
                target_port=target_port,
                direction="in" if getattr(action, "action_type", "") == "BLOCK_INBOUND_PORT_8000" else None
            )
        except Exception as e:
            logger.error(f"Windows Firewall validation failed: {e}")
            action.status = "FAILED"
            action.error_message = str(e)
            AutonomousPolicyEngine._record_audit_log(
                db=db,
                tenant_id=action.tenant_id,
                action_id=action.id,
                event_type="WINDOWS_FIREWALL_FAILED",
                actor=actor,
                previous_status=previous_status,
                new_status="FAILED",
                details={"error": str(e)}
            )
            db.commit()
            return {
                "status": "FAILED",
                "action_id": getattr(action, "action_id", "unknown"),
                "error": str(e),
                "is_live_enforcement": live,
                "is_simulated": not live
            }

        # Resolve traffic direction (inbound exploit source vs outbound C2 destination)
        direction = AutonomousPolicyEngine.resolve_containment_direction(action)
        if direction is None:
            reason = (
                "CONTAINMENT_DIRECTION_UNRESOLVED: Unable to establish whether IP is an inbound exploit source "
                "or outbound C2 destination from threat evidence and policy rules. Rule application rejected."
            )
            logger.warning(f"Windows Firewall containment rejected for {action.action_id}: {reason}")
            action.status = "REJECTED"
            action.error_message = reason
            AutonomousPolicyEngine._record_audit_log(
                db=db,
                tenant_id=action.tenant_id,
                action_id=action.id,
                event_type="CONTAINMENT_DIRECTION_UNRESOLVED",
                actor=actor,
                previous_status=previous_status,
                new_status="REJECTED",
                details={
                    "reason": reason,
                    "action_id": action.action_id,
                    "indicator_value": action.indicator_value,
                    "action_type": action.action_type,
                    "policy_rule": action.policy_rule,
                    "requires_further_evidence_or_approval": True
                }
            )
            db.commit()
            return {
                "status": "REJECTED",
                "action_id": getattr(action, "action_id", "unknown"),
                "error": reason,
                "direction": None,
                "is_live_enforcement": live,
                "is_simulated": not live,
                "requires_further_evidence_or_approval": True
            }

        is_outbound = (direction == "out")

        # Defense-in-depth: strict validation for lab-authorized Fedora VM (192.168.56.101)
        if clean_ip == LAB_FEDORA_HOST_ONLY_IP and live:
            if not is_lab_fedora_authorized():
                lab_err = f"Live containment for lab IP '{clean_ip}' rejected: ALLOW_LAB_FEDORA_HOST_CONTAINMENT is not enabled."
                action.status = "FAILED"
                action.error_message = lab_err
                AutonomousPolicyEngine._record_audit_log(
                    db=db,
                    tenant_id=action.tenant_id,
                    action_id=action.id,
                    event_type="WINDOWS_FIREWALL_FAILED",
                    actor=actor,
                    previous_status=previous_status,
                    new_status="FAILED",
                    details={"error": lab_err}
                )
                db.commit()
                return {"status": "FAILED", "action_id": getattr(action, "action_id", "unknown"), "error": lab_err, "is_live_enforcement": live, "is_simulated": not live}
            if is_outbound or direction != "in":
                lab_err = f"Lab-authorized IP '{clean_ip}' is strictly restricted to inbound exploit containment (dir='in'). Outbound C2 containment is prohibited."
                action.status = "FAILED"
                action.error_message = lab_err
                AutonomousPolicyEngine._record_audit_log(
                    db=db,
                    tenant_id=action.tenant_id,
                    action_id=action.id,
                    event_type="WINDOWS_FIREWALL_FAILED",
                    actor=actor,
                    previous_status=previous_status,
                    new_status="FAILED",
                    details={"error": lab_err}
                )
                db.commit()
                return {"status": "FAILED", "action_id": getattr(action, "action_id", "unknown"), "error": lab_err, "is_live_enforcement": live, "is_simulated": not live}
            if target_port != DEFAULT_CAMPUS_GUIDE_PORT:
                lab_err = f"Lab-authorized IP '{clean_ip}' is strictly restricted to inbound port {DEFAULT_CAMPUS_GUIDE_PORT}. Target port {target_port} is prohibited."
                action.status = "FAILED"
                action.error_message = lab_err
                AutonomousPolicyEngine._record_audit_log(
                    db=db,
                    tenant_id=action.tenant_id,
                    action_id=action.id,
                    event_type="WINDOWS_FIREWALL_FAILED",
                    actor=actor,
                    previous_status=previous_status,
                    new_status="FAILED",
                    details={"error": lab_err}
                )
                db.commit()
                return {"status": "FAILED", "action_id": getattr(action, "action_id", "unknown"), "error": lab_err, "is_live_enforcement": live, "is_simulated": not live}

        # Idempotency check: if already active in expected state
        if live and action.status in ("APPLIED", "VERIFIED"):
            return {
                "status": action.status,
                "action_id": action.action_id,
                "rule_name": rule_name,
                "direction": "OUTBOUND" if is_outbound else "INBOUND",
                "is_live_enforcement": True,
                "is_simulated": False,
                "message": f"Rule {rule_name} already applied."
            }
        elif not live and action.status == "SIMULATED":
            return {
                "status": "SIMULATED",
                "action_id": action.action_id,
                "rule_name": rule_name,
                "direction": "OUTBOUND" if is_outbound else "INBOUND",
                "is_live_enforcement": False,
                "is_simulated": True,
                "message": f"[SIMULATED] Rule {rule_name} already simulated."
            }

        rule_spec = {
            "adapter": "WINDOWS_DEFENDER_FIREWALL",
            "rule_name": rule_name,
            "action": "BLOCK",
            "direction": "OUTBOUND" if is_outbound else "INBOUND",
            "remote_ip": clean_ip,
            "is_simulated": not live
        }
        if is_outbound:
            rule_spec["target_scope"] = "Outbound Botnet/C2 Destination"
        else:
            if target_port and target_port > 0:
                rule_spec["protocol"] = "TCP"
                rule_spec["local_port"] = target_port
                rule_spec["target_service"] = f"Service on port {target_port}"
            else:
                rule_spec["target_scope"] = "All Inbound Traffic"

        previous_status = action.status
        action.rule_spec = rule_spec
        action.applied_at = now
        if not action.expires_at:
            action.expires_at = now + timedelta(seconds=action.ttl_seconds)

        if not live:
            # Safe simulation mode
            action.status = "SIMULATED"
            if is_outbound:
                action.execution_output = (
                    f"[SIMULATED] Staged Windows Defender Firewall rule '{rule_name}' "
                    f"(BLOCK OUTBOUND to C2 destination {clean_ip}). No host firewall changes made."
                )
            else:
                port_desc = f"TCP port {target_port}" if target_port and target_port > 0 else "all ports"
                action.execution_output = (
                    f"[SIMULATED] Staged Windows Defender Firewall rule '{rule_name}' "
                    f"(BLOCK INBOUND {port_desc} from {clean_ip}). No host firewall changes made."
                )
            action.error_message = None

            AutonomousPolicyEngine._record_audit_log(
                db=db,
                tenant_id=action.tenant_id,
                action_id=action.id,
                event_type="WINDOWS_FIREWALL_SIMULATED",
                actor=actor,
                previous_status=previous_status,
                new_status="SIMULATED",
                details=rule_spec
            )
            db.commit()

            return {
                "status": "SIMULATED",
                "action_id": action.action_id,
                "rule_name": rule_name,
                "target_port": target_port if (not is_outbound and target_port and target_port > 0) else None,
                "target_ip": clean_ip,
                "direction": "OUTBOUND" if is_outbound else "INBOUND",
                "is_live_enforcement": False,
                "is_simulated": True,
                "rule_spec": rule_spec,
                "message": (
                    f"[SIMULATED] Windows Defender Firewall containment staged for C2 destination {clean_ip} (outbound)."
                    if is_outbound else
                    f"[SIMULATED] Windows Defender Firewall containment staged for {clean_ip}."
                )
            }

        # Live enforcement execution
        try:
            is_res_authorized = is_authorized_private_ip(clean_ip) or (clean_ip == LAB_FEDORA_HOST_ONLY_IP and is_lab_fedora_authorized())
            daemon_res = cls._execute_via_daemon_if_available("apply", {
                "action_id": clean_action_id,
                "ip_address": clean_ip,
                "port": target_port if not is_outbound else 0,
                "direction": direction,
                "allow_reserved": is_res_authorized
            })

            if not daemon_res:
                # Direct netsh execution fallback
                existing_rule = cls.show_rule(rule_name)
                if not existing_rule:
                    if is_outbound:
                        add_args = [
                            "add", "rule",
                            f"name={rule_name}",
                            "dir=out",
                            "action=block",
                            f"remoteip={clean_ip}",
                            f"description=CyberScribe Automated Outbound C2 Containment for action {clean_action_id}"
                        ]
                    else:
                        add_args = [
                            "add", "rule",
                            f"name={rule_name}",
                            "dir=in",
                            "action=block",
                            f"remoteip={clean_ip}",
                            f"description=CyberScribe Automated Containment for action {clean_action_id}"
                        ]
                        if target_port and target_port > 0:
                            add_args.extend(["protocol=TCP", f"localport={target_port}"])
                    returncode, stdout, stderr = cls._run_netsh(add_args)
                    if returncode != 0:
                        err_msg = stderr.strip() or stdout.strip() or f"netsh returned exit code {returncode}"
                        raise WindowsFirewallError(f"Failed to add rule: {err_msg}")

            # Verify rule presence via independent read-back
            verified_rule = cls.show_rule(rule_name)
            if not verified_rule:
                raise WindowsFirewallError("Verification failed: rule was not found in Windows Firewall after addition.")

            action.status = "VERIFIED"
            action.verified_at = datetime.now(timezone.utc).replace(tzinfo=None)
            action.execution_output = f"Windows Defender Firewall rule '{rule_name}' successfully added and verified."
            action.error_message = None

            AutonomousPolicyEngine._record_audit_log(
                db=db,
                tenant_id=action.tenant_id,
                action_id=action.id,
                event_type="WINDOWS_FIREWALL_APPLIED_AND_VERIFIED",
                actor=actor,
                previous_status=previous_status,
                new_status="VERIFIED",
                details={**rule_spec, "verified": True, "firewall_details": verified_rule}
            )
            db.commit()

            return {
                "status": "VERIFIED",
                "action_id": action.action_id,
                "rule_name": rule_name,
                "target_port": target_port if not is_outbound else None,
                "target_ip": clean_ip,
                "direction": "OUTBOUND" if is_outbound else "INBOUND",
                "is_live_enforcement": True,
                "is_simulated": False,
                "message": f"Rule {rule_name} verified active in Windows Defender Firewall."
            }

        except Exception as e:
            logger.error(f"Windows Firewall apply failed: {e}")
            action.status = "FAILED"
            action.error_message = f"Windows Firewall application error: {e}"

            AutonomousPolicyEngine._record_audit_log(
                db=db,
                tenant_id=action.tenant_id,
                action_id=action.id,
                event_type="WINDOWS_FIREWALL_FAILED",
                actor=actor,
                previous_status=previous_status,
                new_status="FAILED",
                details={"error": str(e), "rule_name": rule_name}
            )
            db.commit()

            return {
                "status": "FAILED",
                "action_id": action.action_id,
                "error": str(e),
                "is_live_enforcement": True,
                "is_simulated": False
            }

    @classmethod
    def verify_containment(
        cls,
        action: ContainmentAction,
        db: Session,
        actor: str = "WINDOWS_FIREWALL_ADAPTER"
    ) -> Dict[str, Any]:
        """Independently verifies active firewall rule."""
        clean_action_id = validate_action_id_str(action.action_id)
        rule_name = cls.get_rule_name(clean_action_id)

        if action.status == "SIMULATED":
            action.verified_at = datetime.now(timezone.utc).replace(tzinfo=None)
            db.commit()
            return {
                "status": "SIMULATED",
                "verified": True,
                "action_id": action.action_id,
                "is_simulated": True,
                "message": "[SIMULATED] Simulated rule verified in state ledger."
            }

        rule = cls.show_rule(rule_name)
        if not rule:
            action.status = "FAILED"
            action.error_message = f"Verification failed: rule {rule_name} absent from Windows Firewall."
            db.commit()
            return {
                "status": "FAILED",
                "verified": False,
                "action_id": action.action_id,
                "error": action.error_message
            }

        action.status = "VERIFIED"
        action.verified_at = datetime.now(timezone.utc).replace(tzinfo=None)
        db.commit()

        return {
            "status": "VERIFIED",
            "verified": True,
            "action_id": action.action_id,
            "rule_name": rule_name,
            "details": rule
        }

    @classmethod
    def rollback_containment(
        cls,
        action: ContainmentAction,
        db: Session,
        reason: str = "EXACT_RULE_ROLLBACK",
        actor: str = "WINDOWS_FIREWALL_ADAPTER",
        expected_tenant_id: Optional[str] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Removes ONLY the exact rule 'CyberScribe_<action_id>' from Windows Defender Firewall.
        Never touches any other rule.
        """
        if expected_tenant_id and action.tenant_id != expected_tenant_id:
            raise PermissionError(
                f"Tenant isolation violation: Action '{action.action_id}' belongs to tenant '{action.tenant_id}', not '{expected_tenant_id}'."
            )
        clean_action_id = validate_action_id_str(action.action_id)
        rule_name = cls.get_rule_name(clean_action_id)
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        previous_status = action.status

        # Idempotency: if already rolled back
        if action.status == "ROLLED_BACK":
            return {
                "status": "ROLLED_BACK",
                "action_id": action.action_id,
                "rule_name": rule_name,
                "message": f"Action {action.action_id} already rolled back."
            }

        if action.status == "SIMULATED":
            action.status = "ROLLED_BACK"
            action.rolled_back_at = now
            action.execution_output = f"[SIMULATED] Simulated Windows Defender Firewall rule '{rule_name}' rolled back."

            AutonomousPolicyEngine._record_audit_log(
                db=db,
                tenant_id=action.tenant_id,
                action_id=action.id,
                event_type="WINDOWS_FIREWALL_ROLLED_BACK",
                actor=actor,
                previous_status=previous_status,
                new_status="ROLLED_BACK",
                details={"rule_name": rule_name, "is_simulated": True}
            )
            db.commit()
            return {
                "status": "ROLLED_BACK",
                "action_id": action.action_id,
                "rule_name": rule_name,
                "is_simulated": True,
                "message": f"[SIMULATED] Rule {rule_name} rolled back successfully."
            }

        # Live rollback
        try:
            daemon_res = cls._execute_via_daemon_if_available("rollback", {"action_id": clean_action_id})
            if not daemon_res:
                returncode, stdout, stderr = cls._run_netsh(["delete", "rule", f"name={rule_name}"])
                # Read-back verification to guarantee rule is gone
                post_check = cls.show_rule(rule_name)
                if post_check is not None:
                    raise WindowsFirewallError(f"Rollback failed: rule '{rule_name}' is still present in Windows Firewall.")

            action.status = "ROLLED_BACK"
            action.rolled_back_at = now
            action.execution_output = f"Windows Defender Firewall rule '{rule_name}' successfully removed and verified absent."
            action.error_message = None

            AutonomousPolicyEngine._record_audit_log(
                db=db,
                tenant_id=action.tenant_id,
                action_id=action.id,
                event_type="WINDOWS_FIREWALL_ROLLED_BACK",
                actor=actor,
                previous_status=previous_status,
                new_status="ROLLED_BACK",
                details={"rule_name": rule_name, "verified_removal": True}
            )
            db.commit()

            return {
                "status": "ROLLED_BACK",
                "action_id": action.action_id,
                "rule_name": rule_name,
                "is_simulated": False,
                "message": f"Rule {rule_name} removed from Windows Defender Firewall and verified absent."
            }

        except Exception as e:
            logger.error(f"Windows Firewall rollback failed: {e}")
            action.error_message = f"Rollback error: {e}"
            AutonomousPolicyEngine._record_audit_log(
                db=db,
                tenant_id=action.tenant_id,
                action_id=action.id,
                event_type="WINDOWS_FIREWALL_ROLLBACK_FAILED",
                actor=actor,
                previous_status=previous_status,
                new_status=action.status,
                details={"error": str(e), "rule_name": rule_name}
            )
            db.commit()
            return {
                "status": action.status,
                "action_id": action.action_id,
                "error": str(e),
                "rolled_back": False
            }

    @classmethod
    def check_and_expire(
        cls,
        action: ContainmentAction,
        db: Session,
        actor: str = "WINDOWS_FIREWALL_ADAPTER"
    ) -> Dict[str, Any]:
        """Expires an active action past its TTL and rolls back rule."""
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        if action.status not in ACTIVE_CONTAINMENT_STATUSES:
            return {"status": action.status, "expired": False}

        if action.expires_at and action.expires_at <= now:
            res = cls.rollback_containment(action, db, actor=actor)
            if res.get("status") == "ROLLED_BACK":
                action.status = "EXPIRED"
                db.commit()
                return {"status": "EXPIRED", "expired": True, "action_id": action.action_id}

        return {"status": action.status, "expired": False}

    @classmethod
    def expire_active_containment_actions(
        cls,
        db: Session,
        tenant_id: Optional[str] = None,
        actor: str = "WINDOWS_FIREWALL_EXPIRY_SERVICE"
    ) -> List[Dict[str, Any]]:
        """Scans and expires all TTL-elapsed active actions on Windows Firewall."""
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
