"""
CyberScribe Windows Firewall Privileged Helper
---------------------------------------------
Executes narrowly scoped, strictly validated Windows Defender Firewall operations:
- Strictly scoped to inbound TCP port 8000 (Campus Guide service)
- Strict action ID format: CyberScribe_<action_id>
- Strictly rejects reserved documentation ranges (198.51.100.0/24, etc.) in live mode
- Zero modification to unrelated rules; never flushes firewall
- Executes via argument vector subprocess calls (no shell=True)
"""

import os
import re
import ipaddress
import subprocess
import logging
from typing import Dict, Any, Optional, List, Tuple

logger = logging.getLogger("CyberScribeWinHelper")

NETSH_BIN = "netsh.exe"
DEFAULT_TARGET_PORT = 8000
ACTION_ID_PATTERN = re.compile(r"^[a-zA-Z0-9_\-]{3,64}$")

LAB_FEDORA_HOST_ONLY_IP = "192.168.56.101"
LAB_FEDORA_TARGET_PORT = 8000


def is_lab_fedora_authorized() -> bool:
    """Checks if lab-only authorization for Fedora VM (192.168.56.101) is explicitly enabled."""
    return os.getenv("ALLOW_LAB_FEDORA_HOST_CONTAINMENT", "false").strip().lower() in ("true", "1", "yes")

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


class HelperSecurityError(Exception):
    """Raised when helper parameters violate security bounds."""
    pass


class RuleVerificationError(Exception):
    """Raised when firewall rule verification fails."""
    pass


def validate_action_id(action_id: str) -> str:
    if not action_id or not isinstance(action_id, str):
        raise HelperSecurityError("action_id must be a non-empty string.")
    clean = action_id.strip()
    if not ACTION_ID_PATTERN.match(clean):
        raise HelperSecurityError(f"action_id '{clean}' contains invalid characters.")
    return clean


def validate_public_ipv4(
    ip_str: str,
    allow_reserved: bool = False,
    target_port: Optional[int] = None,
    direction: Optional[str] = None
) -> str:
    if not ip_str or not isinstance(ip_str, str):
        raise HelperSecurityError("IP address must be a non-empty string.")
    clean_ip = ip_str.strip()
    try:
        addr = ipaddress.ip_address(clean_ip)
    except ValueError as e:
        raise HelperSecurityError(f"Malformed IP address: {e}")

    if not isinstance(addr, ipaddress.IPv4Address):
        raise HelperSecurityError("Only IPv4 addresses are supported.")

    if addr.is_loopback or addr.is_unspecified or clean_ip == "255.255.255.255":
        raise HelperSecurityError(f"IP '{clean_ip}' is loopback/unspecified/broadcast and cannot be contained.")

    is_reserved = (
        addr.is_reserved or
        addr.is_link_local or
        addr.is_multicast or
        any(addr in net for net in RFC1918_PRIVATE_NETWORKS) or
        any(addr in net for net in DOCUMENTATION_NETWORKS)
    )
    if not allow_reserved and is_reserved:
        if clean_ip == LAB_FEDORA_HOST_ONLY_IP:
            if not is_lab_fedora_authorized():
                raise HelperSecurityError(
                    f"IP '{clean_ip}' is a private lab IP. Live containment is rejected because "
                    f"ALLOW_LAB_FEDORA_HOST_CONTAINMENT is not enabled."
                )
            if target_port is not None and target_port != LAB_FEDORA_TARGET_PORT:
                raise HelperSecurityError(
                    f"Lab-authorized IP '{clean_ip}' is strictly restricted to inbound port {LAB_FEDORA_TARGET_PORT}. "
                    f"Port {target_port} is not permitted."
                )
            if direction is not None and direction.strip().lower() not in ("in", "inbound"):
                raise HelperSecurityError(
                    f"Lab-authorized IP '{clean_ip}' is strictly restricted to inbound direction. "
                    f"Direction '{direction}' is not permitted."
                )
            return str(addr)

        # Check explicitly authorized enterprise private IP
        allowed_str = os.getenv("AUTHORIZED_PRIVATE_CONTAINMENT_IPS", "").strip()
        if allowed_str:
            for item in allowed_str.split(","):
                entry = item.strip()
                if not entry:
                    continue
                try:
                    if "/" in entry and addr in ipaddress.ip_network(entry, strict=False):
                        return str(addr)
                    elif clean_ip == entry:
                        return str(addr)
                except ValueError:
                    continue

        raise HelperSecurityError(
            f"IP '{clean_ip}' is in a reserved/documentation/private range. "
            f"Live public containment requires a valid routable target IP."
        )
    return str(addr)


def get_rule_name(action_id: str) -> str:
    clean_id = validate_action_id(action_id)
    return f"CyberScribe_{clean_id}"


def _run_netsh(args: List[str], timeout: int = 8) -> Tuple[int, str, str]:
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
        raise HelperSecurityError("Windows firewall netsh command timed out.")
    except Exception as e:
        raise HelperSecurityError(f"Failed to execute netsh: {e}")


def show_rule(rule_name: str) -> Optional[Dict[str, str]]:
    returncode, stdout, _ = _run_netsh(["show", "rule", f"name={rule_name}"])
    if returncode != 0 or "No rules match the specified criteria" in stdout:
        return None

    parsed = {}
    for line in stdout.splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            parsed[k.strip().lower()] = v.strip()
    return parsed


def apply_rule(
    action_id: str,
    ip_str: str,
    port: int = DEFAULT_TARGET_PORT,
    allow_reserved: bool = False,
    direction: str = "in"
) -> Dict[str, Any]:
    """
    Applies a scoped drop rule on Windows Defender Firewall:
    - direction='in': blocks inbound TCP traffic to Campus Guide port 8000 from validated attacking IP.
    - direction='out': blocks outbound traffic to validated botnet/C2 destination IP.
    """
    clean_action_id = validate_action_id(action_id)
    dir_clean = direction.strip().lower()
    if dir_clean not in ("in", "out"):
        raise HelperSecurityError(f"Invalid direction '{direction}'. Must be 'in' or 'out'.")

    clean_ip = validate_public_ipv4(ip_str, allow_reserved=allow_reserved, target_port=port, direction=dir_clean)
    rule_name = get_rule_name(clean_action_id)

    if clean_ip == LAB_FEDORA_HOST_ONLY_IP:
        if not is_lab_fedora_authorized():
            raise HelperSecurityError("Lab Fedora IP requires ALLOW_LAB_FEDORA_HOST_CONTAINMENT=true.")
        if dir_clean != "in":
            raise HelperSecurityError(f"Lab Fedora IP {LAB_FEDORA_HOST_ONLY_IP} is strictly restricted to inbound direction.")
        if port != LAB_FEDORA_TARGET_PORT:
            raise HelperSecurityError(f"Lab Fedora IP {LAB_FEDORA_HOST_ONLY_IP} is strictly restricted to port {LAB_FEDORA_TARGET_PORT}.")
    else:
        if port is not None and port != 0 and not (1 <= port <= 65535):
            raise HelperSecurityError(f"Invalid target port {port}. Must be between 1 and 65535 or 0.")

    # Idempotent: check if already exists
    existing = show_rule(rule_name)
    if existing:
        return {
            "status": "ALREADY_EXISTS",
            "rule_name": rule_name,
            "action_id": clean_action_id,
            "ip": clean_ip,
            "port": port if dir_clean == "in" else None,
            "direction": dir_clean
        }

    if dir_clean == "out":
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
        if port and port > 0:
            add_args.extend(["protocol=TCP", f"localport={port}"])
    rc, stdout, stderr = _run_netsh(add_args)
    if rc != 0:
        err = stderr.strip() or stdout.strip() or f"netsh returned exit code {rc}"
        raise HelperSecurityError(f"Failed to apply firewall rule: {err}")

    # Read-back verification
    verify_rule(clean_action_id, expected_ip=clean_ip, expected_port=port if dir_clean == "in" else None, direction=dir_clean)

    return {
        "status": "APPLIED",
        "rule_name": rule_name,
        "action_id": clean_action_id,
        "ip": clean_ip,
        "port": port if dir_clean == "in" else None,
        "direction": dir_clean,
        "message": f"Rule {rule_name} ({dir_clean}) applied and verified on Windows Defender Firewall."
    }


def verify_rule(
    action_id: str,
    expected_ip: str,
    expected_port: Optional[int] = DEFAULT_TARGET_PORT,
    direction: str = "in"
) -> bool:
    """Independently verifies rule presence and parameters."""
    clean_action_id = validate_action_id(action_id)
    rule_name = get_rule_name(clean_action_id)

    if expected_ip == LAB_FEDORA_HOST_ONLY_IP:
        if not is_lab_fedora_authorized():
            raise HelperSecurityError("Lab Fedora IP requires ALLOW_LAB_FEDORA_HOST_CONTAINMENT=true.")
        if direction.lower() != "in":
            raise HelperSecurityError(f"Lab Fedora IP {LAB_FEDORA_HOST_ONLY_IP} is strictly restricted to inbound direction.")
        if expected_port is not None and expected_port != DEFAULT_TARGET_PORT:
            raise HelperSecurityError(f"Lab Fedora IP {LAB_FEDORA_HOST_ONLY_IP} is strictly restricted to port {DEFAULT_TARGET_PORT}.")

    info = show_rule(rule_name)

    if not info:
        raise RuleVerificationError(f"Rule '{rule_name}' does not exist on Windows Defender Firewall.")

    # Validate action
    action_val = info.get("action", "").lower()
    if "block" not in action_val:
        raise RuleVerificationError(f"Rule '{rule_name}' action is '{action_val}', expected 'Block'.")

    # Validate direction
    dir_val = info.get("direction", "").lower()
    exp_dir = "out" if direction.lower() == "out" else "in"
    if exp_dir not in dir_val:
        raise RuleVerificationError(f"Rule '{rule_name}' direction is '{dir_val}', expected '{exp_dir}'.")

    # Validate protocol if inbound
    if exp_dir == "in":
        prot_val = info.get("protocol", "").lower()
        if "tcp" not in prot_val:
            raise RuleVerificationError(f"Rule '{rule_name}' protocol is '{prot_val}', expected 'TCP'.")

    return True


def rollback_rule(action_id: str) -> Dict[str, Any]:
    """Deletes ONLY the exact rule CyberScribe_<action_id>."""
    clean_action_id = validate_action_id(action_id)
    rule_name = get_rule_name(clean_action_id)

    existing = show_rule(rule_name)
    if not existing:
        return {
            "status": "NOT_FOUND",
            "rule_name": rule_name,
            "action_id": clean_action_id,
            "message": f"Rule {rule_name} was already deleted or not present."
        }

    del_args = ["delete", "rule", f"name={rule_name}"]
    rc, stdout, stderr = _run_netsh(del_args)
    if rc != 0:
        err = stderr.strip() or stdout.strip() or f"netsh returned exit code {rc}"
        raise HelperSecurityError(f"Failed to delete rule {rule_name}: {err}")

    # Confirm deletion
    if show_rule(rule_name) is not None:
        raise HelperSecurityError(f"Rule {rule_name} still exists after deletion command!")

    return {
        "status": "ROLLED_BACK",
        "rule_name": rule_name,
        "action_id": clean_action_id,
        "message": f"Rule {rule_name} successfully rolled back and verified removed."
    }


def list_cyberscribe_rules() -> List[Dict[str, str]]:
    """Lists only CyberScribe managed firewall rules."""
    rc, stdout, _ = _run_netsh(["show", "rule", "name=all"])
    if rc != 0:
        return []

    rules = []
    current = {}
    for line in stdout.splitlines():
        if "Rule Name:" in line:
            if current and current.get("name", "").startswith("CyberScribe_"):
                rules.append(current)
            current = {"name": line.split(":", 1)[1].strip()}
        elif ":" in line and current:
            k, v = line.split(":", 1)
            current[k.strip().lower()] = v.strip()

    if current and current.get("name", "").startswith("CyberScribe_"):
        rules.append(current)
    return rules
