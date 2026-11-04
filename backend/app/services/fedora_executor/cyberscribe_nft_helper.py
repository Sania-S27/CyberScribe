#!/usr/bin/env python3
"""
CyberScribe Privileged nftables Helper
--------------------------------------
Enforces least-privilege boundary for nftables firewall containment.
Executed via sudo exclusively by the 'cyberscribe' system account.

SECURITY GUARANTEES:
1. Cannot execute arbitrary nftables commands.
2. Interacts ONLY with dedicated table 'inet <table_name>' (default 'cyberscribe').
3. NEVER flushes, alters, or touches Fedora's firewalld tables or policies.
4. Validates single public IPv4 addresses; strictly rejects private, loopback,
   link-local, multicast, broadcast, reserved, and protected infrastructure IPs.
5. Rules must have comment 'cyberscribe:<action_id>' for exact ownership tracking.
6. Rule deletion by handle strictly verifies that the target rule belongs to the
   specified action_id before deletion. Refuses to delete unrelated rules.
7. Handles partial failure: if adding one rule fails during multi-rule insertion,
   any staged rules are rolled back immediately to prevent half-applied state.
"""

import sys
import os
import re
import json
import logging
import ipaddress
import subprocess
from typing import Dict, Any, List, Optional, Tuple

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] [NftHelper] %(message)s"
)
logger = logging.getLogger("NftHelper")

DEFAULT_TABLE = "cyberscribe"
NFT_BIN = "/usr/sbin/nft"

# Protected Internet & Enterprise DNS Infrastructure
PROTECTED_IPV4_HOSTS = {
    ipaddress.IPv4Address("1.1.1.1"),
    ipaddress.IPv4Address("1.0.0.1"),
    ipaddress.IPv4Address("8.8.8.8"),
    ipaddress.IPv4Address("8.8.4.4"),
    ipaddress.IPv4Address("9.9.9.9"),
    ipaddress.IPv4Address("149.112.112.112"),
    ipaddress.IPv4Address("208.67.222.222"),
    ipaddress.IPv4Address("208.67.220.220"),
}

# Special-Use & Documentation IPv4 Ranges (RFC 5737, RFC 2544, RFC 6598, RFC 6890, RFC 7526)
SPECIAL_AND_DOCUMENTATION_NETWORKS = [
    ipaddress.ip_network("192.0.2.0/24"),    # TEST-NET-1 (RFC 5737)
    ipaddress.ip_network("198.51.100.0/24"), # TEST-NET-2 (RFC 5737)
    ipaddress.ip_network("203.0.113.0/24"),  # TEST-NET-3 (RFC 5737)
    ipaddress.ip_network("198.18.0.0/15"),   # Benchmarking (RFC 2544)
    ipaddress.ip_network("100.64.0.0/10"),   # Shared Address Space / CGNAT (RFC 6598)
    ipaddress.ip_network("192.0.0.0/24"),    # IETF Protocol Assignments (RFC 6890)
    ipaddress.ip_network("192.88.99.0/24"),  # 6to4 Relay Anycast (RFC 7526)
]


class HelperSecurityError(Exception):
    """Raised when an argument fails validation or a security check fails."""
    pass


class OwnershipMismatchError(HelperSecurityError):
    """Raised when a rule does not belong to the requested action_id."""
    pass


class InspectionError(HelperSecurityError):
    """Raised when inspecting the nftables firewall state fails."""
    pass



def validate_table_name(table_name: str) -> str:
    """Validates the table name against a strict pattern."""
    if not table_name or not isinstance(table_name, str):
        return DEFAULT_TABLE
    clean = table_name.strip()
    if not re.match(r"^[a-zA-Z0-9_\-]{3,32}$", clean):
        raise HelperSecurityError(f"Invalid table name '{clean}'. Must match ^[a-zA-Z0-9_\\-]{{3,32}}$")
    return clean


def validate_action_id(action_id: str) -> str:
    """Validates the action_id against a strict pattern."""
    if not action_id or not isinstance(action_id, str):
        raise HelperSecurityError("Missing or invalid action_id.")
    clean = action_id.strip()
    if not re.match(r"^[a-zA-Z0-9_\-]{3,64}$", clean):
        raise HelperSecurityError(f"action_id '{clean}' invalid. Must match ^[a-zA-Z0-9_\\-]{{3,64}}$")
    return clean


def validate_public_ipv4(ip_str: str) -> ipaddress.IPv4Address:
    """
    Validates single public IPv4 address.
    Rejects private, loopback, link-local, multicast, broadcast, reserved,
    special-use/documentation, and protected infrastructure IPs.
    """
    if not ip_str or not isinstance(ip_str, str):
        raise HelperSecurityError("Missing or non-string IP address.")
    clean_ip = ip_str.strip()
    try:
        addr = ipaddress.ip_address(clean_ip)
    except ValueError as e:
        raise HelperSecurityError(f"Malformed IP address: {e}")

    if not isinstance(addr, ipaddress.IPv4Address):
        raise HelperSecurityError("Only IPv4 addresses are supported.")

    if addr.is_loopback:
        raise HelperSecurityError("Loopback addresses are strictly rejected.")
    if addr.is_private:
        raise HelperSecurityError("Private addresses are strictly rejected.")
    if addr.is_link_local:
        raise HelperSecurityError("Link-local addresses are strictly rejected.")
    if addr.is_multicast:
        raise HelperSecurityError("Multicast addresses are strictly rejected.")
    if addr.is_reserved:
        raise HelperSecurityError("Reserved addresses are strictly rejected.")
    if addr.is_unspecified:
        raise HelperSecurityError("Unspecified address (0.0.0.0) is rejected.")
    if clean_ip == "255.255.255.255":
        raise HelperSecurityError("Broadcast address (255.255.255.255) is rejected.")
    if not addr.is_global:
        raise HelperSecurityError(f"Non-global / special-use address {addr} is strictly rejected.")
    if any(addr in net for net in SPECIAL_AND_DOCUMENTATION_NETWORKS):
        raise HelperSecurityError(f"Special-use or documentation address {addr} is strictly rejected.")
    if addr in PROTECTED_IPV4_HOSTS:
        raise HelperSecurityError(f"Protected infrastructure address {addr} is rejected.")

    return addr


def validate_chain_name(chain: str) -> str:
    """Validates that chain is strictly one of the two managed chains."""
    clean = chain.strip()
    if clean not in ("inbound_filter", "outbound_filter"):
        raise HelperSecurityError(f"Invalid chain '{clean}'. Must be inbound_filter or outbound_filter.")
    return clean


def validate_handle(handle_val: Any) -> int:
    """Validates that handle is a positive integer."""
    try:
        h = int(handle_val)
        if h <= 0:
            raise ValueError()
        return h
    except (TypeError, ValueError):
        raise HelperSecurityError(f"Invalid rule handle '{handle_val}'. Must be a positive integer.")


class CyberscribeNftHelper:
    """Core controller for the privileged nft helper operations."""

    def __init__(self, table_name: str = DEFAULT_TABLE, dry_run: bool = False, nft_bin: str = NFT_BIN):
        self.table_name = validate_table_name(table_name)
        self.dry_run = dry_run
        self.nft_bin = nft_bin

    def _exec_nft(self, args: List[str]) -> Tuple[int, str, str]:
        """Executes /usr/sbin/nft with fixed arguments and no shell."""
        cmd = [self.nft_bin] + args
        if self.dry_run:
            logger.info(f"[DRY RUN] Would execute: {' '.join(cmd)}")
            return 0, "", ""

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=8,
                shell=False
            )
            return proc.returncode, proc.stdout, proc.stderr
        except subprocess.TimeoutExpired:
            raise HelperSecurityError("nft command timed out after 8 seconds.")
        except Exception as e:
            raise HelperSecurityError(f"nft execution failed: {e}")

    def init_table_and_chains(self) -> Dict[str, Any]:
        """Idempotently initializes table 'inet <table_name>' and drop chains."""
        table = self.table_name
        # Add table inet <table_name>
        rc, _, err = self._exec_nft(["add", "table", "inet", table])
        if rc != 0 and "File exists" not in err:
            logger.warning(f"Notice during add table: {err}")

        # Inbound drop chain: input hook priority -5 (runs before firewalld priority 0)
        self._exec_nft([
            "add", "chain", "inet", table, "inbound_filter",
            "{", "type", "filter", "hook", "input", "priority", "-5", ";", "policy", "accept", ";", "}"
        ])

        # Outbound drop chain: output hook priority -5
        self._exec_nft([
            "add", "chain", "inet", table, "outbound_filter",
            "{", "type", "filter", "hook", "output", "priority", "-5", ";", "policy", "accept", ";", "}"
        ])

        return {"status": "INITIALIZED", "table": f"inet {table}"}

    def list_rules(self) -> List[Dict[str, Any]]:
        """
        Parses and lists rules in 'inet <table_name>' with handle and comments.
        Fails closed on any inspection failure: permission errors, command failures,
        malformed output, unclosed braces, or invalid rule structure.
        Only returns an empty list if the table is genuinely absent from the kernel.
        """
        if self.dry_run:
            return []

        try:
            rc, stdout, err = self._exec_nft(["-a", "list", "table", "inet", self.table_name])
        except Exception as e:
            raise InspectionError(f"nftables inspection execution error: {e}") from e

        if rc != 0:
            err_lower = (err or "").lower()
            # Distinguish permission errors
            if any(term in err_lower for term in ("permission denied", "operation not permitted", "not permitted", "access denied")):
                raise InspectionError(
                    f"nftables inspection permission error for table 'inet {self.table_name}': {err.strip()}"
                )
            # Distinguish genuinely missing table
            if "no such file or directory" in err_lower or "does not exist" in err_lower:
                logger.info(f"Table 'inet {self.table_name}' does not exist.")
                return []
            # Any other command failure
            raise InspectionError(
                f"nftables inspection command failed with exit code {rc} for table 'inet {self.table_name}': {err.strip()}"
            )

        # rc == 0: parse and validate output structure
        if not stdout or not stdout.strip():
            raise InspectionError(
                f"nftables inspection returned empty output for existing table 'inet {self.table_name}'"
            )

        # Validate that output contains the table header
        table_pattern = rf"\btable\s+(?:inet\s+)?{re.escape(self.table_name)}\b"
        if not re.search(table_pattern, stdout):
            raise InspectionError(
                f"nftables inspection returned malformed output: table header 'table inet {self.table_name}' not found"
            )

        rules = []
        current_chain = None
        in_table = False
        saw_table_header = False

        for line_num, line in enumerate(stdout.splitlines(), start=1):
            line_str = line.strip()
            if not line_str:
                continue

            # Check table opening
            if re.match(rf"^table\s+(?:inet\s+)?{re.escape(self.table_name)}\s*\{{", line_str):
                in_table = True
                saw_table_header = True
                continue

            # Check chain opening
            chain_match = re.match(r"^chain\s+([a-zA-Z0-9_\-]+)\s+\{", line_str)
            if chain_match:
                if not in_table:
                    raise InspectionError(
                        f"nftables inspection malformed output: chain '{chain_match.group(1)}' declared outside table block"
                    )
                if current_chain is not None:
                    raise InspectionError(
                        f"nftables inspection malformed output: nested chain '{chain_match.group(1)}' inside '{current_chain}'"
                    )
                current_chain = chain_match.group(1)
                continue

            # Check closing brace
            if line_str == "}":
                if current_chain is not None:
                    current_chain = None
                elif in_table:
                    in_table = False
                else:
                    raise InspectionError(f"nftables inspection malformed output: unexpected closing brace on line {line_num}")
                continue

            # Handle rule line
            handle_match = re.search(r"#\s*handle\s+(\d+)", line_str)
            if handle_match:
                if not in_table or current_chain is None:
                    raise InspectionError(
                        f"nftables inspection malformed output: rule with handle found outside chain on line {line_num}: {line_str}"
                    )
                handle = int(handle_match.group(1))
                if handle <= 0:
                    raise InspectionError(
                        f"nftables inspection malformed output: invalid non-positive handle {handle} on line {line_num}"
                    )

                comment_match = re.search(r'comment\s+"([^"]+)"', line_str)
                comment = comment_match.group(1) if comment_match else None

                rules.append({
                    "chain": current_chain,
                    "handle": handle,
                    "rule_line": line_str,
                    "comment": comment
                })
            else:
                # Check if line looks like it had a broken or malformed handle
                if re.search(r"#\s*handle\b", line_str):
                    raise InspectionError(
                        f"nftables inspection malformed handle format on line {line_num}: {line_str}"
                    )

        if not saw_table_header:
            raise InspectionError(
                f"nftables inspection malformed output: missing table opening declaration for 'inet {self.table_name}'"
            )

        if in_table or current_chain is not None:
            raise InspectionError(
                f"nftables inspection malformed output: unclosed braces in nftables output for 'inet {self.table_name}'"
            )

        return rules

    def find_rules_for_action(self, action_id: str) -> List[Dict[str, Any]]:
        """Returns all rules with comment 'cyberscribe:<action_id>'."""
        target_comment = f"cyberscribe:{action_id}"
        all_rules = self.list_rules()
        return [r for r in all_rules if r.get("comment") == target_comment]

    def apply_block(
        self,
        action_id: str,
        ip_str: str,
        direction: str = "both"
    ) -> Dict[str, Any]:
        """
        Applies drop rules for the validated IPv4 address.
        Guarantees atomicity / rollback on partial failure: if any rule addition fails,
        any previously staged rules are cleaned up immediately and cleanup is verified.
        Enforces strict action-ID idempotency (rejects conflicting reuse).
        """
        clean_action_id = validate_action_id(action_id)
        addr = validate_public_ipv4(ip_str)
        clean_direction = direction.strip().lower()
        if clean_direction not in ("both", "inbound", "ingress", "outbound", "egress"):
            raise HelperSecurityError(f"Invalid direction '{clean_direction}'.")

        self.init_table_and_chains()

        # Expected chains based on requested direction
        if clean_direction == "both":
            expected_chains = {"inbound_filter", "outbound_filter"}
        elif clean_direction in ("inbound", "ingress"):
            expected_chains = {"inbound_filter"}
        else:
            expected_chains = {"outbound_filter"}

        # Safe Idempotency check: verify existing action rules match requested IP and direction
        existing = self.find_rules_for_action(clean_action_id)
        if existing:
            existing_chains = {r["chain"] for r in existing}
            ip_mismatch = any(str(addr) not in r.get("rule_line", "") for r in existing)
            if ip_mismatch or existing_chains != expected_chains:
                raise HelperSecurityError(
                    f"Conflicting action reuse: Action ID '{clean_action_id}' already exists with different parameters "
                    f"(existing chains: {sorted(list(existing_chains))}, requested IP: {addr}, direction: {clean_direction})."
                )
            return {
                "status": "APPLIED",
                "action_id": clean_action_id,
                "ip_address": str(addr),
                "direction": clean_direction,
                "is_idempotent": True,
                "handles": [r["handle"] for r in existing],
                "table": f"inet {self.table_name}",
                "message": f"Rule for action '{clean_action_id}' already present with matching parameters."
            }

        table = self.table_name
        comment = f"cyberscribe:{clean_action_id}"
        staged_rules: List[Tuple[str, int]] = []  # List of (chain, handle) for cleanup

        try:
            # 1. Outbound drop rule
            if clean_direction in ("both", "outbound", "egress"):
                rc, _, err = self._exec_nft([
                    "add", "rule", "inet", table, "outbound_filter",
                    "ip", "daddr", str(addr), "drop", "comment", f'"{comment}"'
                ])
                if rc != 0:
                    raise HelperSecurityError(f"Failed to add outbound drop rule: {err}")
                # Track handle for partial-failure rollback
                rules_after = self.find_rules_for_action(clean_action_id)
                outbound_handles = [r for r in rules_after if r["chain"] == "outbound_filter"]
                if outbound_handles:
                    staged_rules.append(("outbound_filter", outbound_handles[-1]["handle"]))

            # 2. Inbound drop rule
            if clean_direction in ("both", "inbound", "ingress"):
                rc, _, err = self._exec_nft([
                    "add", "rule", "inet", table, "inbound_filter",
                    "ip", "saddr", str(addr), "drop", "comment", f'"{comment}"'
                ])
                if rc != 0:
                    raise HelperSecurityError(f"Failed to add inbound drop rule: {err}")
                # Track handle for partial-failure rollback
                rules_after = self.find_rules_for_action(clean_action_id)
                inbound_handles = [r for r in rules_after if r["chain"] == "inbound_filter"]
                if inbound_handles:
                    staged_rules.append(("inbound_filter", inbound_handles[-1]["handle"]))

            # 3. Independent Read-Back Verification
            verified_rules = self.find_rules_for_action(clean_action_id)
            applied_handles = [r["handle"] for r in verified_rules]

            if not verified_rules and not self.dry_run:
                raise HelperSecurityError("Rule staged but read-back verification found no active rules.")

            found_chains = {r["chain"] for r in verified_rules}
            if not self.dry_run and found_chains != expected_chains:
                raise HelperSecurityError(
                    f"Read-back verification incomplete: expected chains {expected_chains}, found {found_chains}."
                )

            # Secondary deep check using verify_rule
            if not self.dry_run:
                v_res = self.verify_rule(clean_action_id, expected_ip=str(addr), direction=clean_direction)
                if not v_res.get("verified"):
                    raise HelperSecurityError(
                        f"Read-back verification failed for action '{clean_action_id}': rule parameters do not match."
                    )

        except Exception as ex:
            initial_err = str(ex)
            logger.error(
                f"Partial failure during rule application for action '{clean_action_id}': {initial_err}. "
                f"Rolling back staged rules: {staged_rules}"
            )
            cleanup_errors = []
            for chain, handle in staged_rules:
                try:
                    rc_del, _, err_del = self._exec_nft(["delete", "rule", "inet", table, chain, "handle", str(handle)])
                    if rc_del != 0:
                        cleanup_errors.append(f"{chain} handle {handle} deletion command returned {rc_del}: {err_del.strip()}")
                except Exception as rb_err:
                    cleanup_errors.append(f"{chain} handle {handle}: {rb_err}")

            # Verify cleanup by independently reading back the table
            try:
                remaining_rules = self.find_rules_for_action(clean_action_id)
                if remaining_rules and not self.dry_run:
                    remaining_handles = [r["handle"] for r in remaining_rules]
                    cleanup_errors.append(f"rules still present in table: {remaining_handles}")
            except Exception as readback_err:
                cleanup_errors.append(f"read-back inspection failed: {readback_err}")

            if cleanup_errors:
                err_msg = (
                    f"Rule application failed ({initial_err}), AND cleanup verification FAILED "
                    f"({'; '.join(cleanup_errors)}). Inconsistent firewall state on table 'inet {table}'; "
                    f"firewall state unverified."
                )
                logger.critical(err_msg)
                raise HelperSecurityError(err_msg)
            else:
                err_msg = (
                    f"Rule application failed; partial rules cleaned up: {initial_err}. "
                    f"Verified clean rollback of {len(staged_rules)} rule(s)."
                )
                logger.info(err_msg)
                raise HelperSecurityError(err_msg)

        return {
            "status": "APPLIED",
            "action_id": clean_action_id,
            "ip_address": str(addr),
            "direction": clean_direction,
            "handles": applied_handles,
            "table": f"inet {table}",
            "verified": len(verified_rules) > 0 or self.dry_run
        }

    def verify_rule(
        self,
        action_id: str,
        expected_ip: Optional[str] = None,
        direction: str = "both"
    ) -> Dict[str, Any]:
        """
        Independent read-back verification of action rule.
        Validates expected IP and direction, confirming that every expected chain
        contains the corresponding drop rule tagged with exact 'cyberscribe:<action_id>' comment.
        A partial rule set returns verification failure (verified: False).
        """
        clean_action_id = validate_action_id(action_id)
        clean_direction = (direction or "both").strip().lower()
        if clean_direction not in ("both", "inbound", "ingress", "outbound", "egress"):
            raise HelperSecurityError(f"Invalid direction '{clean_direction}'.")

        clean_ip = None
        if expected_ip and str(expected_ip).strip().lower() not in ("none", "any", "-", ""):
            clean_ip = str(validate_public_ipv4(str(expected_ip)))

        if clean_direction == "both":
            expected_chains = {"inbound_filter", "outbound_filter"}
        elif clean_direction in ("inbound", "ingress"):
            expected_chains = {"inbound_filter"}
        else:
            expected_chains = {"outbound_filter"}

        if self.dry_run:
            return {
                "action_id": clean_action_id,
                "verified": True,
                "exists": True,
                "expected_chains": sorted(list(expected_chains)),
                "matched_chains": sorted(list(expected_chains)),
                "handles": [],
                "rules": [],
                "dry_run": True
            }

        rules = self.find_rules_for_action(clean_action_id)
        exists = len(rules) > 0
        if not exists:
            return {
                "action_id": clean_action_id,
                "verified": False,
                "exists": False,
                "expected_chains": sorted(list(expected_chains)),
                "matched_chains": [],
                "handles": [],
                "rules": []
            }

        expected_comment = f"cyberscribe:{clean_action_id}"
        matched_chains = set()
        ip_mismatch = False
        detected_ips = set()

        for r in rules:
            chain = r.get("chain")
            comment = r.get("comment")
            rule_line = r.get("rule_line", "")

            # Exact comment check
            if comment != expected_comment:
                continue

            # Must be a drop rule
            if not re.search(r"\bdrop\b", rule_line):
                continue

            # Chain-specific validation
            if chain == "inbound_filter":
                if "saddr" not in rule_line:
                    continue
                match = re.search(r"saddr\s+([0-9\.]+)", rule_line)
                if match:
                    detected_ips.add(match.group(1))
                if clean_ip:
                    if not re.search(rf"\bsaddr\s+{re.escape(clean_ip)}\b", rule_line):
                        ip_mismatch = True
                        continue
                matched_chains.add("inbound_filter")

            elif chain == "outbound_filter":
                if "daddr" not in rule_line:
                    continue
                match = re.search(r"daddr\s+([0-9\.]+)", rule_line)
                if match:
                    detected_ips.add(match.group(1))
                if clean_ip:
                    if not re.search(rf"\bdaddr\s+{re.escape(clean_ip)}\b", rule_line):
                        ip_mismatch = True
                        continue
                matched_chains.add("outbound_filter")

        # If clean_ip was not specified, verify that all detected rules share a single consistent IP
        if not clean_ip and len(detected_ips) > 1:
            ip_mismatch = True

        # Every expected chain must contain the corresponding drop rule
        # A partial rule set (matched_chains != expected_chains) must fail verification
        all_expected_chains_present = (matched_chains == expected_chains)
        verified = exists and all_expected_chains_present and not ip_mismatch

        return {
            "action_id": clean_action_id,
            "verified": verified,
            "exists": exists,
            "expected_chains": sorted(list(expected_chains)),
            "matched_chains": sorted(list(matched_chains)),
            "handles": [r["handle"] for r in rules],
            "rules": [r["rule_line"] for r in rules]
        }

    def delete_rule_by_handle(
        self,
        action_id: str,
        chain: str,
        handle: int
    ) -> Dict[str, Any]:
        """
        Deletes a rule by handle, with STRICT OWNERSHIP VERIFICATION.
        Refuses to delete if the rule does not exist or does NOT match comment 'cyberscribe:<action_id>'.
        """
        clean_action_id = validate_action_id(action_id)
        clean_chain = validate_chain_name(chain)
        clean_handle = validate_handle(handle)

        all_rules = self.list_rules()
        target_rule = next(
            (r for r in all_rules if r["chain"] == clean_chain and r["handle"] == clean_handle),
            None
        )

        expected_comment = f"cyberscribe:{clean_action_id}"

        if not target_rule:
            if self.dry_run:
                return {"status": "DELETED", "handle": clean_handle, "chain": clean_chain}
            raise HelperSecurityError(
                f"Rule handle {clean_handle} not found in chain '{clean_chain}' of table 'inet {self.table_name}'."
            )

        # STRICT OWNERSHIP CHECK: Must match expected action_id comment
        actual_comment = target_rule.get("comment")
        if actual_comment != expected_comment:
            raise OwnershipMismatchError(
                f"Security violation: Rule handle {clean_handle} in chain '{clean_chain}' has comment "
                f"'{actual_comment}', which does NOT match expected '{expected_comment}'. Deletion rejected."
            )

        rc, _, err = self._exec_nft([
            "delete", "rule", "inet", self.table_name, clean_chain, "handle", str(clean_handle)
        ])
        if rc != 0:
            raise HelperSecurityError(f"Failed to delete rule handle {clean_handle}: {err}")

        return {
            "status": "DELETED",
            "action_id": clean_action_id,
            "chain": clean_chain,
            "handle": clean_handle
        }

    def rollback_action(self, action_id: str) -> Dict[str, Any]:
        """
        Rolls back all rules owned by 'cyberscribe:<action_id>'.
        Idempotent: if already absent, positively verifies absence and returns ROLLED_BACK.
        If table inspection fails, raises an error that clearly reports the firewall state as unverified.
        """
        clean_action_id = validate_action_id(action_id)

        if self.dry_run:
            return {
                "status": "ROLLED_BACK",
                "action_id": clean_action_id,
                "removed_handles": [],
                "verified_removed": True,
                "message": f"[DRY RUN] Would rollback rules for action '{clean_action_id}'."
            }

        # Step 1: Inspect table to find rules for this action
        try:
            rules = self.find_rules_for_action(clean_action_id)
        except Exception as insp_err:
            raise HelperSecurityError(
                f"Rollback failed: unable to inspect table 'inet {self.table_name}' ({insp_err}). "
                f"Firewall state unknown / unverified."
            ) from insp_err

        if not rules:
            return {
                "status": "ROLLED_BACK",
                "action_id": clean_action_id,
                "message": "Rule already absent. Idempotent rollback complete.",
                "verified_removed": True,
                "removed_handles": []
            }

        removed_handles = []
        errors = []
        for rule in rules:
            try:
                res = self.delete_rule_by_handle(
                    action_id=clean_action_id,
                    chain=rule["chain"],
                    handle=rule["handle"]
                )
                removed_handles.append(res["handle"])
            except Exception as e:
                errors.append(f"{rule.get('chain')} handle {rule.get('handle')}: {e}")

        # Step 2: Independent Read-Back Verification of rule absence
        try:
            remaining = self.find_rules_for_action(clean_action_id)
        except Exception as readback_err:
            raise HelperSecurityError(
                f"Rollback failed: read-back inspection failed ({readback_err}). "
                f"Firewall state unknown / unverified."
            ) from readback_err

        if remaining or errors:
            rem_handles = [r["handle"] for r in remaining]
            raise HelperSecurityError(
                f"Rollback failed: rule handles {rem_handles} still present in table. "
                f"Firewall state unverified. Errors: {'; '.join(errors)}"
            )

        return {
            "status": "ROLLED_BACK",
            "action_id": clean_action_id,
            "removed_handles": removed_handles,
            "verified_removed": True,
            "message": f"Successfully removed {len(removed_handles)} rule(s) for action '{clean_action_id}'."
        }


def main():
    """CLI entry point for sudo execution."""
    if len(sys.argv) < 2:
        print(json.dumps({"error": "Usage: cyberscribe_nft_helper.py <command> [args...]"}), file=sys.stderr)
        sys.exit(1)

    command = sys.argv[1].lower()
    table_name = os.getenv("FEDORA_NFTABLES_TABLE", DEFAULT_TABLE)
    helper = CyberscribeNftHelper(table_name=table_name)

    try:
        if command == "init":
            result = helper.init_table_and_chains()
            print(json.dumps(result))
            sys.exit(0)

        elif command == "list":
            rules = helper.list_rules()
            print(json.dumps({"rules": rules}))
            sys.exit(0)

        elif command == "apply":
            if len(sys.argv) < 4:
                raise HelperSecurityError("Usage: apply <action_id> <ip_address> [direction]")
            action_id = sys.argv[2]
            ip_str = sys.argv[3]
            direction = sys.argv[4] if len(sys.argv) > 4 else "both"
            res = helper.apply_block(action_id, ip_str, direction)
            print(json.dumps(res))
            sys.exit(0)

        elif command == "verify":
            if len(sys.argv) < 3:
                raise HelperSecurityError("Usage: verify <action_id> [expected_ip] [direction]")
            action_id = sys.argv[2]
            expected_ip = sys.argv[3] if len(sys.argv) > 3 else None
            direction = sys.argv[4] if len(sys.argv) > 4 else "both"
            res = helper.verify_rule(action_id, expected_ip, direction)
            print(json.dumps(res))
            sys.exit(0)

        elif command == "delete-handle":
            if len(sys.argv) < 5:
                raise HelperSecurityError("Usage: delete-handle <action_id> <chain> <handle>")
            action_id = sys.argv[2]
            chain = sys.argv[3]
            handle = int(sys.argv[4])
            res = helper.delete_rule_by_handle(action_id, chain, handle)
            print(json.dumps(res))
            sys.exit(0)

        elif command == "rollback":
            if len(sys.argv) < 3:
                raise HelperSecurityError("Usage: rollback <action_id>")
            action_id = sys.argv[2]
            res = helper.rollback_action(action_id)
            print(json.dumps(res))
            sys.exit(0)

        else:
            raise HelperSecurityError(f"Unknown command: '{command}'")

    except OwnershipMismatchError as ome:
        print(json.dumps({"error": str(ome), "type": "OwnershipMismatchError"}), file=sys.stderr)
        sys.exit(2)
    except InspectionError as ie:
        print(json.dumps({"error": str(ie), "type": "InspectionError"}), file=sys.stderr)
        sys.exit(1)
    except HelperSecurityError as se:
        print(json.dumps({"error": str(se), "type": "HelperSecurityError"}), file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(json.dumps({"error": f"Internal helper error: {str(e)}"}), file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
