"""
Unit & Regression Tests for CyberscribeNftHelper
------------------------------------------------
Tests:
1. Fail closed on inspection errors (distinguish missing table vs permission / command / malformed errors)
2. Strengthened verification (expected IP, expected chains, reject partial rulesets)
3. Partial-failure cleanup with return-code checking and verified read-back
4. Rollback safety (no ROLLED_BACK on inspection failure, positive absence verification)
5. Strict action-ID ownership enforcement and conflicting reuse detection
6. Table isolation (dedicated inet cyberscribe table, no firewalld flush)
7. Dry-run vs live execution separation
"""

import unittest
from unittest.mock import patch, MagicMock, call

from app.services.fedora_executor.cyberscribe_nft_helper import (
    CyberscribeNftHelper,
    HelperSecurityError,
    OwnershipMismatchError,
    InspectionError,
    validate_public_ipv4,
    validate_action_id,
    validate_table_name,
    validate_chain_name,
    validate_handle,
)


class TestCyberscribeNftHelper(unittest.TestCase):

    def setUp(self):
        self.helper = CyberscribeNftHelper(table_name="cyberscribe", dry_run=False)

    # -------------------------------------------------------------------------
    # 1. Fail Closed on Inspection Errors
    # -------------------------------------------------------------------------

    def test_missing_table_returns_empty_ruleset(self):
        """A genuinely missing table must return an empty list without error."""
        # Case A: nftables standard 'No such file or directory'
        with patch.object(self.helper, "_exec_nft", return_value=(1, "", "Error: No such file or directory\nlist table inet cyberscribe")):
            rules = self.helper.list_rules()
            self.assertEqual(rules, [])

        # Case B: nftables 'does not exist' message
        with patch.object(self.helper, "_exec_nft", return_value=(1, "", "Error: table 'inet cyberscribe' does not exist")):
            rules = self.helper.list_rules()
            self.assertEqual(rules, [])

    def test_permission_failure_raises_inspection_error(self):
        """Permission denied must raise InspectionError and NEVER return empty ruleset."""
        permission_errors = [
            "Error: Could not process rule: Permission denied",
            "Error: Could not process rule: Operation not permitted",
            "access denied by kernel policy",
            "operation not permitted on table"
        ]
        for err_msg in permission_errors:
            with patch.object(self.helper, "_exec_nft", return_value=(1, "", err_msg)):
                with self.assertRaises(InspectionError) as ctx:
                    self.helper.list_rules()
                self.assertIn("permission", str(ctx.exception).lower())

    def test_command_failure_raises_inspection_error(self):
        """Non-zero exit codes with unexpected errors must raise InspectionError."""
        with patch.object(self.helper, "_exec_nft", return_value=(2, "", "nft: memory allocation error")):
            with self.assertRaises(InspectionError) as ctx:
                self.helper.list_rules()
            self.assertIn("command failed with exit code 2", str(ctx.exception))

    def test_subprocess_execution_exception_raises_inspection_error(self):
        """Underlying execution timeouts or OS exceptions must raise InspectionError."""
        with patch.object(self.helper, "_exec_nft", side_effect=HelperSecurityError("Timed out")):
            with self.assertRaises(InspectionError) as ctx:
                self.helper.list_rules()
            self.assertIn("inspection execution error", str(ctx.exception))

    def test_malformed_output_empty_raises_inspection_error(self):
        """rc=0 with empty stdout indicates corrupted output and must fail closed."""
        with patch.object(self.helper, "_exec_nft", return_value=(0, "   ", "")):
            with self.assertRaises(InspectionError) as ctx:
                self.helper.list_rules()
            self.assertIn("empty output", str(ctx.exception))

    def test_malformed_output_missing_table_header_raises_inspection_error(self):
        """Missing table header in output must fail closed."""
        malformed = (
            "chain inbound_filter {\n"
            "    type filter hook input priority -5; policy accept;\n"
            "}\n"
        )
        with patch.object(self.helper, "_exec_nft", return_value=(0, malformed, "")):
            with self.assertRaises(InspectionError) as ctx:
                self.helper.list_rules()
            self.assertIn("table header", str(ctx.exception))

    def test_malformed_output_unclosed_brace_raises_inspection_error(self):
        """Truncated output with unclosed braces must raise InspectionError."""
        truncated = (
            "table inet cyberscribe {\n"
            "    chain inbound_filter {\n"
            "        ip saddr 185.220.101.5 drop comment \"cyberscribe:act-01\" # handle 10\n"
        )
        with patch.object(self.helper, "_exec_nft", return_value=(0, truncated, "")):
            with self.assertRaises(InspectionError) as ctx:
                self.helper.list_rules()
            self.assertIn("unclosed braces", str(ctx.exception))

    def test_malformed_output_rule_outside_chain_raises_inspection_error(self):
        """Rule declared outside chain scope must raise InspectionError."""
        bad_structure = (
            "table inet cyberscribe {\n"
            "    ip saddr 185.220.101.5 drop comment \"cyberscribe:act-01\" # handle 10\n"
            "}\n"
        )
        with patch.object(self.helper, "_exec_nft", return_value=(0, bad_structure, "")):
            with self.assertRaises(InspectionError) as ctx:
                self.helper.list_rules()
            self.assertIn("rule with handle found outside chain", str(ctx.exception))

    def test_malformed_output_corrupted_handle_raises_inspection_error(self):
        """Malformed handle syntax must raise InspectionError."""
        corrupted_handle = (
            "table inet cyberscribe {\n"
            "    chain inbound_filter {\n"
            "        ip saddr 185.220.101.5 drop comment \"cyberscribe:act-01\" # handle non_digit\n"
            "    }\n"
            "}\n"
        )
        with patch.object(self.helper, "_exec_nft", return_value=(0, corrupted_handle, "")):
            with self.assertRaises(InspectionError) as ctx:
                self.helper.list_rules()
            self.assertIn("malformed handle format", str(ctx.exception))

    def test_valid_table_output_parses_rules_correctly(self):
        """Valid nftables output parses chains, handles, comments, and rule text."""
        valid_nft = (
            "table inet cyberscribe {\n"
            "    chain inbound_filter {\n"
            "        type filter hook input priority -5; policy accept;\n"
            "        ip saddr 185.220.101.5 drop comment \"cyberscribe:act-01\" # handle 10\n"
            "    }\n"
            "    chain outbound_filter {\n"
            "        type filter hook output priority -5; policy accept;\n"
            "        ip daddr 185.220.101.5 drop comment \"cyberscribe:act-01\" # handle 11\n"
            "    }\n"
            "}\n"
        )
        with patch.object(self.helper, "_exec_nft", return_value=(0, valid_nft, "")):
            rules = self.helper.list_rules()
            self.assertEqual(len(rules), 2)
            self.assertEqual(rules[0]["chain"], "inbound_filter")
            self.assertEqual(rules[0]["handle"], 10)
            self.assertEqual(rules[0]["comment"], "cyberscribe:act-01")
            self.assertEqual(rules[1]["chain"], "outbound_filter")
            self.assertEqual(rules[1]["handle"], 11)
            self.assertEqual(rules[1]["comment"], "cyberscribe:act-01")

    # -------------------------------------------------------------------------
    # 2. Strengthened Verification (verify_rule)
    # -------------------------------------------------------------------------

    def test_verify_rule_one_missing_direction_fails(self):
        """When direction='both', having only inbound or only outbound rule must fail verification."""
        # Only inbound rule exists
        inbound_only = [
            {
                "chain": "inbound_filter",
                "handle": 10,
                "rule_line": 'ip saddr 185.220.101.5 drop comment "cyberscribe:act-partial"',
                "comment": "cyberscribe:act-partial"
            }
        ]
        with patch.object(self.helper, "find_rules_for_action", return_value=inbound_only):
            res = self.helper.verify_rule("act-partial", expected_ip="185.220.101.5", direction="both")
            self.assertFalse(res["verified"])
            self.assertTrue(res["exists"])
            self.assertEqual(res["matched_chains"], ["inbound_filter"])
            self.assertEqual(res["expected_chains"], ["inbound_filter", "outbound_filter"])

        # Only outbound rule exists
        outbound_only = [
            {
                "chain": "outbound_filter",
                "handle": 11,
                "rule_line": 'ip daddr 185.220.101.5 drop comment "cyberscribe:act-partial"',
                "comment": "cyberscribe:act-partial"
            }
        ]
        with patch.object(self.helper, "find_rules_for_action", return_value=outbound_only):
            res = self.helper.verify_rule("act-partial", expected_ip="185.220.101.5", direction="both")
            self.assertFalse(res["verified"])
            self.assertEqual(res["matched_chains"], ["outbound_filter"])

    def test_verify_rule_single_direction_passes_when_expected(self):
        """When direction='inbound' was requested, single inbound rule passes verification."""
        inbound_only = [
            {
                "chain": "inbound_filter",
                "handle": 10,
                "rule_line": 'ip saddr 185.220.101.5 drop comment "cyberscribe:act-single"',
                "comment": "cyberscribe:act-single"
            }
        ]
        with patch.object(self.helper, "find_rules_for_action", return_value=inbound_only):
            res = self.helper.verify_rule("act-single", expected_ip="185.220.101.5", direction="inbound")
            self.assertTrue(res["verified"])
            self.assertEqual(res["matched_chains"], ["inbound_filter"])

    def test_verify_rule_incorrect_ip_fails(self):
        """If the rule contains a different IP than expected, verification must fail."""
        rules_wrong_ip = [
            {
                "chain": "inbound_filter",
                "handle": 10,
                "rule_line": 'ip saddr 93.184.216.34 drop comment "cyberscribe:act-ip-mismatch"',
                "comment": "cyberscribe:act-ip-mismatch"
            },
            {
                "chain": "outbound_filter",
                "handle": 11,
                "rule_line": 'ip daddr 93.184.216.34 drop comment "cyberscribe:act-ip-mismatch"',
                "comment": "cyberscribe:act-ip-mismatch"
            }
        ]
        with patch.object(self.helper, "find_rules_for_action", return_value=rules_wrong_ip):
            res = self.helper.verify_rule("act-ip-mismatch", expected_ip="185.220.101.5", direction="both")
            self.assertFalse(res["verified"])

    def test_verify_rule_matching_both_chains_and_ip_succeeds(self):
        """When both chains are present with drop action and exact IP, verification succeeds."""
        rules_ok = [
            {
                "chain": "inbound_filter",
                "handle": 10,
                "rule_line": 'ip saddr 185.220.101.5 drop comment "cyberscribe:act-ok"',
                "comment": "cyberscribe:act-ok"
            },
            {
                "chain": "outbound_filter",
                "handle": 11,
                "rule_line": 'ip daddr 185.220.101.5 drop comment "cyberscribe:act-ok"',
                "comment": "cyberscribe:act-ok"
            }
        ]
        with patch.object(self.helper, "find_rules_for_action", return_value=rules_ok):
            res = self.helper.verify_rule("act-ok", expected_ip="185.220.101.5", direction="both")
            self.assertTrue(res["verified"])
            self.assertEqual(res["handles"], [10, 11])

    # -------------------------------------------------------------------------
    # 3. Conflicting Action-ID Reuse & Safe Idempotency
    # -------------------------------------------------------------------------

    def test_conflicting_action_id_reuse_different_ip_rejected(self):
        """Reusing action_id with a different IP address must be rejected."""
        existing = [
            {
                "chain": "outbound_filter",
                "handle": 10,
                "rule_line": 'ip daddr 185.220.101.5 drop comment "cyberscribe:act-reuse"',
                "comment": "cyberscribe:act-reuse"
            },
            {
                "chain": "inbound_filter",
                "handle": 11,
                "rule_line": 'ip saddr 185.220.101.5 drop comment "cyberscribe:act-reuse"',
                "comment": "cyberscribe:act-reuse"
            }
        ]
        with patch.object(self.helper, "init_table_and_chains"):
            with patch.object(self.helper, "find_rules_for_action", return_value=existing):
                with self.assertRaises(HelperSecurityError) as ctx:
                    self.helper.apply_block(
                        action_id="act-reuse",
                        ip_str="93.184.216.34",
                        direction="both"
                    )
                self.assertIn("Conflicting action reuse", str(ctx.exception))

    def test_conflicting_action_id_reuse_different_direction_rejected(self):
        """Reusing action_id with different chains/direction must be rejected."""
        existing = [
            {
                "chain": "inbound_filter",
                "handle": 11,
                "rule_line": 'ip saddr 185.220.101.5 drop comment "cyberscribe:act-reuse-dir"',
                "comment": "cyberscribe:act-reuse-dir"
            }
        ]
        with patch.object(self.helper, "init_table_and_chains"):
            with patch.object(self.helper, "find_rules_for_action", return_value=existing):
                with self.assertRaises(HelperSecurityError) as ctx:
                    self.helper.apply_block(
                        action_id="act-reuse-dir",
                        ip_str="185.220.101.5",
                        direction="both"
                    )
                self.assertIn("Conflicting action reuse", str(ctx.exception))

    def test_exact_match_action_id_returns_idempotent_success(self):
        """Exact matching parameters return idempotent APPLIED status."""
        existing = [
            {
                "chain": "inbound_filter",
                "handle": 10,
                "rule_line": 'ip saddr 185.220.101.5 drop comment "cyberscribe:act-idem"',
                "comment": "cyberscribe:act-idem"
            },
            {
                "chain": "outbound_filter",
                "handle": 11,
                "rule_line": 'ip daddr 185.220.101.5 drop comment "cyberscribe:act-idem"',
                "comment": "cyberscribe:act-idem"
            }
        ]
        with patch.object(self.helper, "init_table_and_chains"):
            with patch.object(self.helper, "find_rules_for_action", return_value=existing):
                res = self.helper.apply_block(
                    action_id="act-idem",
                    ip_str="185.220.101.5",
                    direction="both"
                )
                self.assertEqual(res["status"], "APPLIED")
                self.assertTrue(res["is_idempotent"])
                self.assertEqual(res["handles"], [10, 11])

    # -------------------------------------------------------------------------
    # 4. Deletion Return Code & Ownership Enforcement
    # -------------------------------------------------------------------------

    def test_delete_rule_by_handle_checks_command_return_code(self):
        """If nft deletion command exits with non-zero return code, raise HelperSecurityError."""
        mock_rule = [
            {
                "chain": "inbound_filter",
                "handle": 15,
                "rule_line": 'ip saddr 185.220.101.5 drop comment "cyberscribe:act-del-fail"',
                "comment": "cyberscribe:act-del-fail"
            }
        ]
        with patch.object(self.helper, "list_rules", return_value=mock_rule):
            with patch.object(self.helper, "_exec_nft", return_value=(1, "", "Kernel error deleting handle")):
                with self.assertRaises(HelperSecurityError) as ctx:
                    self.helper.delete_rule_by_handle(
                        action_id="act-del-fail",
                        chain="inbound_filter",
                        handle=15
                    )
                self.assertIn("Failed to delete rule handle 15", str(ctx.exception))

    def test_delete_rule_by_handle_ownership_mismatch_fails(self):
        """Attempting to delete a rule belonging to another action_id raises OwnershipMismatchError."""
        mock_rules = [
            {
                "chain": "inbound_filter",
                "handle": 25,
                "rule_line": 'ip saddr 185.220.101.5 drop comment "cyberscribe:act-other"',
                "comment": "cyberscribe:act-other"
            }
        ]
        with patch.object(self.helper, "list_rules", return_value=mock_rules):
            with self.assertRaises(OwnershipMismatchError):
                self.helper.delete_rule_by_handle(
                    action_id="act-mine",
                    chain="inbound_filter",
                    handle=25
                )

    # -------------------------------------------------------------------------
    # 5. Partial-Failure Cleanup & Unverified Firewall State
    # -------------------------------------------------------------------------

    def test_partial_failure_cleanup_deletion_command_failure_reports_unverified(self):
        """If rule deletion fails during partial-failure cleanup, report firewall state as unverified."""
        staged = [
            {
                "chain": "outbound_filter",
                "handle": 100,
                "rule_line": 'ip daddr 185.220.101.5 drop comment "cyberscribe:act-clean-fail"',
                "comment": "cyberscribe:act-clean-fail"
            }
        ]
        # Outbound add succeeds, inbound add fails, delete command fails
        def mock_exec(args):
            if args[0] == "add" and args[4] == "outbound_filter":
                return 0, "", ""
            if args[0] == "add" and args[4] == "inbound_filter":
                return 1, "", "Kernel reject"
            if args[0] == "delete":
                return 1, "", "nft delete failure"
            return 0, "", ""

        with patch.object(self.helper, "init_table_and_chains"):
            with patch.object(self.helper, "find_rules_for_action", side_effect=[[], staged, staged]):
                with patch.object(self.helper, "_exec_nft", side_effect=mock_exec):
                    with self.assertRaises(HelperSecurityError) as ctx:
                        self.helper.apply_block("act-clean-fail", "185.220.101.5", "both")
                    err_msg = str(ctx.exception).lower()
                    self.assertIn("cleanup verification failed", err_msg)
                    self.assertIn("firewall state unverified", err_msg)

    def test_partial_failure_cleanup_inspection_failure_reports_unverified(self):
        """If read-back inspection fails during partial cleanup, report firewall state as unverified."""
        staged = [
            {
                "chain": "outbound_filter",
                "handle": 101,
                "rule_line": 'ip daddr 185.220.101.5 drop comment "cyberscribe:act-insp-fail"',
                "comment": "cyberscribe:act-insp-fail"
            }
        ]
        call_count = 0

        def mock_find(action_id):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return []
            if call_count == 2:
                return staged
            raise InspectionError("Kernel table lock error during inspection")

        def mock_exec(args):
            if args[0] == "add" and args[4] == "outbound_filter":
                return 0, "", ""
            if args[0] == "add" and args[4] == "inbound_filter":
                return 1, "", "Kernel reject"
            if args[0] == "delete":
                return 0, "", ""
            return 0, "", ""

        with patch.object(self.helper, "init_table_and_chains"):
            with patch.object(self.helper, "find_rules_for_action", side_effect=mock_find):
                with patch.object(self.helper, "_exec_nft", side_effect=mock_exec):
                    with self.assertRaises(HelperSecurityError) as ctx:
                        self.helper.apply_block("act-insp-fail", "185.220.101.5", "both")
                    err_msg = str(ctx.exception).lower()
                    self.assertIn("cleanup verification failed", err_msg)
                    self.assertIn("firewall state unverified", err_msg)

    # -------------------------------------------------------------------------
    # 6. Hardened Rollback & Positive Absence Verification
    # -------------------------------------------------------------------------

    def test_rollback_inspection_failure_raises_unverified_error(self):
        """If table cannot be inspected during rollback, do NOT return ROLLED_BACK."""
        with patch.object(self.helper, "find_rules_for_action", side_effect=InspectionError("Permission denied")):
            with self.assertRaises(HelperSecurityError) as ctx:
                self.helper.rollback_action("act-rollback-insp")
            err_msg = str(ctx.exception).lower()
            self.assertIn("unable to inspect table", err_msg)
            self.assertIn("firewall state unknown / unverified", err_msg)

    def test_rollback_readback_inspection_failure_raises_unverified_error(self):
        """If read-back inspection fails after deleting rules, report firewall state as unverified."""
        rules = [
            {
                "chain": "inbound_filter",
                "handle": 30,
                "rule_line": 'ip saddr 185.220.101.5 drop comment "cyberscribe:act-rb-rb"',
                "comment": "cyberscribe:act-rb-rb"
            }
        ]
        with patch.object(self.helper, "find_rules_for_action", side_effect=[rules, InspectionError("Readback failed")]):
            with patch.object(self.helper, "delete_rule_by_handle", return_value={"handle": 30}):
                with self.assertRaises(HelperSecurityError) as ctx:
                    self.helper.rollback_action("act-rb-rb")
                err_msg = str(ctx.exception).lower()
                self.assertIn("read-back inspection failed", err_msg)
                self.assertIn("firewall state unknown / unverified", err_msg)

    def test_idempotent_rollback_positive_absence(self):
        """When rule is genuinely absent, rollback returns ROLLED_BACK with verified_removed=True."""
        with patch.object(self.helper, "find_rules_for_action", return_value=[]):
            res = self.helper.rollback_action("act-absent")
            self.assertEqual(res["status"], "ROLLED_BACK")
            self.assertTrue(res["verified_removed"])
            self.assertEqual(res["removed_handles"], [])

    def test_rollback_successful_deletion_and_verified_removal(self):
        """When rules are deleted and verified absent, rollback returns ROLLED_BACK."""
        rules = [
            {
                "chain": "inbound_filter",
                "handle": 40,
                "rule_line": 'ip saddr 185.220.101.5 drop comment "cyberscribe:act-clean-rb"',
                "comment": "cyberscribe:act-clean-rb"
            },
            {
                "chain": "outbound_filter",
                "handle": 41,
                "rule_line": 'ip daddr 185.220.101.5 drop comment "cyberscribe:act-clean-rb"',
                "comment": "cyberscribe:act-clean-rb"
            }
        ]
        with patch.object(self.helper, "find_rules_for_action", side_effect=[rules, []]):
            with patch.object(self.helper, "delete_rule_by_handle", side_effect=[{"handle": 40}, {"handle": 41}]):
                res = self.helper.rollback_action("act-clean-rb")
                self.assertEqual(res["status"], "ROLLED_BACK")
                self.assertTrue(res["verified_removed"])
                self.assertEqual(res["removed_handles"], [40, 41])

    # -------------------------------------------------------------------------
    # 7. Table Isolation & Dry-Run Separation
    # -------------------------------------------------------------------------

    def test_table_isolation_never_touches_firewalld(self):
        """All commands must target inet cyberscribe and never mention firewalld or issue flush."""
        executed_cmds = []

        def mock_exec(args):
            executed_cmds.append(args)
            return 0, "", ""

        with patch.object(self.helper, "_exec_nft", side_effect=mock_exec):
            self.helper.init_table_and_chains()
            for cmd in executed_cmds:
                cmd_str = " ".join(cmd)
                self.assertNotIn("firewalld", cmd_str)
                self.assertNotIn("flush", cmd_str)
                self.assertIn("cyberscribe", cmd_str)

    def test_dry_run_separation(self):
        """In dry_run mode, no real nft commands are executed to kernel."""
        dry_helper = CyberscribeNftHelper(table_name="cyberscribe", dry_run=True)
        with patch("subprocess.run") as mock_subproc:
            res = dry_helper.apply_block("act-dry", "185.220.101.5", "both")
            self.assertEqual(res["status"], "APPLIED")
            self.assertTrue(res["verified"])
            mock_subproc.assert_not_called()

            rb = dry_helper.rollback_action("act-dry")
            self.assertEqual(rb["status"], "ROLLED_BACK")
            self.assertTrue(rb["verified_removed"])
            mock_subproc.assert_not_called()


if __name__ == "__main__":
    unittest.main()
