"""
Unit & Integration Tests for Windows Defender Firewall Adapter
--------------------------------------------------------------
Verifies:
1. Strict IP and action-ID validation.
2. Safe simulation mode by default (no host commands executed, status=SIMULATED).
3. Narrow scope enforcement (port 8000, inbound, TCP, rule named CyberScribe_<action_id>).
4. Verified application and rollback via mocked netsh execution.
5. Idempotent application and rollback.
6. Honest failure recording on command errors.
7. Zero modification of existing/unrelated firewall rules.
"""

import os
import uuid
from unittest.mock import patch, MagicMock
from tests.base import BaseTestCase
from app import models
from app.services.windows_firewall_adapter import (
    WindowsFirewallAdapter,
    WindowsFirewallError,
    validate_ip_for_containment,
    validate_action_id_str
)


class TestWindowsFirewallAdapter(BaseTestCase):

    def setUp(self):
        super().setUp()
        self.orig_exec_url = os.environ.get("WINDOWS_EXECUTOR_URL")
        os.environ["WINDOWS_EXECUTOR_URL"] = ""
        self.tenant = models.Tenant(
            id=str(uuid.uuid4()),
            company_name="Campus Guide Inc",
            tech_stack="FastAPI, React"
        )
        self.action = models.ContainmentAction(
            id=str(uuid.uuid4()),
            action_id="act-win-test-001",
            tenant_id=self.tenant.id,
            indicator_value="198.51.100.42",
            indicator_type="ipv4",
            action_type="BLOCK_INBOUND_PORT_8000",
            policy_decision="QUALIFIED",
            status="PENDING",
            ttl_seconds=3600
        )
        self.db.add(self.action)
        self.db.commit()

    def tearDown(self):
        if self.orig_exec_url is not None:
            os.environ["WINDOWS_EXECUTOR_URL"] = self.orig_exec_url
        else:
            os.environ.pop("WINDOWS_EXECUTOR_URL", None)
        super().tearDown()

    def test_ip_and_action_id_validation(self):
        """Verifies strict input validation for IP addresses and action IDs."""
        self.assertEqual(validate_ip_for_containment("198.51.100.42"), "198.51.100.42")
        self.assertEqual(validate_action_id_str("act-win-test-001"), "act-win-test-001")

        with self.assertRaises(WindowsFirewallError):
            validate_ip_for_containment("not-an-ip")
        with self.assertRaises(WindowsFirewallError):
            validate_ip_for_containment("999.999.999.999")
        with self.assertRaises(WindowsFirewallError):
            validate_action_id_str("bad id with spaces!")

    def test_simulation_mode_is_default_and_safe(self):
        """Verifies that simulation mode is safe, stages the rule, and executes no commands."""
        res = WindowsFirewallAdapter.apply_containment(
            action=self.action,
            db=self.db,
            is_simulated=True
        )

        self.assertEqual(res["status"], "SIMULATED")
        self.assertTrue(res["is_simulated"])
        self.assertEqual(res["target_port"], 8000)
        self.assertEqual(res["target_ip"], "198.51.100.42")
        self.assertEqual(res["rule_name"], "CyberScribe_act-win-test-001")

        # Database record must reflect SIMULATED
        self.db.refresh(self.action)
        self.assertEqual(self.action.status, "SIMULATED")
        self.assertIsNotNone(self.action.applied_at)
        self.assertIsNotNone(self.action.expires_at)

        # Audit log must be persisted
        audit = self.db.query(models.ContainmentAuditLog).filter(
            models.ContainmentAuditLog.action_id == self.action.id
        ).first()
        self.assertIsNotNone(audit)
        self.assertEqual(audit.new_status, "SIMULATED")

    def test_simulation_idempotency(self):
        """Verifies repeated application in simulation mode is cleanly idempotent."""
        WindowsFirewallAdapter.apply_containment(self.action, self.db, is_simulated=True)
        res2 = WindowsFirewallAdapter.apply_containment(self.action, self.db, is_simulated=True)
        self.assertEqual(res2["status"], "SIMULATED")

    def test_simulation_rollback(self):
        """Verifies simulated rollback transitions to ROLLED_BACK."""
        WindowsFirewallAdapter.apply_containment(self.action, self.db, is_simulated=True)
        roll_res = WindowsFirewallAdapter.rollback_containment(self.action, self.db)

        self.assertEqual(roll_res["status"], "ROLLED_BACK")
        self.db.refresh(self.action)
        self.assertEqual(self.action.status, "ROLLED_BACK")
        self.assertIsNotNone(self.action.rolled_back_at)

    @patch("app.services.windows_firewall_adapter.WindowsFirewallAdapter._run_netsh")
    @patch("app.services.windows_firewall_adapter.WindowsFirewallAdapter.show_rule")
    def test_live_enforcement_and_verification(self, mock_show_rule, mock_run_netsh):
        """Verifies live mode application, verification, and rollback using mocked netsh with public IP."""
        self.action.indicator_value = "93.184.216.34"
        self.db.commit()

        mock_show_rule.side_effect = [
            None,
            {
                "Rule Name": "CyberScribe_act-win-test-001",
                "Direction": "In",
                "Action": "Block",
                "LocalPort": "8000",
                "RemoteIP": "93.184.216.34",
                "Protocol": "TCP"
            }
        ]
        mock_run_netsh.return_value = (0, "Ok.\n", "")

        res = WindowsFirewallAdapter.apply_containment(
            action=self.action,
            db=self.db,
            is_simulated=False
        )

        self.assertEqual(res["status"], "VERIFIED")
        self.assertTrue(res["is_live_enforcement"])
        self.assertEqual(res["rule_name"], "CyberScribe_act-win-test-001")

        # Assert exact netsh add rule arguments proving narrowly scoped targeting
        mock_run_netsh.assert_called_once()
        called_args = mock_run_netsh.call_args[0][0]
        self.assertIn("add", called_args)
        self.assertIn("rule", called_args)
        self.assertIn("name=CyberScribe_act-win-test-001", called_args)
        self.assertIn("dir=in", called_args)
        self.assertIn("action=block", called_args)
        self.assertIn("protocol=TCP", called_args)
        self.assertIn("localport=8000", called_args)
        self.assertIn("remoteip=93.184.216.34", called_args)
        # Ensure it does NOT broadly block all inbound traffic on port 8000
        self.assertNotIn("remoteip=any", [a.lower() for a in called_args])
        self.assertNotIn("remoteip=*", called_args)

        self.db.refresh(self.action)
        self.assertEqual(self.action.status, "VERIFIED")
        self.assertIsNotNone(self.action.verified_at)

    def test_reserved_documentation_ip_rejected_in_live_mode(self):
        """Phase C requirement: Reserved/documentation IPs (198.51.100.123) are rejected in live mode."""
        self.action.indicator_value = "198.51.100.123"
        self.db.commit()

        # In live mode (is_simulated=False), reserved IP MUST fail with an explicit rejection
        res = WindowsFirewallAdapter.apply_containment(
            action=self.action,
            db=self.db,
            is_simulated=False
        )
        self.assertEqual(res["status"], "FAILED")
        self.assertIn("reserved documentation", res.get("error", "").lower())

        # In simulation mode (is_simulated=True), reserved IP is permitted for fixtures
        sim_res = WindowsFirewallAdapter.apply_containment(
            action=self.action,
            db=self.db,
            is_simulated=True
        )
        self.assertEqual(sim_res["status"], "SIMULATED")

    @patch("app.services.windows_firewall_adapter.WindowsFirewallAdapter._run_netsh")
    @patch("app.services.windows_firewall_adapter.WindowsFirewallAdapter.show_rule")
    def test_live_rollback_removes_exact_rule(self, mock_show_rule, mock_run_netsh):
        """Verifies live rollback executes netsh delete rule and confirms absence."""
        self.action.status = "VERIFIED"
        self.db.commit()

        # Post-rollback check confirms rule is absent (returns None)
        mock_show_rule.return_value = None
        mock_run_netsh.return_value = (0, "Deleted 1 rule(s).\nOk.\n", "")

        res = WindowsFirewallAdapter.rollback_containment(self.action, self.db)
        self.assertEqual(res["status"], "ROLLED_BACK")

        # Verify netsh was called with exact rule name
        mock_run_netsh.assert_called_with(["delete", "rule", "name=CyberScribe_act-win-test-001"])

        self.db.refresh(self.action)
        self.assertEqual(self.action.status, "ROLLED_BACK")

    @patch("app.services.windows_firewall_adapter.WindowsFirewallAdapter._run_netsh")
    @patch("app.services.windows_firewall_adapter.WindowsFirewallAdapter.show_rule")
    def test_live_apply_command_failure_reports_failed(self, mock_show_rule, mock_run_netsh):
        """Verifies that elevation errors or netsh failures mark the action FAILED."""
        self.action.indicator_value = "93.184.216.34"
        self.db.commit()

        mock_show_rule.return_value = None
        mock_run_netsh.return_value = (1, "The requested operation requires elevation (Run as administrator).\n", "")

        res = WindowsFirewallAdapter.apply_containment(
            action=self.action,
            db=self.db,
            is_simulated=False
        )

        self.assertEqual(res["status"], "FAILED")
        self.db.refresh(self.action)
        self.assertEqual(self.action.status, "FAILED")
        self.assertIn("requires elevation", self.action.error_message)

    @patch("app.services.windows_firewall_adapter.WindowsFirewallAdapter._run_netsh")
    @patch("app.services.windows_firewall_adapter.WindowsFirewallAdapter.show_rule")
    def test_inbound_exploit_source_creates_inbound_rule_on_port_8000(self, mock_show_rule, mock_run_netsh):
        """
        Confirms that malicious inbound exploit sources targeting Campus Guide
        strictly trigger an inbound TCP port 8000 drop rule.
        """
        inbound_action = models.ContainmentAction(
            id=str(uuid.uuid4()),
            action_id="act-win-inbound-01",
            tenant_id=self.tenant.id,
            indicator_value="185.220.101.11",
            indicator_type="ipv4",
            action_type="BLOCK_INBOUND_PORT_8000",
            policy_decision="QUALIFIED",
            policy_rule="INBOUND_EXPLOIT_DEFENSE",
            status="PENDING",
            ttl_seconds=3600
        )
        self.db.add(inbound_action)
        self.db.commit()

        # 1. Non-destructive simulation check
        sim_res = WindowsFirewallAdapter.apply_containment(inbound_action, self.db, is_simulated=True)
        self.assertEqual(sim_res["status"], "SIMULATED")
        self.assertEqual(sim_res["direction"], "INBOUND")
        self.assertEqual(sim_res["target_port"], 8000)
        self.assertEqual(sim_res["rule_spec"]["direction"], "INBOUND")
        self.assertEqual(sim_res["rule_spec"]["protocol"], "TCP")
        self.assertEqual(sim_res["rule_spec"]["local_port"], 8000)

        # 2. Mocked live check asserting exact netsh command arguments
        mock_show_rule.side_effect = [
            None,
            {
                "Rule Name": f"CyberScribe_{inbound_action.action_id}",
                "Direction": "In",
                "Action": "Block",
                "LocalPort": "8000",
                "RemoteIP": "185.220.101.11",
                "Protocol": "TCP"
            }
        ]
        mock_run_netsh.return_value = (0, "Ok.\n", "")

        # Reset to PENDING for live test
        inbound_action.status = "PENDING"
        self.db.commit()

        live_res = WindowsFirewallAdapter.apply_containment(inbound_action, self.db, is_simulated=False)
        self.assertEqual(live_res["status"], "VERIFIED")
        self.assertEqual(live_res["direction"], "INBOUND")
        self.assertEqual(live_res["target_port"], 8000)

        # Assert exact netsh arguments for inbound rule
        mock_run_netsh.assert_called_once()
        cmd_args = mock_run_netsh.call_args[0][0]
        self.assertIn("dir=in", cmd_args)
        self.assertIn("action=block", cmd_args)
        self.assertIn("protocol=TCP", cmd_args)
        self.assertIn("localport=8000", cmd_args)
        self.assertIn("remoteip=185.220.101.11", cmd_args)

    @patch("app.services.windows_firewall_adapter.WindowsFirewallAdapter._run_netsh")
    @patch("app.services.windows_firewall_adapter.WindowsFirewallAdapter.show_rule")
    def test_feodo_tracker_c2_cannot_trigger_inbound_only_rule_and_creates_outbound_rule(self, mock_show_rule, mock_run_netsh):
        """
        CRITICAL SECURITY CHECK:
        Confirms Feodo Tracker botnet C2 indicators CANNOT trigger an inbound-only rule
        on port 8000 (which would fail to block outbound C2 beacon/bot traffic).
        Must strictly trigger an outbound destination rule (dir=out remoteip=<ip>).
        """
        c2_action = models.ContainmentAction(
            id=str(uuid.uuid4()),
            action_id="act-win-feodo-01",
            tenant_id=self.tenant.id,
            indicator_value="185.220.101.99",
            indicator_type="ipv4",
            action_type="BLOCK_IPV4_DESTINATION",
            policy_decision="QUALIFIED",
            policy_rule="FEODO_TRACKER_C2_CONTAINMENT",
            status="PENDING",
            ttl_seconds=3600,
            rule_spec={
                "action": "DROP_EGRESS_IPV4",
                "direction": "egress",
                "feed_source": "Feodo Tracker C2",
                "evidence_summary": "Grounded botnet C2 observation from Feodo Tracker C2"
            }
        )
        self.db.add(c2_action)
        self.db.commit()

        # 1. Non-destructive simulation check
        sim_res = WindowsFirewallAdapter.apply_containment(c2_action, self.db, is_simulated=True)
        self.assertEqual(sim_res["status"], "SIMULATED")
        self.assertEqual(sim_res["direction"], "OUTBOUND")
        self.assertIsNone(sim_res["target_port"])
        self.assertEqual(sim_res["rule_spec"]["direction"], "OUTBOUND")
        self.assertNotIn("local_port", sim_res["rule_spec"])
        self.assertIn("Outbound Botnet/C2 Destination", sim_res["rule_spec"]["target_scope"])

        # 2. Mocked live check asserting exact netsh command arguments
        mock_show_rule.side_effect = [
            None,
            {
                "Rule Name": f"CyberScribe_{c2_action.action_id}",
                "Direction": "Out",
                "Action": "Block",
                "RemoteIP": "185.220.101.99"
            }
        ]
        mock_run_netsh.return_value = (0, "Ok.\n", "")

        c2_action.status = "PENDING"
        self.db.commit()

        live_res = WindowsFirewallAdapter.apply_containment(c2_action, self.db, is_simulated=False)
        self.assertEqual(live_res["status"], "VERIFIED")
        self.assertEqual(live_res["direction"], "OUTBOUND")
        self.assertIsNone(live_res["target_port"])

        # Assert exact netsh arguments for outbound C2 destination rule
        mock_run_netsh.assert_called_once()
        cmd_args = mock_run_netsh.call_args[0][0]
        self.assertIn("dir=out", cmd_args)
        self.assertIn("action=block", cmd_args)
        self.assertIn("remoteip=185.220.101.99", cmd_args)
        # MUST NOT contain inbound port 8000 constraints!
        self.assertNotIn("dir=in", cmd_args)
        self.assertNotIn("localport=8000", cmd_args)
        self.assertNotIn("protocol=TCP", cmd_args)

    @patch("app.services.windows_firewall_adapter.WindowsFirewallAdapter._run_netsh")
    def test_unestablished_traffic_direction_rejects_rule_and_requires_approval(self, mock_run_netsh):
        """
        If the required traffic direction (inbound exploit source vs outbound C2 destination)
        cannot be established from evidence and policy, the firewall adapter MUST NOT apply a rule;
        it must mark the action REJECTED, log the reason, and require further evidence or manual approval.
        """
        ambiguous_action = models.ContainmentAction(
            id=str(uuid.uuid4()),
            action_id="act-win-ambig-01",
            tenant_id=self.tenant.id,
            indicator_value="198.51.100.44",
            indicator_type="ipv4",
            action_type="GENERIC_IP_BLOCK",
            policy_decision="QUALIFIED",
            policy_rule="GENERIC_UNSTRUCTURED_RULE",
            status="PENDING",
            ttl_seconds=3600
        )
        self.db.add(ambiguous_action)
        self.db.commit()

        res = WindowsFirewallAdapter.apply_containment(ambiguous_action, self.db, is_simulated=True)

        self.assertEqual(res["status"], "REJECTED")
        self.assertIsNone(res["direction"])
        self.assertTrue(res["requires_further_evidence_or_approval"])
        self.assertIn("CONTAINMENT_DIRECTION_UNRESOLVED", res["error"])

        # DB status must be updated to REJECTED
        self.db.refresh(ambiguous_action)
        self.assertEqual(ambiguous_action.status, "REJECTED")
        self.assertIn("CONTAINMENT_DIRECTION_UNRESOLVED", ambiguous_action.error_message)

        # Audit log must be recorded
        audit = self.db.query(models.ContainmentAuditLog).filter(
            models.ContainmentAuditLog.action_id == ambiguous_action.id,
            models.ContainmentAuditLog.event_type == "CONTAINMENT_DIRECTION_UNRESOLVED"
        ).first()
        self.assertIsNotNone(audit)
        self.assertEqual(audit.new_status, "REJECTED")

        # Zero netsh commands executed
        mock_run_netsh.assert_not_called()

    # =========================================================================
    # Focused Lab-Only Fedora VM (192.168.56.101) Containment Tests
    # =========================================================================

    def test_lab_fedora_vm_rejected_by_default_in_live_mode(self):
        """Without ALLOW_LAB_FEDORA_HOST_CONTAINMENT=true, lab IP 192.168.56.101 is rejected in live mode."""
        self.action.indicator_value = "192.168.56.101"
        self.db.commit()

        # Ensure lab auth is unset
        with patch.dict("os.environ", {}, clear=False):
            if "ALLOW_LAB_FEDORA_HOST_CONTAINMENT" in os.environ:
                del os.environ["ALLOW_LAB_FEDORA_HOST_CONTAINMENT"]
            res = WindowsFirewallAdapter.apply_containment(self.action, self.db, is_simulated=False)

        self.assertEqual(res["status"], "FAILED")
        self.assertIn("ALLOW_LAB_FEDORA_HOST_CONTAINMENT is not enabled", res.get("error", ""))

    @patch("app.services.windows_firewall_adapter.WindowsFirewallAdapter._run_netsh")
    @patch("app.services.windows_firewall_adapter.WindowsFirewallAdapter.show_rule")
    def test_lab_fedora_vm_permitted_when_explicitly_authorized(self, mock_show_rule, mock_run_netsh):
        """With ALLOW_LAB_FEDORA_HOST_CONTAINMENT=true, lab IP 192.168.56.101 is accepted for inbound port 8000."""
        self.action.indicator_value = "192.168.56.101"
        self.action.action_type = "BLOCK_INBOUND_PORT_8000"
        self.action.policy_rule = "INBOUND_EXPLOIT_DEFENSE"
        self.db.commit()

        mock_show_rule.side_effect = [
            None,
            {
                "Rule Name": "CyberScribe_act-win-test-001",
                "Direction": "In",
                "Action": "Block",
                "LocalPort": "8000",
                "RemoteIP": "192.168.56.101",
                "Protocol": "TCP"
            }
        ]
        mock_run_netsh.return_value = (0, "Ok.\n", "")

        with patch.dict("os.environ", {"ALLOW_LAB_FEDORA_HOST_CONTAINMENT": "true"}):
            res = WindowsFirewallAdapter.apply_containment(self.action, self.db, is_simulated=False)

        self.assertEqual(res["status"], "VERIFIED")
        self.assertTrue(res["is_live_enforcement"])
        self.assertEqual(res["rule_name"], "CyberScribe_act-win-test-001")
        self.assertEqual(res["target_port"], 8000)

        # Verify netsh arguments were narrowly scoped
        mock_run_netsh.assert_called_once()
        cmd_args = mock_run_netsh.call_args[0][0]
        self.assertIn("add", cmd_args)
        self.assertIn("rule", cmd_args)
        self.assertIn("name=CyberScribe_act-win-test-001", cmd_args)
        self.assertIn("dir=in", cmd_args)
        self.assertIn("action=block", cmd_args)
        self.assertIn("protocol=TCP", cmd_args)
        self.assertIn("localport=8000", cmd_args)
        self.assertIn("remoteip=192.168.56.101", cmd_args)

    @patch("app.services.windows_firewall_adapter.WindowsFirewallAdapter._run_netsh")
    @patch("app.services.windows_firewall_adapter.WindowsFirewallAdapter.show_rule")
    def test_lab_fedora_vm_idempotency_and_rollback_readback(self, mock_show_rule, mock_run_netsh):
        """Verifies idempotent live application and verified rollback for lab IP 192.168.56.101."""
        self.action.indicator_value = "192.168.56.101"
        self.action.action_type = "BLOCK_INBOUND_PORT_8000"
        self.action.policy_rule = "INBOUND_EXPLOIT_DEFENSE"
        self.action.status = "VERIFIED"
        self.db.commit()

        # 1. Idempotent re-application in live mode returns active status without duplicate netsh call
        with patch.dict("os.environ", {"ALLOW_LAB_FEDORA_HOST_CONTAINMENT": "true"}):
            res_idemp = WindowsFirewallAdapter.apply_containment(self.action, self.db, is_simulated=False)
        self.assertEqual(res_idemp["status"], "VERIFIED")
        mock_run_netsh.assert_not_called()

        # 2. Rollback deletes exact rule and performs read-back verification
        mock_show_rule.return_value = None  # Confirms rule is absent post-delete
        mock_run_netsh.return_value = (0, "Deleted 1 rule(s).\nOk.\n", "")

        with patch.dict("os.environ", {"ALLOW_LAB_FEDORA_HOST_CONTAINMENT": "true"}):
            roll_res = WindowsFirewallAdapter.rollback_containment(self.action, self.db)

        self.assertEqual(roll_res["status"], "ROLLED_BACK")
        mock_run_netsh.assert_called_with(["delete", "rule", "name=CyberScribe_act-win-test-001"])
        self.db.refresh(self.action)
        self.assertEqual(self.action.status, "ROLLED_BACK")

    def test_lab_fedora_vm_rejects_outbound_direction(self):
        """Lab IP 192.168.56.101 is strictly restricted to inbound; outbound direction is rejected."""
        self.action.indicator_value = "192.168.56.101"
        self.action.action_type = "BLOCK_IPV4_DESTINATION"
        self.action.policy_rule = "FEODO_TRACKER_C2_CONTAINMENT"
        self.action.rule_spec = {"action": "DROP_EGRESS_IPV4", "direction": "egress"}
        self.db.commit()

        with patch.dict("os.environ", {"ALLOW_LAB_FEDORA_HOST_CONTAINMENT": "true"}):
            res = WindowsFirewallAdapter.apply_containment(self.action, self.db, is_simulated=False)

        self.assertEqual(res["status"], "FAILED")
        self.assertIn("strictly restricted to inbound exploit containment", res.get("error", ""))

    def test_lab_fedora_vm_rejects_non_8000_port(self):
        """Lab IP 192.168.56.101 is strictly restricted to port 8000; other ports are rejected."""
        self.action.indicator_value = "192.168.56.101"
        self.action.action_type = "BLOCK_INBOUND_PORT_8000"
        self.action.policy_rule = "INBOUND_EXPLOIT_DEFENSE"
        self.db.commit()

        with patch.dict("os.environ", {"ALLOW_LAB_FEDORA_HOST_CONTAINMENT": "true"}):
            res = WindowsFirewallAdapter.apply_containment(self.action, self.db, target_port=8080, is_simulated=False)

        self.assertEqual(res["status"], "FAILED")
        self.assertIn("strictly restricted to inbound port 8000", res.get("error", ""))

    def test_other_private_and_reserved_ips_strictly_rejected_even_with_lab_enabled(self):
        """ALLOW_LAB_FEDORA_HOST_CONTAINMENT=true does NOT weaken protection for any other private/reserved IP."""
        unauthorized_ips = [
            "192.168.56.102",  # Adjacent host in same lab subnet
            "192.168.1.1",     # Router / Gateway
            "10.0.0.1",        # RFC1918 Class A
            "172.16.0.1",      # RFC1918 Class B
            "198.51.100.42",   # Documentation range
        ]

        with patch.dict("os.environ", {"ALLOW_LAB_FEDORA_HOST_CONTAINMENT": "true"}):
            for ip in unauthorized_ips:
                self.action.indicator_value = ip
                self.action.status = "PENDING"
                self.db.commit()

                res = WindowsFirewallAdapter.apply_containment(self.action, self.db, is_simulated=False)
                self.assertEqual(
                    res["status"],
                    "FAILED",
                    f"Private/reserved IP {ip} must be rejected even with lab authorization enabled."
                )
                self.assertIn("reserved documentation / private / non-routable range", res.get("error", "").lower())

    def test_cyberscribe_win_helper_lab_fedora_validation(self):
        """Direct tests for cyberscribe_win_helper lab Fedora authorization and scoping restrictions."""
        from app.services.windows_executor import cyberscribe_win_helper as helper

        # 1. Disabled by default
        with patch.dict("os.environ", {}, clear=False):
            if "ALLOW_LAB_FEDORA_HOST_CONTAINMENT" in os.environ:
                del os.environ["ALLOW_LAB_FEDORA_HOST_CONTAINMENT"]
            with self.assertRaises(helper.HelperSecurityError):
                helper.validate_public_ipv4("192.168.56.101", allow_reserved=False)

        # 2. Enabled allows 192.168.56.101 for inbound port 8000
        with patch.dict("os.environ", {"ALLOW_LAB_FEDORA_HOST_CONTAINMENT": "true"}):
            val_ip = helper.validate_public_ipv4("192.168.56.101", allow_reserved=False, target_port=8000, direction="in")
            self.assertEqual(val_ip, "192.168.56.101")

            # 3. Enabled strictly rejects adjacent host 192.168.56.102
            with self.assertRaises(helper.HelperSecurityError):
                helper.validate_public_ipv4("192.168.56.102", allow_reserved=False)

            # 4. Outbound direction rejected for lab IP
            with self.assertRaises(helper.HelperSecurityError):
                helper.validate_public_ipv4("192.168.56.101", allow_reserved=False, direction="out")

            # 5. Non-8000 port rejected for lab IP
            with self.assertRaises(helper.HelperSecurityError):
                helper.validate_public_ipv4("192.168.56.101", allow_reserved=False, target_port=8080)

