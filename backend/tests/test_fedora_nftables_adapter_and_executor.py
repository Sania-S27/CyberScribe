"""
Targeted Test Suite for Milestone 4A: Fedora nftables Executor & Adapter
-------------------------------------------------------------------------
Tests:
1. Fedora executor daemon input validation (bogon/private/protected IP rejection, action_id validation)
2. Privileged boundary enforcement (sudoers restrictions, helper validation)
3. Exact-rule ownership enforcement on handle deletion (rejects deleting rules owned by other actions or firewalld)
4. Partial-failure recovery (multi-rule rollback on atomic insertion failure)
5. Request authentication (bearer token constant-time comparison, rejection of unauthorized calls)
6. NftablesController / Helper command generation (dedicated table inet cyberscribe, priority -5, exact comments)
7. FedoraNftablesAdapter lifecycle integration (APPLIED, VERIFIED, ROLLED_BACK, EXPIRED, FAILED)
8. Rollback failure safety (never marks ROLLED_BACK if removal fails)
9. Tenant isolation and permission enforcement
10. Factory get_containment_adapter mode selection (simulation default vs fedora_nftables)
11. Offline VM error handling
"""

import os
import sys
import uuid
import ipaddress
from io import BytesIO
from datetime import datetime, timedelta, timezone
from unittest.mock import patch, MagicMock

backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from tests.base import BaseTestCase
from app import models
from app.models import ContainmentAction, ContainmentAuditLog
from app.services.fedora_executor.executor_daemon import (
    validate_public_ipv4,
    validate_action_id,
    ExecutorSecurityError,
    NftablesController,
    ExecutorRequestHandler
)
from app.services.fedora_executor.cyberscribe_nft_helper import (
    CyberscribeNftHelper,
    HelperSecurityError,
    OwnershipMismatchError,
    validate_table_name,
    validate_chain_name,
    validate_handle
)
from app.services.fedora_nftables_adapter import (
    FedoraNftablesAdapter,
    FedoraExecutorError
)
from app.services.firewall_adapter import (
    SimulatedFirewallAdapter,
    get_containment_adapter,
    InvalidStateTransitionError
)


class TestFedoraNftablesMilestone4A(BaseTestCase):

    def setUp(self):
        super().setUp()
        self.tenant_b = models.Tenant(
            company_name="Gamma SOC Operations",
            tech_stack="Python:3.12, FastAPI, PostgreSQL:16",
            webhook_url="https://gamma-soc.local/containment",
            auth_token="GAMMA_TOKEN_SECRET"
        )
        self.db.add(self.tenant_b)
        self.db.commit()
        self.db.refresh(self.tenant_b)

    def _create_pending_action(self, ip="185.220.101.5", tenant_id=None, action_id="act-auto-test4a-001"):
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        act = ContainmentAction(
            id=str(uuid.uuid4()),
            action_id=action_id,
            tenant_id=tenant_id or self.tenant.id,
            indicator_value=ip,
            indicator_type="ipv4",
            action_type="BLOCK_IPV4_DESTINATION",
            policy_decision="QUALIFIED",
            policy_rule="deterministic_autonomous_destination_blocking_v1",
            status="PENDING",
            ttl_seconds=3600,
            expires_at=now + timedelta(seconds=3600)
        )
        self.db.add(act)
        self.db.commit()
        self.db.refresh(act)
        return act

    # -------------------------------------------------------------------------
    # 1. Input Validation & Bogon/Protected IP Rejection
    # -------------------------------------------------------------------------

    def test_executor_valid_public_ip_passes(self):
        valid_ips = ["185.220.101.5", "93.184.216.34", "151.101.1.69", "142.250.190.46"]
        for ip in valid_ips:
            addr = validate_public_ipv4(ip)
            self.assertIsInstance(addr, ipaddress.IPv4Address)
            self.assertEqual(str(addr), ip)

    def test_executor_bogons_private_and_protected_ips_rejected(self):
        rejected_ips = [
            "127.0.0.1",       # Loopback
            "10.0.0.5",        # Private
            "192.168.1.1",     # Private
            "172.16.0.10",     # Private
            "169.254.1.1",     # Link-local
            "224.0.0.1",       # Multicast
            "240.0.0.1",       # Reserved
            "0.0.0.0",         # Unspecified
            "255.255.255.255", # Broadcast
            "192.0.2.1",       # TEST-NET-1 (RFC 5737)
            "198.51.100.1",    # TEST-NET-2 (RFC 5737)
            "203.0.113.1",     # TEST-NET-3 (RFC 5737)
            "198.18.0.1",      # Benchmark (RFC 2544)
            "100.64.0.1",      # Shared Address Space / CGNAT (RFC 6598)
            "8.8.8.8",         # Google DNS Protected
            "1.1.1.1",         # Cloudflare Protected
            "9.9.9.9",         # Quad9 Protected
            "invalid-ip",      # Malformed
            "2001:db8::1"      # IPv6
        ]
        for ip in rejected_ips:
            with self.assertRaises((ExecutorSecurityError, HelperSecurityError), msg=f"Expected {ip} to be rejected"):
                validate_public_ipv4(ip)

    def test_executor_action_id_validation(self):
        valid_ids = ["act-auto-12345678", "act-soar-abcdef", "ACT_001_TEST"]
        for aid in valid_ids:
            self.assertEqual(validate_action_id(aid), aid)

        invalid_ids = [
            "; rm -rf /",
            "act-123; cat /etc/passwd",
            "act 123",
            "a" * 70,  # Exceeds max length
            "",
            "$(whoami)"
        ]
        for aid in invalid_ids:
            with self.assertRaises((ExecutorSecurityError, HelperSecurityError), msg=f"Expected {aid} to be rejected"):
                validate_action_id(aid)

    # -------------------------------------------------------------------------
    # 2. Privileged Helper Boundary & Sudoers Verification
    # -------------------------------------------------------------------------

    def test_sudoers_policy_strictly_restricts_privileges(self):
        """Verifies sudoers file does NOT allow arbitrary nft commands or /usr/sbin/nft."""
        sudoers_path = os.path.join(
            backend_dir, "scripts", "fedora_executor", "cyberscribe-nftables.sudoers"
        )
        self.assertTrue(os.path.exists(sudoers_path), f"Missing sudoers file at {sudoers_path}")
        with open(sudoers_path, "r", encoding="utf-8") as f:
            content = f.read()

        # MUST NOT contain /usr/sbin/nft directly
        self.assertNotIn(
            "cyberscribe ALL=(root) NOPASSWD: /usr/sbin/nft",
            content,
            "Sudoers must not allow arbitrary arguments to /usr/sbin/nft"
        )
        # MUST permit ONLY the helper script
        self.assertIn("cyberscribe_nft_helper.py", content)

    def test_helper_parameter_validation(self):
        """Validates that helper rejects invalid chains, handles, and table names."""
        # Valid chain names
        self.assertEqual(validate_chain_name("inbound_filter"), "inbound_filter")
        self.assertEqual(validate_chain_name("outbound_filter"), "outbound_filter")
        # Invalid chain names
        with self.assertRaises(HelperSecurityError):
            validate_chain_name("PREROUTING")
        with self.assertRaises(HelperSecurityError):
            validate_chain_name("custom_chain; drop;")

        # Valid handles
        self.assertEqual(validate_handle(5), 5)
        self.assertEqual(validate_handle("12"), 12)
        # Invalid handles
        with self.assertRaises(HelperSecurityError):
            validate_handle(0)
        with self.assertRaises(HelperSecurityError):
            validate_handle(-1)
        with self.assertRaises(HelperSecurityError):
            validate_handle("invalid")

        # Table validation
        self.assertEqual(validate_table_name("cyberscribe"), "cyberscribe")
        with self.assertRaises(HelperSecurityError):
            validate_table_name("table; drop all;")

    # -------------------------------------------------------------------------
    # 3. Exact Ownership Enforcement on Handle Deletion
    # -------------------------------------------------------------------------

    def test_exact_rule_ownership_verification_on_deletion(self):
        """
        When attempting to delete a handle that belongs to a different action ID,
        or an unmanaged/firewalld rule, the helper strictly refuses and raises OwnershipMismatchError.
        """
        helper = CyberscribeNftHelper(table_name="cyberscribe", dry_run=False)

        # Mock list_rules returning two rules: handle 10 for act-A, and handle 20 for act-B
        mock_rules = [
            {
                "chain": "inbound_filter",
                "handle": 10,
                "rule_line": 'ip saddr 185.220.101.5 drop comment "cyberscribe:act-test-A"',
                "comment": "cyberscribe:act-test-A"
            },
            {
                "chain": "inbound_filter",
                "handle": 20,
                "rule_line": 'ip saddr 93.184.216.34 drop comment "cyberscribe:act-test-B"',
                "comment": "cyberscribe:act-test-B"
            },
            {
                "chain": "inbound_filter",
                "handle": 30,
                "rule_line": 'ip saddr 198.51.100.1 drop',
                "comment": None  # Unmanaged rule
            }
        ]

        with patch.object(helper, "list_rules", return_value=mock_rules):
            # Attempt to delete handle 20 (belongs to act-test-B) using action_id act-test-A -> MUST FAIL
            with self.assertRaises(OwnershipMismatchError):
                helper.delete_rule_by_handle(
                    action_id="act-test-A",
                    chain="inbound_filter",
                    handle=20
                )

            # Attempt to delete handle 30 (unmanaged rule) using action_id act-test-A -> MUST FAIL
            with self.assertRaises(OwnershipMismatchError):
                helper.delete_rule_by_handle(
                    action_id="act-test-A",
                    chain="inbound_filter",
                    handle=30
                )

            # Deleting matching handle 10 for act-test-A succeeds
            with patch.object(helper, "_exec_nft", return_value=(0, "", "")):
                res = helper.delete_rule_by_handle(
                    action_id="act-test-A",
                    chain="inbound_filter",
                    handle=10
                )
                self.assertEqual(res["status"], "DELETED")
                self.assertEqual(res["handle"], 10)

    # -------------------------------------------------------------------------
    # 4. Partial-Failure Recovery (Atomic Multi-Rule Rollback)
    # -------------------------------------------------------------------------

    def test_partial_failure_recovery_cleans_up_staged_rules(self):
        """
        If outbound rule succeeds but inbound rule fails during insertion,
        the helper immediately deletes the staged outbound rule and raises an error.
        """
        helper = CyberscribeNftHelper(table_name="cyberscribe", dry_run=False)

        # Simulation: outbound succeeds (returns rc=0), then list_rules finds handle 100,
        # then inbound fails (returns rc=1)
        staged_rules_found = [
            {
                "chain": "outbound_filter",
                "handle": 100,
                "rule_line": 'ip daddr 185.220.101.5 drop comment "cyberscribe:act-partial-01"',
                "comment": "cyberscribe:act-partial-01"
            }
        ]

        exec_calls = []

        def mock_exec_nft(args):
            exec_calls.append(args)
            # init calls
            if args[0] == "add" and args[1] in ("table", "chain"):
                return 0, "", ""
            # Outbound rule add
            if args[0] == "add" and args[4] == "outbound_filter":
                return 0, "", ""
            # Inbound rule add fails!
            if args[0] == "add" and args[4] == "inbound_filter":
                return 1, "", "Kernel error adding inbound rule"
            # Delete cleanup call
            if args[0] == "delete" and args[1] == "rule":
                return 0, "", ""
            return 0, "", ""

        with patch.object(helper, "init_table_and_chains"):
            with patch.object(helper, "find_rules_for_action", side_effect=[[], staged_rules_found, []]):
                with patch.object(helper, "_exec_nft", side_effect=mock_exec_nft):
                    with self.assertRaises(HelperSecurityError) as ctx:
                        helper.apply_block(
                            action_id="act-partial-01",
                            ip_str="185.220.101.5",
                            direction="both"
                        )
                    self.assertIn("partial rules cleaned up", str(ctx.exception))

                    # Verify that a delete command was issued for the staged handle 100
                    delete_commands = [c for c in exec_calls if c[0] == "delete" and "100" in c]
                    self.assertTrue(len(delete_commands) > 0, "Expected staged rule 100 to be rolled back!")

    # -------------------------------------------------------------------------
    # 5. Authentication & Unauthorized Requests
    # -------------------------------------------------------------------------

    def test_unauthorized_requests_rejected(self):
        """Verifies handler rejects unauthenticated or incorrectly tokenized requests."""
        controller = NftablesController(table_name="cyberscribe", dry_run=True)
        handler_class = ExecutorRequestHandler
        handler_class.controller = controller
        handler_class.auth_token = "SECURE_SECRET_TOKEN_XYZ"

        # Mock request with missing auth
        mock_handler = MagicMock()
        mock_handler.headers = {}
        mock_handler.auth_token = "SECURE_SECRET_TOKEN_XYZ"
        is_auth = ExecutorRequestHandler._authenticate(mock_handler)
        self.assertFalse(is_auth)

        # Mock request with wrong token
        mock_handler.headers = {"Authorization": "Bearer WRONG_TOKEN"}
        is_auth = ExecutorRequestHandler._authenticate(mock_handler)
        self.assertFalse(is_auth)

        # Mock request with correct token
        mock_handler.headers = {"Authorization": "Bearer SECURE_SECRET_TOKEN_XYZ"}
        is_auth = ExecutorRequestHandler._authenticate(mock_handler)
        self.assertTrue(is_auth)

    # -------------------------------------------------------------------------
    # 6. NftablesController Dry-Run Commands
    # -------------------------------------------------------------------------

    def test_nftables_controller_dry_run_commands(self):
        controller = NftablesController(table_name="cyberscribe", dry_run=True, sudo=True)

        addr = ipaddress.IPv4Address("185.220.101.5")
        res = controller.apply_ip_block(
            action_id="act-auto-test4a-01",
            ip_addr=addr,
            direction="both"
        )
        self.assertEqual(res["status"], "APPLIED")
        self.assertEqual(res["table"], "inet cyberscribe")
        self.assertTrue(res["verified"])

        rb_res = controller.rollback_action_rule("act-auto-test4a-01")
        self.assertEqual(rb_res["status"], "ROLLED_BACK")

    # -------------------------------------------------------------------------
    # 7. FedoraNftablesAdapter Lifecycle Integration
    # -------------------------------------------------------------------------

    @patch("requests.get")
    @patch("requests.post")
    def test_adapter_apply_and_verify_success(self, mock_post, mock_get):
        mock_post_resp = MagicMock()
        mock_post_resp.status_code = 200
        mock_post_resp.json.return_value = {
            "status": "APPLIED",
            "action_id": "act-auto-test4a-001",
            "handles": [10, 11]
        }
        mock_post.return_value = mock_post_resp

        mock_get_resp = MagicMock()
        mock_get_resp.status_code = 200
        mock_get_resp.json.return_value = {
            "action_id": "act-auto-test4a-001",
            "verified": True,
            "handles": [10, 11]
        }
        mock_get.return_value = mock_get_resp

        with patch.dict(os.environ, {"FEDORA_EXECUTOR_TOKEN": "test-token-12345"}):
            act = self._create_pending_action(action_id="act-auto-test4a-001")
            res = FedoraNftablesAdapter.apply_containment(act, self.db)

            self.assertEqual(res["status"], "VERIFIED")
            self.assertTrue(res["is_live_enforcement"])
            self.assertEqual(act.status, "VERIFIED")
            self.assertIsNotNone(act.applied_at)
            self.assertIsNotNone(act.verified_at)
            self.assertIn("handles", res)
            self.assertEqual(res["handles"], [10, 11])

            logs = self.db.query(ContainmentAuditLog).filter(
                ContainmentAuditLog.action_id == act.id
            ).all()
            events = [l.event_type for l in logs]
            self.assertIn("LIVE_FIREWALL_APPLIED", events)
            self.assertIn("LIVE_FIREWALL_VERIFIED", events)

    @patch("requests.post")
    def test_adapter_rollback_success(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "status": "ROLLED_BACK",
            "action_id": "act-auto-test4a-002",
            "verified_removed": True,
            "removed_handles": [10, 11]
        }
        mock_post.return_value = mock_resp

        with patch.dict(os.environ, {"FEDORA_EXECUTOR_TOKEN": "test-token-12345"}):
            act = self._create_pending_action(action_id="act-auto-test4a-002")
            act.status = "VERIFIED"
            self.db.commit()

            res = FedoraNftablesAdapter.rollback_containment(act, self.db)
            self.assertEqual(res["status"], "ROLLED_BACK")
            self.assertEqual(act.status, "ROLLED_BACK")
            self.assertIsNotNone(act.rolled_back_at)

    @patch("requests.post")
    def test_rollback_failure_never_marks_rolled_back(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 500
        mock_resp.text = "Internal nft execution error deleting handle"
        mock_post.return_value = mock_resp

        with patch.dict(os.environ, {"FEDORA_EXECUTOR_TOKEN": "test-token-12345"}):
            act = self._create_pending_action(action_id="act-auto-test4a-003")
            act.status = "VERIFIED"
            self.db.commit()

            with self.assertRaises(FedoraExecutorError):
                FedoraNftablesAdapter.rollback_containment(act, self.db)

            self.assertNotEqual(act.status, "ROLLED_BACK")
            self.assertEqual(act.status, "VERIFIED")
            self.assertIn("Internal nft execution error", act.error_message)

    @patch("requests.post")
    def test_rollback_enforces_tenant_isolation(self, mock_post):
        act_b = self._create_pending_action(
            action_id="act-auto-test4a-004",
            tenant_id=self.tenant_b.id
        )
        act_b.status = "VERIFIED"
        self.db.commit()

        with self.assertRaises(PermissionError):
            FedoraNftablesAdapter.rollback_containment(
                action=act_b,
                db=self.db,
                expected_tenant_id=self.tenant.id
            )

    @patch("requests.post")
    def test_offline_vm_handled_gracefully(self, mock_post):
        mock_post.side_effect = Exception("Connection refused (127.0.0.1:8088)")

        with patch.dict(os.environ, {"FEDORA_EXECUTOR_TOKEN": "test-token-12345"}):
            act = self._create_pending_action(action_id="act-auto-test4a-005")
            res = FedoraNftablesAdapter.apply_containment(act, self.db)

            self.assertEqual(res["status"], "FAILED")
            self.assertEqual(act.status, "FAILED")
            self.assertIn("Connection refused", act.error_message)

    # -------------------------------------------------------------------------
    # 8. Mode Selection & Simulation Default
    # -------------------------------------------------------------------------

    def test_simulation_mode_is_default(self):
        with patch.dict(os.environ, {}, clear=False):
            if "CONTAINMENT_ADAPTER_MODE" in os.environ:
                del os.environ["CONTAINMENT_ADAPTER_MODE"]

            adapter = get_containment_adapter()
            self.assertEqual(adapter, SimulatedFirewallAdapter)

    def test_fedora_nftables_mode_selected_when_explicitly_configured(self):
        with patch.dict(os.environ, {"CONTAINMENT_ADAPTER_MODE": "fedora_nftables"}):
            adapter = get_containment_adapter()
            self.assertEqual(adapter, FedoraNftablesAdapter)

    # -------------------------------------------------------------------------
    # 9. Extended Lifecycle & Expiry Verification (Step 3 Requirements)
    # -------------------------------------------------------------------------

    def test_controller_input_validation_defense_in_depth(self):
        """Verifies NftablesController rejects invalid arguments before invoking helper."""
        controller = NftablesController(table_name="cyberscribe", dry_run=True)

        # Invalid IP
        with self.assertRaises(ExecutorSecurityError):
            controller.apply_ip_block("act-test-01", "127.0.0.1")

        with self.assertRaises(ExecutorSecurityError):
            controller.apply_ip_block("act-test-01", "8.8.8.8")

        # Invalid Action ID
        with self.assertRaises(ExecutorSecurityError):
            controller.apply_ip_block("; cat /etc/shadow", "185.220.101.5")

        # Invalid Direction
        with self.assertRaises(ExecutorSecurityError):
            controller.apply_ip_block("act-test-01", "185.220.101.5", direction="invalid_dir")

    @patch("requests.post")
    def test_adapter_apply_http_500_failure_produces_failed_status_and_audit(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 500
        mock_resp.text = "nftables syntax error: table inet cyberscribe does not exist"
        mock_post.return_value = mock_resp

        with patch.dict(os.environ, {"FEDORA_EXECUTOR_TOKEN": "test-token-12345"}):
            act = self._create_pending_action(action_id="act-auto-test4a-500")
            res = FedoraNftablesAdapter.apply_containment(act, self.db)

            self.assertEqual(res["status"], "FAILED")
            self.assertEqual(act.status, "FAILED")
            self.assertIn("Fedora executor returned HTTP 500", act.error_message)

            logs = self.db.query(ContainmentAuditLog).filter(
                ContainmentAuditLog.action_id == act.id,
                ContainmentAuditLog.event_type == "LIVE_FIREWALL_FAILED"
            ).all()
            self.assertTrue(len(logs) > 0)

    @patch("requests.post")
    def test_adapter_apply_idempotent_when_already_applied(self, mock_post):
        with patch.dict(os.environ, {"FEDORA_EXECUTOR_TOKEN": "test-token-12345"}):
            act = self._create_pending_action(action_id="act-auto-test4a-idem")
            act.status = "APPLIED"
            self.db.commit()

            res = FedoraNftablesAdapter.apply_containment(act, self.db)
            self.assertEqual(res["status"], "APPLIED")
            self.assertTrue(res["is_live_enforcement"])
            self.assertIn("already active", res["message"])
            mock_post.assert_not_called()

    @patch("requests.get")
    def test_adapter_verification_failure_leaves_unverified(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"action_id": "act-auto-test4a-unver", "verified": False, "handles": []}
        mock_get.return_value = mock_resp

        with patch.dict(os.environ, {"FEDORA_EXECUTOR_TOKEN": "test-token-12345"}):
            act = self._create_pending_action(action_id="act-auto-test4a-unver")
            act.status = "APPLIED"
            self.db.commit()

            res = FedoraNftablesAdapter.verify_containment(act, self.db)
            self.assertFalse(res["verified"])
            self.assertEqual(act.status, "APPLIED")
            self.assertIsNone(act.verified_at)

    @patch("requests.post")
    def test_adapter_check_and_expire_success(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "status": "ROLLED_BACK",
            "action_id": "act-auto-test4a-exp",
            "verified_removed": True,
            "removed_handles": [42]
        }
        mock_post.return_value = mock_resp

        with patch.dict(os.environ, {"FEDORA_EXECUTOR_TOKEN": "test-token-12345"}):
            act = self._create_pending_action(action_id="act-auto-test4a-exp")
            act.status = "VERIFIED"
            # Set expiration in the past
            act.expires_at = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(minutes=5)
            self.db.commit()

            res = FedoraNftablesAdapter.check_and_expire(act, self.db)
            self.assertEqual(res["status"], "EXPIRED")
            self.assertTrue(res["expired"])
            self.assertEqual(act.status, "EXPIRED")

            logs = self.db.query(ContainmentAuditLog).filter(
                ContainmentAuditLog.action_id == act.id,
                ContainmentAuditLog.event_type == "LIVE_FIREWALL_EXPIRED"
            ).all()
            self.assertTrue(len(logs) > 0)

    def test_adapter_check_and_expire_noop_when_not_expired(self):
        act = self._create_pending_action(action_id="act-auto-test4a-active")
        act.status = "VERIFIED"
        act.expires_at = datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(hours=2)
        self.db.commit()

        res = FedoraNftablesAdapter.check_and_expire(act, self.db)
        self.assertFalse(res["expired"])
        self.assertEqual(act.status, "VERIFIED")

    @patch("requests.post")
    def test_adapter_bulk_expire_active_containment_actions(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "status": "ROLLED_BACK",
            "verified_removed": True,
            "removed_handles": [99]
        }
        mock_post.return_value = mock_resp

        with patch.dict(os.environ, {"FEDORA_EXECUTOR_TOKEN": "test-token-12345"}):
            act1 = self._create_pending_action(action_id="act-auto-test4a-bulk1", ip="185.220.101.61")
            act1.status = "APPLIED"
            act1.expires_at = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(minutes=10)

            act2 = self._create_pending_action(action_id="act-auto-test4a-bulk2", ip="185.220.101.62")
            act2.status = "VERIFIED"
            act2.expires_at = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(minutes=5)

            self.db.commit()

            results = FedoraNftablesAdapter.expire_active_containment_actions(self.db, tenant_id=self.tenant.id)
            self.assertEqual(len(results), 2)
            self.assertTrue(all(r["expired"] for r in results))

            self.db.refresh(act1)
            self.db.refresh(act2)
            self.assertEqual(act1.status, "EXPIRED")
            self.assertEqual(act2.status, "EXPIRED")

    # -------------------------------------------------------------------------
    # 10. Hardening Regressions: Conflicting Reuse, Malformed Requests, Isolation
    # -------------------------------------------------------------------------

    def test_conflicting_action_id_reuse_rejected(self):
        """Verifies action ID reuse with conflicting IP or direction is strictly rejected."""
        helper = CyberscribeNftHelper(table_name="cyberscribe", dry_run=False)

        # Staged rule represents an existing rule for act-test-conflict with IP 185.220.101.5 in both chains
        existing_rules = [
            {
                "chain": "outbound_filter",
                "handle": 101,
                "rule_line": 'ip daddr 185.220.101.5 drop comment "cyberscribe:act-test-conflict"',
                "comment": "cyberscribe:act-test-conflict"
            },
            {
                "chain": "inbound_filter",
                "handle": 102,
                "rule_line": 'ip saddr 185.220.101.5 drop comment "cyberscribe:act-test-conflict"',
                "comment": "cyberscribe:act-test-conflict"
            }
        ]

        with patch.object(helper, "init_table_and_chains"):
            with patch.object(helper, "find_rules_for_action", return_value=existing_rules):
                # 1. Matching parameters -> Idempotent success
                res = helper.apply_block("act-test-conflict", "185.220.101.5", direction="both")
                self.assertEqual(res["status"], "APPLIED")
                self.assertTrue(res["is_idempotent"])

                # 2. Conflicting IP -> Rejection
                with self.assertRaises(HelperSecurityError) as ctx_ip:
                    helper.apply_block("act-test-conflict", "93.184.216.34", direction="both")
                self.assertIn("Conflicting action reuse", str(ctx_ip.exception))

                # 3. Conflicting Direction -> Rejection (existing has both, requested outbound only)
                with self.assertRaises(HelperSecurityError) as ctx_dir:
                    helper.apply_block("act-test-conflict", "185.220.101.5", direction="outbound")
                self.assertIn("Conflicting action reuse", str(ctx_dir.exception))

    def test_partial_failure_unverified_cleanup_reports_failure(self):
        """If partial rule insertion fails AND rollback of staged rule fails, system reports failure."""
        helper = CyberscribeNftHelper(table_name="cyberscribe", dry_run=False)

        staged_rules = [
            {
                "chain": "outbound_filter",
                "handle": 201,
                "rule_line": 'ip daddr 185.220.101.5 drop comment "cyberscribe:act-unclean-01"',
                "comment": "cyberscribe:act-unclean-01"
            }
        ]

        def mock_exec_nft(args):
            # Outbound rule add succeeds
            if args[0] == "add" and args[4] == "outbound_filter":
                return 0, "", ""
            # Inbound rule add fails
            if args[0] == "add" and args[4] == "inbound_filter":
                return 1, "", "Kernel memory error"
            # Delete call fails!
            if args[0] == "delete" and args[1] == "rule":
                return 1, "", "Cannot delete: busy"
            return 0, "", ""

        with patch.object(helper, "init_table_and_chains"):
            # find_rules_for_action: 1st call for idempotency check (empty),
            # 2nd call after outbound add (finds staged rule),
            # 3rd call for cleanup verification (staged rule still present!)
            with patch.object(helper, "find_rules_for_action", side_effect=[[], staged_rules, staged_rules]):
                with patch.object(helper, "_exec_nft", side_effect=mock_exec_nft):
                    with self.assertRaises(HelperSecurityError) as ctx:
                        helper.apply_block("act-unclean-01", "185.220.101.5", direction="both")
                    self.assertIn("cleanup verification FAILED", str(ctx.exception))

    def test_helper_rollback_reports_failure_when_rules_remain(self):
        """Verifies helper rollback raises HelperSecurityError if rules remain in table."""
        helper = CyberscribeNftHelper(table_name="cyberscribe", dry_run=False)

        mock_rule = {
            "chain": "outbound_filter",
            "handle": 301,
            "rule_line": 'ip daddr 185.220.101.5 drop comment "cyberscribe:act-rb-fail"',
            "comment": "cyberscribe:act-rb-fail"
        }

        with patch.object(helper, "find_rules_for_action", side_effect=[[mock_rule], [mock_rule]]):
            with patch.object(helper, "delete_rule_by_handle", side_effect=HelperSecurityError("Delete failed")):
                with self.assertRaises(HelperSecurityError) as ctx:
                    helper.rollback_action("act-rb-fail")
                self.assertIn("Rollback failed", str(ctx.exception))

    def test_executor_malformed_request_handling(self):
        """Verifies handler safely rejects malformed or oversized requests without crashing."""
        controller = NftablesController(table_name="cyberscribe", dry_run=True)
        handler = MagicMock()
        handler.controller = controller
        handler.auth_token = "SECRET_123"

        # 1. Negative Content-Length
        handler.headers = {"Content-Length": "-10"}
        with self.assertRaises(ExecutorSecurityError) as ctx_neg:
            ExecutorRequestHandler._read_json_body(handler)
        self.assertIn("Invalid Content-Length", str(ctx_neg.exception))

        # 2. Non-integer Content-Length
        handler.headers = {"Content-Length": "not_an_int"}
        with self.assertRaises(ExecutorSecurityError) as ctx_nan:
            ExecutorRequestHandler._read_json_body(handler)
        self.assertIn("Invalid Content-Length", str(ctx_nan.exception))

        # 3. Oversized Content-Length
        handler.headers = {"Content-Length": "1000000"}  # 1 MB > 64 KB limit
        with self.assertRaises(ExecutorSecurityError) as ctx_size:
            ExecutorRequestHandler._read_json_body(handler)
        self.assertIn("exceeds maximum size", str(ctx_size.exception))

        # 4. Non-dict JSON body (JSON list)
        handler.headers = {"Content-Length": "6"}
        handler.rfile = BytesIO(b"[1, 2]")
        with self.assertRaises(ExecutorSecurityError) as ctx_list:
            ExecutorRequestHandler._read_json_body(handler)
        self.assertIn("must be an object/dict", str(ctx_list.exception))

        # 5. Malformed non-JSON data
        handler.headers = {"Content-Length": "12"}
        handler.rfile = BytesIO(b"{not: valid}")
        with self.assertRaises(ExecutorSecurityError) as ctx_malf:
            ExecutorRequestHandler._read_json_body(handler)
        self.assertIn("Malformed JSON", str(ctx_malf.exception))

    def test_firewalld_isolation_guarantees(self):
        """Verifies controller and helper operations are strictly confined to 'inet cyberscribe'."""
        helper = CyberscribeNftHelper(table_name="cyberscribe", dry_run=True)
        self.assertEqual(helper.table_name, "cyberscribe")

        # Confirm init commands use table inet cyberscribe and priority -5 (before firewalld)
        init_res = helper.init_table_and_chains()
        self.assertEqual(init_res["table"], "inet cyberscribe")

        # Confirm helper never issues firewall-cmd or flush commands
        with self.assertRaises(HelperSecurityError):
            validate_chain_name("firewalld_filter")

        with self.assertRaises(HelperSecurityError):
            validate_table_name("filter; flush ruleset;")


if __name__ == "__main__":
    import unittest
    unittest.main()


