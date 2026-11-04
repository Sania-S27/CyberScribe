"""
Readiness, Adapter Selection, and Truthful Lifecycle Verification Test Suite
----------------------------------------------------------------------------
Validates:
1. Readiness endpoint (/health, /health/readiness, /admin/readiness):
   - Returns simulation_ready=True by default.
   - Accurately reports live_executor_ready and live_patch_ready.
   - Redacts any tokens or secrets from response bodies.
   - Enforces RBAC on /admin/readiness.
2. Adapter selection:
   - Defaults to SimulatedFirewallAdapter in simulation mode.
   - Resolves FedoraNftablesAdapter when configured or when tenant has Linux/Fedora stack.
   - Resolves WindowsFirewallAdapter when configured or when tenant has Windows stack.
   - Never confuses Fedora nftables with Windows firewall.
3. Package Already Fixed:
   - Accurately reports ALREADY_FIXED when installed_version >= candidate_version.
   - Skips redundant patch proposal and update execution.
4. Truthful failure handling:
   - When executor is unreachable or returns error, containment is recorded as FAILED.
   - Never reports a false positive or marks VERIFIED without successful independent read-back.
5. Live containment verification against Fedora VM (if reachable):
   - Probes live Fedora executor health.
   - Applies an authorized test block for a reserved test IP.
   - Independently reads back rule existence from inet cyberscribe table.
   - Rolls back the rule by exact action ID and verifies absence.
"""

import os
import sys
import uuid
import unittest
from unittest.mock import patch, MagicMock
import requests
from fastapi.testclient import TestClient

# Preserve real underlying requests.post before any fixtures or test cases mock it
REAL_REQUESTS_POST = requests.post

backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from tests.base import BaseTestCase
from main import app
from app import models
from app.services.readiness_service import ReadinessService
from app.services.firewall_adapter import (
    SimulatedFirewallAdapter,
    get_containment_adapter,
    get_adapter_for_action
)
from app.services.fedora_nftables_adapter import FedoraNftablesAdapter
from app.services.windows_firewall_adapter import WindowsFirewallAdapter
from app.services.fixed_version_service import FixedVersionDiscoveryService
from app.services.autonomous_response_orchestrator import AutonomousResponseOrchestrator
from app.services.patch_adapter import PatchManagementAdapter


class TestReadinessAndLifecycleVerification(BaseTestCase):

    def setUp(self):
        super().setUp()
        self.client = TestClient(app)

    # =========================================================================
    # 1. Readiness Service & Endpoints
    # =========================================================================

    def test_01_readiness_service_distinguishes_simulation_and_live(self):
        """Readiness accurately distinguishes simulation readiness from live executor readiness."""
        with patch.dict(os.environ, {"CONTAINMENT_ADAPTER_MODE": "simulated", "PATCH_ADAPTER_MODE": "simulated"}):
            readiness = ReadinessService.get_system_readiness(db=self.db)
            self.assertEqual(readiness["status"], "READY")
            self.assertTrue(readiness["overall_ready"])
            self.assertTrue(readiness["database"]["connected"])

            # Containment simulation is ready by default
            containment = readiness["containment"]
            self.assertTrue(containment["simulation_ready"])
            self.assertFalse(containment["live_enforcement_active"])
            self.assertEqual(containment["configured_mode"], "simulated")

            # Remediation simulation is ready by default
            remediation = readiness["remediation"]
            self.assertTrue(remediation["simulation_ready"])
            self.assertFalse(remediation["live_execution_active"])
            self.assertEqual(remediation["configured_mode"], "simulated")

    def test_02_public_health_and_readiness_endpoints(self):
        """Root /health and /health/readiness endpoints respond correctly."""
        res_h = self.client.get("/health")
        self.assertEqual(res_h.status_code, 200)
        self.assertEqual(res_h.json()["status"], "HEALTHY")

        res_r = self.client.get("/health/readiness")
        self.assertEqual(res_r.status_code, 200)
        data = res_r.json()
        self.assertIn("status", data)
        self.assertIn("containment", data)
        self.assertIn("remediation", data)
        self.assertIn("database", data)

    def test_03_admin_readiness_requires_super_admin(self):
        """GET /admin/readiness requires super_admin authentication."""
        # Unauthenticated request fails with 401
        res_no_auth = self.client.get("/admin/readiness")
        self.assertEqual(res_no_auth.status_code, 401)

        # Company user token fails with 403
        company_headers = {"Authorization": f"Bearer {self.user_token}"}
        res_forbidden = self.client.get("/admin/readiness", headers=company_headers)
        self.assertEqual(res_forbidden.status_code, 403)

        # Super admin token succeeds with 200
        admin_headers = {"Authorization": f"Bearer {self.admin_token}"}
        res_ok = self.client.get("/admin/readiness", headers=admin_headers)
        self.assertEqual(res_ok.status_code, 200)
        self.assertTrue(res_ok.json()["overall_ready"])

    def test_04_readiness_redacts_secrets(self):
        """Readiness output never exposes raw bearer tokens, passwords, or secret keys."""
        with patch.dict(os.environ, {
            "FEDORA_EXECUTOR_TOKEN": "SUPER_SECRET_TOKEN_DO_NOT_LEAK",
            "SMTP_PASSWORD": "SUPER_SECRET_SMTP_PASSWORD"
        }):
            readiness = ReadinessService.get_system_readiness(db=self.db)
            readiness_str = str(readiness)
            self.assertNotIn("SUPER_SECRET_TOKEN_DO_NOT_LEAK", readiness_str)
            self.assertNotIn("SUPER_SECRET_SMTP_PASSWORD", readiness_str)
            # Only reports boolean configuration status
            self.assertTrue(readiness["containment"]["fedora_executor"]["token_configured"])

    # =========================================================================
    # 2. Adapter Selection Accuracy
    # =========================================================================

    def test_05_adapter_selection_does_not_confuse_fedora_and_windows(self):
        """Validates adapter selection strictly separates Fedora nftables and Windows Defender."""
        # Fedora action resolution by ID and table
        fed_action = models.ContainmentAction(
            id=str(uuid.uuid4()),
            action_id="act-fed-test-101",
            tenant_id=self.tenant.id,
            indicator_value="185.220.101.5",
            indicator_type="ipv4",
            action_type="BLOCK_IPV4_DESTINATION",
            policy_decision="QUALIFIED",
            status="PENDING",
            rule_spec={"adapter": "FEDORA_NFTABLES", "table": "inet cyberscribe"}
        )
        self.assertEqual(get_adapter_for_action(fed_action), FedoraNftablesAdapter)

        # Windows action resolution by ID and port 8000
        win_action = models.ContainmentAction(
            id=str(uuid.uuid4()),
            action_id="act-win-test-202",
            tenant_id=self.tenant.id,
            indicator_value="93.184.216.34",
            indicator_type="ipv4",
            action_type="BLOCK_INBOUND_PORT_8000",
            policy_decision="QUALIFIED",
            status="PENDING",
            rule_spec={"adapter": "WINDOWS_DEFENDER_FIREWALL"}
        )
        self.assertEqual(get_adapter_for_action(win_action), WindowsFirewallAdapter)

        # Default configured adapter mode
        with patch.dict(os.environ, {"CONTAINMENT_ADAPTER_MODE": "simulated"}):
            self.assertEqual(get_containment_adapter(), SimulatedFirewallAdapter)

        with patch.dict(os.environ, {"CONTAINMENT_ADAPTER_MODE": "fedora_nftables"}):
            self.assertEqual(get_containment_adapter(), FedoraNftablesAdapter)

        with patch.dict(os.environ, {"CONTAINMENT_ADAPTER_MODE": "windows_firewall"}):
            self.assertEqual(get_containment_adapter(), WindowsFirewallAdapter)

    # =========================================================================
    # 3. Package Already Fixed Verification
    # =========================================================================

    def test_06_package_already_fixed_avoids_unnecessary_update(self):
        """When an installed package already satisfies or exceeds fixed version, reports ALREADY_FIXED without running update."""
        report = models.ThreatReport(
            id=str(uuid.uuid4()),
            cve_id="CVE-2026-TEST-FIXED",
            title="Uvicorn Buffer Flaw",
            summary="Uvicorn before 0.38.1 is vulnerable. Fixed in 0.38.1.",
            severity="high"
        )
        self.db.add(report)
        self.db.commit()

        # Scenario A: Installed version is exactly 0.38.1 (already at fixed version)
        res_exact = FixedVersionDiscoveryService.discover_and_verify_fix(
            package_name="uvicorn",
            current_version="0.38.1",
            threat_report=report
        )
        self.assertEqual(res_exact["status"], "ALREADY_FIXED")
        self.assertTrue(res_exact["already_fixed"])
        self.assertTrue(res_exact["live_execution_blocked"])
        self.assertIn("already satisfies", res_exact["message"])

        # Scenario B: Installed version is 0.39.0 (exceeds fixed version)
        res_higher = FixedVersionDiscoveryService.discover_and_verify_fix(
            package_name="uvicorn",
            current_version="0.39.0",
            threat_report=report
        )
        self.assertEqual(res_higher["status"], "ALREADY_FIXED")
        self.assertTrue(res_higher["already_fixed"])

    # =========================================================================
    # 4. Truthful Failure on Live Executor Downtime
    # =========================================================================

    def test_07_truthful_failure_when_fedora_executor_unreachable(self):
        """When Fedora executor is down, containment application reports FAILED and never claims success."""
        action = models.ContainmentAction(
            id=str(uuid.uuid4()),
            action_id="act-fed-fail-test",
            tenant_id=self.tenant.id,
            indicator_value="185.220.101.5",
            indicator_type="ipv4",
            action_type="BLOCK_IPV4_DESTINATION",
            policy_decision="QUALIFIED",
            policy_rule="TEST_FAILURE",
            status="PENDING",
            ttl_seconds=3600
        )
        self.db.add(action)
        self.db.commit()

        # Point executor URL to an unreachable port
        with patch.dict(os.environ, {
            "FEDORA_EXECUTOR_URL": "http://127.0.0.1:59999",
            "FEDORA_EXECUTOR_TOKEN": "TEST_TOKEN_FOR_DOWN_PORT"
        }):
            with patch("requests.post", side_effect=requests.exceptions.ConnectionError("Connection refused on port 59999")):
                res = FedoraNftablesAdapter.apply_containment(action, self.db, is_simulated=False)
                self.assertEqual(res["status"], "FAILED")
                self.assertIn("Network communication failure", res["error"])

            # Verify truthful DB status
            self.db.refresh(action)
            self.assertEqual(action.status, "FAILED")
            self.assertIsNotNone(action.error_message)

            # Audit log must record failure honestly
            audit = self.db.query(models.ContainmentAuditLog).filter(
                models.ContainmentAuditLog.action_id == action.id,
                models.ContainmentAuditLog.event_type == "LIVE_FIREWALL_FAILED"
            ).first()
            self.assertIsNotNone(audit, "Must log LIVE_FIREWALL_FAILED audit record")

    # =========================================================================
    # 5. Live Fedora VM Execution Verification
    # =========================================================================

    def test_08_live_fedora_vm_containment_lifecycle(self):
        """
        When Fedora VM executor is reachable, exercises real apply, independent read-back,
        and exact rollback on the live kernel nftables table 'inet cyberscribe'.
        """
        probe = FedoraNftablesAdapter.health_check()
        if probe.get("status") != "HEALTHY":
            self.skipTest(f"Fedora 44 VM executor is not running or unreachable ({probe.get('error', 'unknown')}).")

        # Create live test action for public test IP
        test_ip = "185.220.101.5"
        action = models.ContainmentAction(
            id=str(uuid.uuid4()),
            action_id=f"act-fed-live-{uuid.uuid4().hex[:8]}",
            tenant_id=self.tenant.id,
            indicator_value=test_ip,
            indicator_type="ipv4",
            action_type="BLOCK_IPV4_DESTINATION",
            policy_decision="QUALIFIED",
            policy_rule="LIVE_VM_TEST",
            status="PENDING",
            ttl_seconds=300
        )
        self.db.add(action)
        self.db.commit()

        try:
            with patch("requests.post", side_effect=REAL_REQUESTS_POST):
                # 1. Apply live rule
                apply_res = FedoraNftablesAdapter.apply_containment(action, self.db, is_simulated=False)
                self.assertEqual(apply_res["status"], "VERIFIED")
                self.assertTrue(apply_res["is_live_enforcement"])
                self.assertFalse(apply_res["is_simulated"])
                self.assertTrue(len(apply_res["handles"]) > 0)
                self.assertEqual(apply_res["table"], "inet cyberscribe")

                # 2. Independent read-back query
                verify_res = FedoraNftablesAdapter.verify_containment(action, self.db)
                self.assertEqual(verify_res["status"], "VERIFIED")
                self.assertTrue(verify_res["verified"])
                self.assertEqual(verify_res["handles"], apply_res["handles"])

                # 3. Rollback
                rollback_res = FedoraNftablesAdapter.rollback_containment(action, self.db)
                self.assertEqual(rollback_res["status"], "ROLLED_BACK")
                self.assertEqual(rollback_res["removed_handles"], apply_res["handles"])

                # 4. Confirm rule is no longer verified after rollback
                action.status = "APPLIED"  # Attempting to verify after removal
                post_verify = FedoraNftablesAdapter.verify_containment(action, self.db)
                self.assertFalse(post_verify["verified"])

        finally:
            self.db.delete(action)
            self.db.commit()


if __name__ == "__main__":
    unittest.main()
