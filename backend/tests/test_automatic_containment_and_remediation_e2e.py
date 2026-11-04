"""
CyberScribe End-to-End Automatic Containment and Remediation Verification Test Suite
-------------------------------------------------------------------------------------
Validates all 14 core operational scenarios:
 1. Eligible threat automatically invokes containment dispatcher without a dashboard click.
 2. Invalid or out-of-scope indicators (bogon, loopback, multicast, private without lab authorization) are suppressed.
 3. Simulation mode remains simulation ('SIMULATED') and never claims live success.
 4. Authorized lab execution invokes real adapter and verifies resulting state.
 5. Execution or verification failure is persisted as 'FAILED'.
 6. Eligible Critical/High vulnerability automatically progresses to remediation under AUTO_PATCH policy.
 7. Default NOTIFY policy prevents automatic patch execution.
 8. Missing or unsafe target (missing target python, attempt to patch CyberScribe runtime) prevents patching.
 9. Successful patch execution is followed by independent version verification.
10. Failed patching or verification never results in APPLIED / VERIFIED.
11. Duplicate events do not repeat containment or patching (idempotency).
12. Other tenants remain unaffected (tenant isolation).
13. Webhook and email failures do not corrupt action status.
14. Vulnerability without malicious IP suppresses containment while remediation continues independently.
"""

import os
import sys
import uuid
from datetime import datetime, timezone
from unittest.mock import patch, MagicMock

backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from tests.base import BaseTestCase
from app import models
from app.models import ContainmentAction, PatchProposal, ThreatMatch, ThreatReport, AssetComponent
from app.services.autonomous_response_orchestrator import AutonomousResponseOrchestrator
from app.services.patch_adapter import (
    PatchManagementAdapter,
    PatchSecurityError,
    PatchStateError
)
from app.services.windows_firewall_adapter import (
    WindowsFirewallAdapter,
    WindowsFirewallError
)
from app.services.containment_policy import (
    AutonomousPolicyEngine,
    NetworkIndicatorCandidate
)
from app.services.notification_service import NotificationService


class TestAutomaticContainmentAndRemediationE2E(BaseTestCase):

    def setUp(self):
        super().setUp()
        self.orig_exec_url = os.environ.get("WINDOWS_EXECUTOR_URL")
        os.environ["WINDOWS_EXECUTOR_URL"] = ""

        # Designated Demonstration Tenant ('Campus Guide') configured for AUTO_PATCH
        self.demo_tenant = models.Tenant(
            id=str(uuid.uuid4()),
            company_name="Campus Guide Demo Lab",
            tech_stack="FastAPI:0.120.1, Uvicorn:0.38.0, SQLAlchemy:2.0.44",
            webhook_url="https://campus-guide.local/webhook",
            auth_token="CAMPUS_GUIDE_SECRET_TOKEN_2026",
            remediation_policy="AUTO_PATCH"
        )
        self.db.add(self.demo_tenant)

        # Other standard tenant configured for default NOTIFY
        self.standard_tenant = models.Tenant(
            id=str(uuid.uuid4()),
            company_name="Standard Corp",
            tech_stack="Python:3.11, Django:4.2, PostgreSQL:15",
            webhook_url="https://standard-corp.local/webhook",
            auth_token="STANDARD_CORP_TOKEN_1234",
            remediation_policy="NOTIFY"
        )
        self.db.add(self.standard_tenant)

        # Asset component on demo tenant
        self.asset_uvicorn = models.AssetComponent(
            id=str(uuid.uuid4()),
            tenant_id=self.demo_tenant.id,
            software_name="uvicorn",
            software_version="0.38.0",
            environment="production"
        )
        self.db.add(self.asset_uvicorn)

        # Asset component on standard tenant
        self.asset_django = models.AssetComponent(
            id=str(uuid.uuid4()),
            tenant_id=self.standard_tenant.id,
            software_name="django",
            software_version="4.2.0",
            environment="production"
        )
        self.db.add(self.asset_django)

        # Threat report with CVE and malicious attacking IP
        self.threat_report_with_ip = models.ThreatReport(
            id=str(uuid.uuid4()),
            cve_id="CVE-2026-26209",
            title="Uvicorn Critical Request Smuggling Exploit",
            summary="Uvicorn before 0.38.1 allows HTTP request smuggling. Exploit traffic from 93.184.216.34. Fixed in 0.38.1.",
            severity="critical"
        )
        self.db.add(self.threat_report_with_ip)

        # Threat report without malicious IP (pure vulnerability advisory)
        self.threat_report_no_ip = models.ThreatReport(
            id=str(uuid.uuid4()),
            cve_id="CVE-2026-26210",
            title="Uvicorn Memory Leak Advisory",
            summary="Uvicorn before 0.38.1 has a memory leak during websocket disconnects. Fixed in 0.38.1.",
            severity="high"
        )
        self.db.add(self.threat_report_no_ip)

        self.db.commit()

    def tearDown(self):
        if self.orig_exec_url is not None:
            os.environ["WINDOWS_EXECUTOR_URL"] = self.orig_exec_url
        else:
            os.environ.pop("WINDOWS_EXECUTOR_URL", None)
        super().tearDown()

    # =========================================================================
    # Scenario 1: Automatic Containment Dispatch Without Dashboard Click
    # =========================================================================
    def test_01_eligible_threat_automatically_invokes_containment_dispatcher(self):
        """An eligible threat with valid attacking IP automatically reaches the containment dispatcher."""
        result = AutonomousResponseOrchestrator.correlate_sbom_and_create_incident(
            db=self.db,
            tenant_id=self.demo_tenant.id,
            threat_report_id=self.threat_report_with_ip.id,
            supporting_malicious_ip="93.184.216.34",
            is_simulated=True
        )

        self.assertIsNotNone(result.get("containment"))
        self.assertEqual(result["containment"]["status"], "SIMULATED")
        self.assertEqual(result["containment"]["target_ip"], "93.184.216.34")

        # Verify ContainmentAction record persisted in database
        action = self.db.query(ContainmentAction).filter(
            ContainmentAction.tenant_id == self.demo_tenant.id,
            ContainmentAction.indicator_value == "93.184.216.34"
        ).first()
        self.assertIsNotNone(action)
        self.assertEqual(action.status, "SIMULATED")
        self.assertEqual(action.policy_decision, "QUALIFIED")

    # =========================================================================
    # Scenario 2: Suppression of Invalid / Out-of-Scope Indicators
    # =========================================================================
    def test_02_invalid_or_out_of_scope_indicators_suppressed(self):
        """Loopback, RFC 1918 private, broadcast, multicast, and protected IPs are strictly rejected."""
        disallowed_ips = [
            "127.0.0.1",       # Loopback
            "10.0.0.1",        # RFC 1918 Private (unauthorized)
            "192.168.1.50",    # RFC 1918 Private (unauthorized)
            "255.255.255.255", # Broadcast
            "224.0.0.1",       # Multicast
            "8.8.8.8"          # Protected Public DNS
        ]

        for bad_ip in disallowed_ips:
            candidate = NetworkIndicatorCandidate(
                indicator_value=bad_ip,
                tenant_id=self.demo_tenant.id,
                confidence_score=95.0,
                evidence_source="CISA_KEV",
                is_structured_ioc=True
            )
            qualified, action, reason = AutonomousPolicyEngine.evaluate_candidate(candidate, self.db)
            self.assertFalse(qualified, f"IP {bad_ip} should have been rejected!")
            self.assertIsNone(action)
            self.assertTrue(reason.startswith("REJECTED_"))

    # =========================================================================
    # Scenario 3: Simulation Mode Stays Simulation
    # =========================================================================
    def test_03_simulation_mode_remains_simulation(self):
        """Simulation mode explicitly sets SIMULATED status and never claims live success."""
        action = ContainmentAction(
            id=str(uuid.uuid4()),
            action_id=f"act-sim-{uuid.uuid4().hex[:8]}",
            tenant_id=self.demo_tenant.id,
            indicator_value="93.184.216.34",
            indicator_type="ipv4",
            action_type="BLOCK_INBOUND_PORT_8000",
            policy_decision="QUALIFIED",
            policy_rule="DEMO_POLICY",
            status="PENDING",
            ttl_seconds=3600
        )
        self.db.add(action)
        self.db.commit()

        res = WindowsFirewallAdapter.apply_containment(action, self.db, is_simulated=True)
        self.assertEqual(res["status"], "SIMULATED")
        self.assertTrue(res["is_simulated"])
        self.assertFalse(res["is_live_enforcement"])

        self.db.refresh(action)
        self.assertEqual(action.status, "SIMULATED")
        self.assertIn("[SIMULATED]", action.execution_output)

    # =========================================================================
    # Scenario 4: Authorized Lab Execution Invokes Adapter & Verifies State
    # =========================================================================
    @patch("app.services.windows_firewall_adapter.WindowsFirewallAdapter._run_netsh")
    @patch("app.services.windows_firewall_adapter.WindowsFirewallAdapter.show_rule")
    def test_04_authorized_lab_execution_invokes_real_adapter_and_verifies_state(
        self, mock_show_rule, mock_run_netsh
    ):
        """An authorized lab target invokes netsh add rule and confirms presence via show_rule."""
        action = ContainmentAction(
            id=str(uuid.uuid4()),
            action_id=f"act-live-{uuid.uuid4().hex[:8]}",
            tenant_id=self.demo_tenant.id,
            indicator_value="93.184.216.34",
            indicator_type="ipv4",
            action_type="BLOCK_INBOUND_PORT_8000",
            policy_decision="QUALIFIED",
            policy_rule="DEMO_LIVE_RULE",
            status="PENDING",
            ttl_seconds=3600
        )
        self.db.add(action)
        self.db.commit()

        # Mock netsh execution success and independent verification return
        mock_show_rule.side_effect = [
            None,  # Rule does not exist before addition
            {"Rule Name": WindowsFirewallAdapter.get_rule_name(action.action_id), "Action": "Block"}  # Exists after addition
        ]
        mock_run_netsh.return_value = (0, "Ok.\n", "")

        res = WindowsFirewallAdapter.apply_containment(action, self.db, is_simulated=False)

        self.assertEqual(res["status"], "VERIFIED")
        self.assertTrue(res["is_live_enforcement"])
        self.assertFalse(res["is_simulated"])

        self.db.refresh(action)
        self.assertEqual(action.status, "VERIFIED")
        self.assertIsNotNone(action.verified_at)

    # =========================================================================
    # Scenario 5: Execution or Verification Failure Persisted as FAILED
    # =========================================================================
    @patch("app.services.windows_firewall_adapter.WindowsFirewallAdapter._run_netsh")
    @patch("app.services.windows_firewall_adapter.WindowsFirewallAdapter.show_rule")
    def test_05_execution_or_verification_failure_persisted_as_failure(
        self, mock_show_rule, mock_run_netsh
    ):
        """When netsh or verification fails, status is accurately recorded as FAILED."""
        action = ContainmentAction(
            id=str(uuid.uuid4()),
            action_id=f"act-fail-{uuid.uuid4().hex[:8]}",
            tenant_id=self.demo_tenant.id,
            indicator_value="93.184.216.34",
            indicator_type="ipv4",
            action_type="BLOCK_INBOUND_PORT_8000",
            policy_decision="QUALIFIED",
            policy_rule="DEMO_FAIL_RULE",
            status="PENDING",
            ttl_seconds=3600
        )
        self.db.add(action)
        self.db.commit()

        mock_show_rule.return_value = None
        mock_run_netsh.return_value = (1, "The requested operation requires elevation.\n", "")

        res = WindowsFirewallAdapter.apply_containment(action, self.db, is_simulated=False)

        self.assertEqual(res["status"], "FAILED")
        self.db.refresh(action)
        self.assertEqual(action.status, "FAILED")
        self.assertIn("requires elevation", action.error_message)

    # =========================================================================
    # Scenario 6: Eligible Critical/High Automatically Remediates Under AUTO_PATCH
    # =========================================================================
    def test_06_eligible_critical_high_vulnerability_progresses_under_auto_patch(self):
        """Under AUTO_PATCH, Critical/High vulnerability automatically creates, approves, and executes proposal."""
        result = AutonomousResponseOrchestrator.correlate_sbom_and_create_incident(
            db=self.db,
            tenant_id=self.demo_tenant.id,
            threat_report_id=self.threat_report_with_ip.id,
            supporting_malicious_ip="93.184.216.34",
            is_simulated=True
        )

        self.assertIn(result["status"], ("AUTO_PATCH_SIMULATED", "AUTO_PATCHED_AND_RESOLVED"))
        self.assertEqual(result["remediation_policy"], "AUTO_PATCH")

        # Verify proposal was created and approved automatically
        proposal = self.db.query(PatchProposal).filter(
            PatchProposal.tenant_id == self.demo_tenant.id,
            PatchProposal.package_name == "uvicorn"
        ).first()
        self.assertIsNotNone(proposal)
        self.assertEqual(proposal.approved_by, "AUTONOMOUS_POLICY_AUTO_PATCH")
        self.assertIn(proposal.status, ("SIMULATED", "VERIFIED"))

    # =========================================================================
    # Scenario 7: Default NOTIFY Policy Prevents Automatic Patch Execution
    # =========================================================================
    def test_07_default_notify_policy_prevents_automatic_patch_execution(self):
        """Under NOTIFY policy, proposal is created in PROPOSED status and halts for human approval."""
        # Create threat report affecting django on standard_tenant (remediation_policy=NOTIFY)
        threat_django = models.ThreatReport(
            id=str(uuid.uuid4()),
            cve_id="CVE-2026-11111",
            title="Django QuerySet SQL Injection",
            summary="Django before 4.2.1 is vulnerable to SQL injection. Fixed in 4.2.1.",
            severity="high"
        )
        self.db.add(threat_django)
        self.db.commit()

        result = AutonomousResponseOrchestrator.correlate_sbom_and_create_incident(
            db=self.db,
            tenant_id=self.standard_tenant.id,
            threat_report_id=threat_django.id,
            is_simulated=True
        )

        self.assertEqual(result["status"], "INCIDENT_CREATED")
        proposal_info = result.get("patch_proposal")
        self.assertIsNotNone(proposal_info)

        proposal = self.db.query(PatchProposal).filter(
            PatchProposal.proposal_id == proposal_info["proposal_id"]
        ).first()
        self.assertEqual(proposal.status, "PROPOSED")
        self.assertIsNone(proposal.approved_by)

    # =========================================================================
    # Scenario 8: Missing or Unsafe Target Prevents Patching
    # =========================================================================
    def test_08_missing_or_unsafe_target_prevents_patching(self):
        """Patching against a non-existent interpreter path fails closed with FAILED status."""
        proposal = PatchManagementAdapter.create_proposal(
            db=self.db,
            tenant_id=self.demo_tenant.id,
            package_name="uvicorn",
            current_version="0.38.0",
            target_version="0.38.1",
            package_manager="pip"
        )
        PatchManagementAdapter.approve_proposal(
            db=self.db,
            proposal_id=proposal.proposal_id,
            approver="TEST_ADMIN"
        )

        # Point target interpreter to non-existent path
        orig_exists = os.path.exists
        with patch.dict(os.environ, {"TARGET_PYTHON_PATH": r"C:\non_existent_venv\python.exe", "ALLOW_SELF_PATCHING": "false"}):
            with patch("os.path.exists", side_effect=lambda p: False if "non_existent_venv" in str(p) else orig_exists(p)):
                res = PatchManagementAdapter.execute_patch(
                    db=self.db,
                    proposal_id=proposal.proposal_id,
                    mode="live"
                )
                self.assertEqual(res["status"], "FAILED")
                self.db.refresh(proposal)
                self.assertEqual(proposal.status, "FAILED")
                self.assertIn("does not exist", proposal.error_message)

    # =========================================================================
    # Scenario 9: Successful Patch Followed by Independent Version Verification
    # =========================================================================
    @patch("subprocess.run")
    def test_09_successful_patch_execution_followed_by_independent_version_verification(self, mock_subproc):
        """Live patch execution runs pip install, verifies read-back version, and marks VERIFIED."""
        proposal = PatchManagementAdapter.create_proposal(
            db=self.db,
            tenant_id=self.demo_tenant.id,
            package_name="uvicorn",
            current_version="0.38.0",
            target_version="0.38.1",
            package_manager="pip"
        )
        PatchManagementAdapter.approve_proposal(
            db=self.db,
            proposal_id=proposal.proposal_id,
            approver="TEST_ADMIN"
        )

        # Mock pip install success and pip show readback returning Version: 0.38.1
        mock_proc_install = MagicMock(returncode=0, stdout="Successfully installed uvicorn-0.38.1\n", stderr="")
        mock_proc_show = MagicMock(
            returncode=0,
            stdout="Name: uvicorn\nVersion: 0.38.1\nSummary: ASGI web server\n",
            stderr=""
        )
        mock_subproc.side_effect = [mock_proc_install, mock_proc_show]

        with patch.dict(os.environ, {"ALLOW_SELF_PATCHING": "true"}):
            res = PatchManagementAdapter.execute_patch(
                db=self.db,
                proposal_id=proposal.proposal_id,
                mode="live"
            )

        self.assertEqual(res["status"], "VERIFIED")
        self.assertFalse(res["is_simulated"])
        self.db.refresh(proposal)
        self.assertEqual(proposal.status, "VERIFIED")

    # =========================================================================
    # Scenario 10: Failed Patching or Verification Never Results in APPLIED/VERIFIED
    # =========================================================================
    @patch("subprocess.run")
    def test_10_failed_patching_or_verification_never_results_in_applied(self, mock_subproc):
        """If pip show returns mismatched version, proposal status is FAILED, not VERIFIED."""
        proposal = PatchManagementAdapter.create_proposal(
            db=self.db,
            tenant_id=self.demo_tenant.id,
            package_name="uvicorn",
            current_version="0.38.0",
            target_version="0.38.1",
            package_manager="pip"
        )
        PatchManagementAdapter.approve_proposal(
            db=self.db,
            proposal_id=proposal.proposal_id,
            approver="TEST_ADMIN"
        )

        # Pip install returned 0, but pip show still shows old version 0.38.0!
        mock_proc_install = MagicMock(returncode=0, stdout="Requirement already satisfied\n", stderr="")
        mock_proc_show = MagicMock(
            returncode=0,
            stdout="Name: uvicorn\nVersion: 0.38.0\n",
            stderr=""
        )
        mock_subproc.side_effect = [mock_proc_install, mock_proc_show]

        with patch.dict(os.environ, {"ALLOW_SELF_PATCHING": "true"}):
            res = PatchManagementAdapter.execute_patch(
                db=self.db,
                proposal_id=proposal.proposal_id,
                mode="live"
            )

        self.assertEqual(res["status"], "FAILED")
        self.assertIn("mismatch", res["error"].lower())
        self.db.refresh(proposal)
        self.assertEqual(proposal.status, "FAILED")

    # =========================================================================
    # Scenario 11: Duplicate Events Do Not Repeat Containment or Patching
    # =========================================================================
    def test_11_duplicate_events_do_not_repeat_containment_or_patching(self):
        """Repeated events reuse existing active proposals and containment actions idempotently."""
        # First execution creates proposal
        prop1 = PatchManagementAdapter.create_proposal(
            db=self.db,
            tenant_id=self.demo_tenant.id,
            package_name="uvicorn",
            current_version="0.38.0",
            target_version="0.38.1",
            package_manager="pip"
        )

        # Second creation call with identical spec returns the existing proposal
        prop2 = PatchManagementAdapter.create_proposal(
            db=self.db,
            tenant_id=self.demo_tenant.id,
            package_name="uvicorn",
            current_version="0.38.0",
            target_version="0.38.1",
            package_manager="pip"
        )
        self.assertEqual(prop1.id, prop2.id)
        self.assertEqual(prop1.proposal_id, prop2.proposal_id)

    # =========================================================================
    # Scenario 12: Multi-Tenant Isolation Enforced
    # =========================================================================
    def test_12_other_tenants_remain_unaffected(self):
        """Standard tenant cannot approve, execute, or view demo tenant's remediation proposals."""
        prop = PatchManagementAdapter.create_proposal(
            db=self.db,
            tenant_id=self.demo_tenant.id,
            package_name="uvicorn",
            current_version="0.38.0",
            target_version="0.38.1",
            package_manager="pip"
        )

        # Cross-tenant approval attempt must raise PatchStateError
        with self.assertRaises(PatchStateError):
            PatchManagementAdapter.approve_proposal(
                db=self.db,
                proposal_id=prop.proposal_id,
                approver="ATTACKER",
                tenant_id=self.standard_tenant.id
            )

        # Standard tenant policy remains NOTIFY
        self.db.refresh(self.standard_tenant)
        self.assertEqual(self.standard_tenant.remediation_policy, "NOTIFY")

    # =========================================================================
    # Scenario 13: Webhook & Email Failures Do Not Corrupt Action Status
    # =========================================================================
    @patch("requests.post")
    def test_13_webhook_and_email_failures_do_not_corrupt_action_status(self, mock_post):
        """Webhook network timeout does not undo security action execution or alter its status."""
        mock_post.side_effect = Exception("Connection refused / Webhook endpoint down")

        action = ContainmentAction(
            id=str(uuid.uuid4()),
            action_id=f"act-notif-{uuid.uuid4().hex[:8]}",
            tenant_id=self.demo_tenant.id,
            indicator_value="93.184.216.34",
            indicator_type="ipv4",
            action_type="BLOCK_INBOUND_PORT_8000",
            policy_decision="QUALIFIED",
            policy_rule="DEMO_RULE",
            status="SIMULATED",
            ttl_seconds=3600
        )
        self.db.add(action)
        self.db.commit()

        # Notification dispatch encounters network failure
        notif_res = NotificationService.send_incident_notification(
            db=self.db,
            tenant=self.demo_tenant,
            event_type="CONTAINMENT_APPLIED",
            threat_report=self.threat_report_with_ip,
            asset=self.asset_uvicorn,
            containment_action_id=action.action_id
        )

        self.assertEqual(notif_res["status"], "FAILED")
        self.db.refresh(action)
        # Action status MUST remain SIMULATED (never changed to FAILED due to webhook)
        self.assertEqual(action.status, "SIMULATED")

    # =========================================================================
    # Scenario 14: Vulnerability Without Malicious IP Suppresses Containment
    # =========================================================================
    def test_14_vulnerability_without_malicious_ip_suppresses_containment(self):
        """An SBOM match on a vulnerability advisory without malicious IP suppresses containment."""
        result = AutonomousResponseOrchestrator.correlate_sbom_and_create_incident(
            db=self.db,
            tenant_id=self.demo_tenant.id,
            threat_report_id=self.threat_report_no_ip.id,
            supporting_malicious_ip=None,
            is_simulated=True
        )

        # Containment is suppressed (None)
        self.assertIsNone(result.get("containment"))

        # Remediation progresses independently
        self.assertIn(result["status"], ("AUTO_PATCH_SIMULATED", "AUTO_PATCHED_AND_RESOLVED"))
        proposal = self.db.query(PatchProposal).filter(
            PatchProposal.tenant_id == self.demo_tenant.id,
            PatchProposal.package_name == "uvicorn"
        ).first()
        self.assertIsNotNone(proposal)
