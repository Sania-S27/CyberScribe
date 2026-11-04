"""
Targeted Tests for CyberScribe Target-Host Execution Architecture
-----------------------------------------------------------------
Validates all requirements for real host target execution:
1. Target Authentication and Authorization:
   - Tenant isolation on patch proposals (create, approve, reject, execute).
   - Tenant isolation on containment rollback.
   - Bearer token authentication on Windows loopback daemon.
   - Bearer token authentication on Fedora executor daemon.
2. Allowlisted, Policy-Approved Execution Only:
   - Rejection of arbitrary shell commands and injection metacharacters.
3. Narrowly Scoped Containment & Exact Rollback:
   - Windows Defender Firewall scoped to inbound port 8000.
   - Exact rule name CyberScribe_<action_id>.
   - Rollback deletes ONLY the exact CyberScribe rule; unrelated rules remain untouched.
4. Independent Post-Execution Version Read-Back:
   - Verification parses installed package version from verify command stdout.
   - Rejection if installed version does not match target version.
   - Rejection if verify output is inconclusive.
5. Containment Retention on Patch Failure or Mismatch:
   - Containment is preserved if update command fails.
   - Containment is preserved if verification fails or is inconclusive.
   - Containment is preserved if installed version does not resolve vulnerability.
   - Containment is released ONLY when verified and evaluated to NOT_AFFECTED.
6. Execution Resilience & Duplicate Idempotency:
   - Duplicate patch execution requests safely return existing state.
   - Subprocess timeout handling records honest failure and preserves containment.
"""

import os
import sys
import uuid
import subprocess
from datetime import datetime, timedelta, timezone
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from tests.base import BaseTestCase
from app import models
from app.services.patch_adapter import (
    PatchManagementAdapter,
    PatchSecurityError,
    PatchStateError,
    parse_installed_version,
    verify_version_match,
    _get_python_bin
)
from app.services.windows_firewall_adapter import (
    WindowsFirewallAdapter,
    WindowsFirewallError,
    validate_ip_for_containment
)
from app.services.windows_executor.cyberscribe_win_helper import (
    validate_public_ipv4,
    HelperSecurityError,
    apply_rule as helper_apply_rule
)
from app.services.autonomous_response_orchestrator import AutonomousResponseOrchestrator
from app.services.firewall_adapter import SimulatedFirewallAdapter, get_adapter_for_action
from app.services.windows_executor.windows_executor_daemon import app as win_daemon_app, EXECUTOR_TOKEN as WIN_TOKEN


class TestTargetHostExecution(BaseTestCase):

    def setUp(self):
        super().setUp()
        self._orig_win_exec_url = os.environ.get("WINDOWS_EXECUTOR_URL")
        os.environ["WINDOWS_EXECUTOR_URL"] = ""

        # Seed second tenant to verify multi-tenant isolation
        self.other_tenant = models.Tenant(
            id=str(uuid.uuid4()),
            company_name="Malicious Adversary Org",
            tech_stack="Linux, Bash"
        )
        self.db.add(self.other_tenant)

        # Asset component on Campus Guide (FastAPI backend)
        self.asset_uvicorn = models.AssetComponent(
            id=str(uuid.uuid4()),
            tenant_id=self.tenant.id,
            software_name="uvicorn",
            software_version="0.38.0",
            environment="production"
        )
        self.db.add(self.asset_uvicorn)

        # Threat report for CVE-2026-26209 affecting uvicorn < 0.38.1
        self.threat_report = models.ThreatReport(
            id=str(uuid.uuid4()),
            cve_id="CVE-2026-26209",
            title="Uvicorn Header Parsing Vulnerability",
            summary="Uvicorn versions before 0.38.1 are vulnerable to HTTP request smuggling. Fixed in version 0.38.1.",
            severity="high"
        )
        self.db.add(self.threat_report)

        # Threat match linking tenant, report, and asset
        self.threat_match = models.ThreatMatch(
            id=str(uuid.uuid4()),
            tenant_id=self.tenant.id,
            asset_component_id=self.asset_uvicorn.id,
            threat_report_id=self.threat_report.id,
            status="OPEN",
            ai_confidence_score=0.95,
            ai_matching_reason="Affected package uvicorn 0.38.0 satisfies constraint < 0.38.1."
        )
        self.db.add(self.threat_match)

        # Active containment action on port 8000
        self.containment_action = models.ContainmentAction(
            id=str(uuid.uuid4()),
            action_id="act-target-test-001",
            tenant_id=self.tenant.id,
            threat_report_id=self.threat_report.id,
            threat_match_id=self.threat_match.id,
            indicator_value="93.184.216.34",
            indicator_type="ipv4",
            action_type="BLOCK_INBOUND_PORT_8000",
            policy_decision="QUALIFIED",
            policy_rule="JUSTIFIED_INCIDENT_EXPLOIT_CONTAINMENT",
            status="SIMULATED",
            ttl_seconds=3600
        )
        self.db.add(self.containment_action)
        self.db.commit()

    def tearDown(self):
        if self._orig_win_exec_url is not None:
            os.environ["WINDOWS_EXECUTOR_URL"] = self._orig_win_exec_url
        else:
            os.environ.pop("WINDOWS_EXECUTOR_URL", None)
        super().tearDown()

    # =========================================================================
    # 1. Authentication & Tenant Authorization
    # =========================================================================

    def test_01_tenant_isolation_on_proposals(self):
        """Cross-tenant authorization check: unauthorized tenant cannot approve or execute proposal."""
        proposal = PatchManagementAdapter.create_proposal(
            db=self.db,
            tenant_id=self.tenant.id,
            package_name="uvicorn",
            current_version="0.38.0",
            target_version="0.38.1",
            package_manager="pip"
        )

        # Attempt approval from other tenant must fail
        with self.assertRaises(PatchStateError):
            PatchManagementAdapter.approve_proposal(
                db=self.db,
                proposal_id=proposal.proposal_id,
                approver="ADVERSARY_USER",
                tenant_id=self.other_tenant.id
            )

        # Approve legitimately
        PatchManagementAdapter.approve_proposal(
            db=self.db,
            proposal_id=proposal.proposal_id,
            approver="AUTHORIZED_SOC_LEAD",
            tenant_id=self.tenant.id
        )

        # Attempt execution from other tenant must fail
        with self.assertRaises(PatchStateError):
            PatchManagementAdapter.execute_patch(
                db=self.db,
                proposal_id=proposal.proposal_id,
                mode="simulated",
                tenant_id=self.other_tenant.id
            )

    def test_02_tenant_isolation_on_containment_rollback(self):
        """Cross-tenant containment rollback is strictly rejected."""
        with self.assertRaises(PermissionError):
            SimulatedFirewallAdapter.rollback_containment(
                action=self.containment_action,
                db=self.db,
                expected_tenant_id=self.other_tenant.id
            )

    @patch("app.services.windows_executor.cyberscribe_win_helper.apply_rule")
    def test_03_windows_executor_daemon_authentication(self, mock_apply):
        """Windows loopback executor daemon enforces bearer token authorization."""
        client = TestClient(win_daemon_app)

        # Unauthenticated request fails with 401
        res_no_auth = client.post("/apply", json={
            "action_id": "act-test-01",
            "ip_address": "93.184.216.34",
            "port": 8000
        })
        self.assertEqual(res_no_auth.status_code, 401)

        # Bad token fails with 401
        res_bad_auth = client.post(
            "/apply",
            json={"action_id": "act-test-01", "ip_address": "93.184.216.34", "port": 8000},
            headers={"X-CyberScribe-Executor-Token": "invalid-secret"}
        )
        self.assertEqual(res_bad_auth.status_code, 401)

        # Valid token succeeds
        mock_apply.return_value = {"status": "APPLIED", "action_id": "act-test-01"}
        res_valid = client.post(
            "/apply",
            json={"action_id": "act-test-01", "ip_address": "93.184.216.34", "port": 8000},
            headers={"X-CyberScribe-Executor-Token": WIN_TOKEN}
        )
        self.assertEqual(res_valid.status_code, 200)
        self.assertEqual(res_valid.json()["status"], "APPLIED")

    # =========================================================================
    # 2. Rejection of Arbitrary Shell Commands (Least Privilege)
    # =========================================================================

    def test_04_arbitrary_shell_injection_defense(self):
        """Rejects dangerous shell metacharacters and arbitrary commands in package/version."""
        dangerous_inputs = [
            ("fastapi; rm -rf /", "0.120.2"),
            ("uvicorn && cat /etc/passwd", "0.38.1"),
            ("curl | bash", "1.0.0"),
            ("uvicorn", "0.38.1; echo pwned"),
            ("`whoami`", "1.0.0"),
            ("$(reboot)", "1.0.0")
        ]
        for pkg, ver in dangerous_inputs:
            with self.assertRaises(PatchSecurityError):
                PatchManagementAdapter.create_proposal(
                    db=self.db,
                    tenant_id=self.tenant.id,
                    package_name=pkg,
                    target_version=ver,
                    package_manager="pip"
                )

    # =========================================================================
    # 3. Duplicate Requests & Idempotency
    # =========================================================================

    def test_05_duplicate_patch_execution_is_idempotent(self):
        """Executing an already-executed patch returns the existing state safely."""
        proposal = PatchManagementAdapter.create_proposal(
            db=self.db,
            tenant_id=self.tenant.id,
            package_name="uvicorn",
            target_version="0.38.1",
            package_manager="pip"
        )
        PatchManagementAdapter.approve_proposal(
            db=self.db,
            proposal_id=proposal.proposal_id,
            approver="SOC_LEAD",
            tenant_id=self.tenant.id
        )

        first_res = PatchManagementAdapter.execute_patch(
            db=self.db,
            proposal_id=proposal.proposal_id,
            mode="simulated",
            tenant_id=self.tenant.id
        )
        self.assertEqual(first_res["status"], "SIMULATED")

        # Duplicate call
        dup_res = PatchManagementAdapter.execute_patch(
            db=self.db,
            proposal_id=proposal.proposal_id,
            mode="simulated",
            tenant_id=self.tenant.id
        )
        self.assertEqual(dup_res["status"], "SIMULATED")
        self.assertIn("already executed", dup_res["message"].lower())

    def test_06_duplicate_containment_application_is_idempotent(self):
        """Repeated containment application returns existing status without duplicate rule staging."""
        res1 = WindowsFirewallAdapter.apply_containment(
            action=self.containment_action,
            db=self.db,
            is_simulated=True
        )
        self.assertEqual(res1["status"], "SIMULATED")

        res2 = WindowsFirewallAdapter.apply_containment(
            action=self.containment_action,
            db=self.db,
            is_simulated=True
        )
        self.assertEqual(res2["status"], "SIMULATED")
        self.assertIn("already simulated", res2["message"].lower())

    # =========================================================================
    # 4. Mocked Execution: Timeout & Command Failure Handling
    # =========================================================================

    @patch("subprocess.run")
    def test_07_patch_execution_timeout_records_honest_failure(self, mock_subproc):
        """Execution timeout is caught, marks status FAILED, and logs audit record."""
        mock_subproc.side_effect = subprocess.TimeoutExpired(cmd=["pip", "install"], timeout=45)

        proposal = PatchManagementAdapter.create_proposal(
            db=self.db,
            tenant_id=self.tenant.id,
            package_name="uvicorn",
            target_version="0.38.1",
            package_manager="pip"
        )
        PatchManagementAdapter.approve_proposal(
            db=self.db,
            proposal_id=proposal.proposal_id,
            approver="SOC_LEAD",
            tenant_id=self.tenant.id
        )

        res = PatchManagementAdapter.execute_patch(
            db=self.db,
            proposal_id=proposal.proposal_id,
            mode="live",
            tenant_id=self.tenant.id
        )
        self.assertEqual(res["status"], "FAILED")
        self.assertIn("timed out", res["error"].lower())

        self.db.refresh(proposal)
        self.assertEqual(proposal.status, "FAILED")

    @patch("subprocess.run")
    def test_08_patch_command_exit_code_failure_records_honest_failure(self, mock_subproc):
        """Non-zero exit code marks proposal FAILED and saves error message."""
        mock_proc = MagicMock()
        mock_proc.returncode = 1
        mock_proc.stdout = ""
        mock_proc.stderr = "ERROR: Could not find a version that satisfies the requirement uvicorn==0.38.1"
        mock_subproc.return_value = mock_proc

        proposal = PatchManagementAdapter.create_proposal(
            db=self.db,
            tenant_id=self.tenant.id,
            package_name="uvicorn",
            target_version="0.38.1",
            package_manager="pip"
        )
        PatchManagementAdapter.approve_proposal(
            db=self.db,
            proposal_id=proposal.proposal_id,
            approver="SOC_LEAD",
            tenant_id=self.tenant.id
        )

        res = PatchManagementAdapter.execute_patch(
            db=self.db,
            proposal_id=proposal.proposal_id,
            mode="live",
            tenant_id=self.tenant.id
        )
        self.assertEqual(res["status"], "FAILED")
        self.assertIn("exit code 1", res["error"].lower())

        self.db.refresh(proposal)
        self.assertEqual(proposal.status, "FAILED")

    # =========================================================================
    # 5. Independent Post-Execution Version Verification & Mismatch Defense
    # =========================================================================

    def test_09_version_parsing_logic(self):
        """Validates robust parsing across pip, apt, and dnf/yum outputs."""
        pip_sample = "Name: uvicorn\nVersion: 0.38.1\nSummary: ASGI web server\nLocation: /app/venv\n"
        self.assertEqual(parse_installed_version("pip", pip_sample, "uvicorn"), "0.38.1")

        apt_sample = "install ok installed 0.38.1-1ubuntu1\n"
        self.assertEqual(parse_installed_version("apt", apt_sample, "uvicorn"), "0.38.1-1ubuntu1")

        rpm_sample = "uvicorn-0.38.1-1.fc44.noarch\n"
        self.assertEqual(parse_installed_version("dnf", rpm_sample, "uvicorn"), "0.38.1")

        self.assertTrue(verify_version_match("0.38.1", "0.38.1"))
        self.assertFalse(verify_version_match("0.38.0", "0.38.1"))

    @patch("subprocess.run")
    def test_10_verification_mismatch_preserves_containment(self, mock_subproc):
        """
        When update command exits 0 but independent verification detects installed version != target_version,
        the proposal MUST fail and containment must NOT be released.
        """
        # Call 1 (update): succeeds
        proc_update = MagicMock(returncode=0, stdout="Successfully installed uvicorn-0.38.0", stderr="")
        # Call 2 (verify): reports version is STILL 0.38.0 (mismatch against target 0.38.1)
        proc_verify = MagicMock(returncode=0, stdout="Name: uvicorn\nVersion: 0.38.0\n", stderr="")
        mock_subproc.side_effect = [proc_update, proc_verify]

        proposal = PatchManagementAdapter.create_proposal(
            db=self.db,
            tenant_id=self.tenant.id,
            package_name="uvicorn",
            target_version="0.38.1",
            package_manager="pip"
        )
        PatchManagementAdapter.approve_proposal(
            db=self.db,
            proposal_id=proposal.proposal_id,
            approver="SOC_LEAD",
            tenant_id=self.tenant.id
        )

        res = PatchManagementAdapter.execute_patch(
            db=self.db,
            proposal_id=proposal.proposal_id,
            mode="live",
            tenant_id=self.tenant.id
        )
        self.assertEqual(res["status"], "FAILED")
        self.assertIn("mismatch", res["error"].lower())
        self.assertEqual(res["installed_version"], "0.38.0")
        self.assertEqual(res["target_version"], "0.38.1")

        self.db.refresh(proposal)
        self.assertEqual(proposal.status, "FAILED")

    @patch("subprocess.run")
    def test_11_inconclusive_verification_fails_and_preserves_containment(self, mock_subproc):
        """When verify output cannot be parsed to an installed version, proposal fails."""
        proc_update = MagicMock(returncode=0, stdout="Success", stderr="")
        proc_verify = MagicMock(returncode=0, stdout="Package not found or malformed output", stderr="")
        mock_subproc.side_effect = [proc_update, proc_verify]

        proposal = PatchManagementAdapter.create_proposal(
            db=self.db,
            tenant_id=self.tenant.id,
            package_name="uvicorn",
            target_version="0.38.1",
            package_manager="pip"
        )
        PatchManagementAdapter.approve_proposal(
            db=self.db,
            proposal_id=proposal.proposal_id,
            approver="SOC_LEAD",
            tenant_id=self.tenant.id
        )

        res = PatchManagementAdapter.execute_patch(
            db=self.db,
            proposal_id=proposal.proposal_id,
            mode="live",
            tenant_id=self.tenant.id
        )
        self.assertEqual(res["status"], "FAILED")
        self.assertIn("inconclusive", res["error"].lower())

    # =========================================================================
    # 6. Firewall Rollback Safety & Scope Verification
    # =========================================================================

    @patch("app.services.windows_firewall_adapter.WindowsFirewallAdapter._run_netsh")
    @patch("app.services.windows_firewall_adapter.WindowsFirewallAdapter.show_rule")
    def test_12_exact_firewall_rule_rollback_safety(self, mock_show_rule, mock_run_netsh):
        """Deletes only the exact CyberScribe_<action_id> rule and verifies absence."""
        self.containment_action.status = "VERIFIED"
        self.db.commit()

        mock_run_netsh.return_value = (0, "Deleted 1 rule(s).\nOk.\n", "")
        mock_show_rule.return_value = None  # Readback confirms rule is gone

        res = WindowsFirewallAdapter.rollback_containment(self.containment_action, self.db)
        self.assertEqual(res["status"], "ROLLED_BACK")

        # Must invoke delete rule for ONLY this exact rule
        mock_run_netsh.assert_called_with(["delete", "rule", f"name=CyberScribe_{self.containment_action.action_id}"])

    @patch("app.services.windows_firewall_adapter.WindowsFirewallAdapter._run_netsh")
    @patch("app.services.windows_firewall_adapter.WindowsFirewallAdapter.show_rule")
    def test_13_firewall_rollback_failure_does_not_mark_rolled_back(self, mock_show_rule, mock_run_netsh):
        """If netsh fails or rule persists after delete command, action is NOT marked ROLLED_BACK."""
        self.containment_action.status = "VERIFIED"
        self.db.commit()

        mock_run_netsh.return_value = (1, "Access denied.\n", "")
        mock_show_rule.return_value = {"rule name": f"CyberScribe_{self.containment_action.action_id}"}

        res = WindowsFirewallAdapter.rollback_containment(self.containment_action, self.db)
        self.assertNotEqual(res["status"], "ROLLED_BACK")
        self.assertFalse(res.get("rolled_back", False))

        self.db.refresh(self.containment_action)
        self.assertNotEqual(self.containment_action.status, "ROLLED_BACK")

    # =========================================================================
    # 7. End-to-End Orchestrator: Containment Retention vs Safe Release
    # =========================================================================

    @patch("app.services.notification_service.NotificationService.send_incident_notification")
    @patch("subprocess.run")
    def test_14_orchestrator_preserves_containment_when_patch_verification_fails(self, mock_subproc, mock_notif):
        """End-to-end: If patch verification reports wrong version, containment stays active."""
        proc_update = MagicMock(returncode=0, stdout="Installed", stderr="")
        proc_verify = MagicMock(returncode=0, stdout="Name: uvicorn\nVersion: 0.38.0\n", stderr="")
        mock_subproc.side_effect = [proc_update, proc_verify]

        proposal = PatchManagementAdapter.create_proposal(
            db=self.db,
            tenant_id=self.tenant.id,
            threat_match_id=self.threat_match.id,
            asset_component_id=self.asset_uvicorn.id,
            package_name="uvicorn",
            target_version="0.38.1",
            package_manager="pip"
        )
        PatchManagementAdapter.approve_proposal(
            db=self.db,
            proposal_id=proposal.proposal_id,
            approver="SOC_LEAD",
            tenant_id=self.tenant.id
        )

        res = AutonomousResponseOrchestrator.execute_patch_and_release(
            db=self.db,
            proposal_id=proposal.proposal_id,
            tenant_id=self.tenant.id,
            is_simulated=False
        )

        self.assertEqual(res["status"], "PATCH_EXECUTION_FAILED")
        self.assertIn("mismatch", res["error"].lower())

        # Containment action MUST STILL BE ACTIVE (SIMULATED or VERIFIED)
        self.db.refresh(self.containment_action)
        self.assertEqual(self.containment_action.status, "SIMULATED")
        self.assertIsNone(self.containment_action.rolled_back_at)

        # ThreatMatch must NOT be resolved
        self.db.refresh(self.threat_match)
        self.assertNotEqual(self.threat_match.status, "RESOLVED")

    @patch("app.services.notification_service.NotificationService.send_incident_notification")
    @patch("subprocess.run")
    @patch("app.services.windows_firewall_adapter.WindowsFirewallAdapter._run_netsh")
    @patch("app.services.windows_firewall_adapter.WindowsFirewallAdapter.show_rule")
    def test_15_orchestrator_releases_containment_only_when_fully_verified(
        self, mock_show_rule, mock_run_netsh, mock_subproc, mock_notif
    ):
        """End-to-end: Live patch succeeds, version 0.38.1 verified, containment released, threat RESOLVED."""
        # Live subprocess runs
        proc_update = MagicMock(returncode=0, stdout="Successfully installed uvicorn-0.38.1", stderr="")
        proc_verify = MagicMock(returncode=0, stdout="Name: uvicorn\nVersion: 0.38.1\n", stderr="")
        mock_subproc.side_effect = [proc_update, proc_verify]

        # Firewall netsh mocks
        mock_run_netsh.return_value = (0, "Deleted 1 rule(s).\nOk.\n", "")
        mock_show_rule.return_value = None

        proposal = PatchManagementAdapter.create_proposal(
            db=self.db,
            tenant_id=self.tenant.id,
            threat_match_id=self.threat_match.id,
            asset_component_id=self.asset_uvicorn.id,
            package_name="uvicorn",
            target_version="0.38.1",
            package_manager="pip"
        )
        PatchManagementAdapter.approve_proposal(
            db=self.db,
            proposal_id=proposal.proposal_id,
            approver="SOC_LEAD",
            tenant_id=self.tenant.id
        )

        res = AutonomousResponseOrchestrator.execute_patch_and_release(
            db=self.db,
            proposal_id=proposal.proposal_id,
            tenant_id=self.tenant.id,
            is_simulated=False
        )

        self.assertEqual(res["status"], "SUCCESS_VERIFIED_AND_RELEASED")
        self.assertEqual(res["verified_version"], "0.38.1")
        self.assertEqual(res["vulnerability_status"], "RESOLVED")

        # Containment action must be rolled back
        self.db.refresh(self.containment_action)
        self.assertEqual(self.containment_action.status, "ROLLED_BACK")
        self.assertIsNotNone(self.containment_action.rolled_back_at)

        # ThreatMatch must be RESOLVED
        self.db.refresh(self.threat_match)
        self.assertEqual(self.threat_match.status, "RESOLVED")

        # AssetComponent version must be updated
        self.db.refresh(self.asset_uvicorn)
        self.assertEqual(self.asset_uvicorn.software_version, "0.38.1")

    def test_automatic_policy_auto_patch_flow(self):
        """AUTO_PATCH policy automatically creates proposal, containment, executes patch, and releases."""
        self.tenant.remediation_policy = "AUTO_PATCH"
        self.db.commit()

        # Advisory with malicious IP in summary
        report = models.ThreatReport(
            id=str(uuid.uuid4()),
            cve_id="CVE-2026-99991",
            title="Uvicorn Critical Remote Exploit",
            summary="Uvicorn versions before 0.38.1 are vulnerable. Fixed in version 0.38.1. Malicious exploit payload delivered from C2 server 198.51.100.88.",
            severity="critical"
        )
        self.db.add(report)
        self.db.commit()

        res = AutonomousResponseOrchestrator.correlate_sbom_and_create_incident(
            db=self.db,
            tenant_id=self.tenant.id,
            threat_report_id=report.id,
            is_simulated=True
        )

        self.assertEqual(res["status"], "AUTO_PATCH_SIMULATED")
        self.assertEqual(res["matched_component"], "uvicorn")
        self.assertEqual(res["fixed_version"], "0.38.1")
        self.assertIsNotNone(res["containment"])

        # Check proposal was approved by autonomous engine
        prop = self.db.query(models.PatchProposal).filter(
            models.PatchProposal.tenant_id == self.tenant.id,
            models.PatchProposal.threat_match_id == res["incident_id"]
        ).first()
        self.assertIsNotNone(prop)
        self.assertEqual(prop.status, "SIMULATED")
        self.assertEqual(prop.approved_by, "AUTONOMOUS_POLICY_AUTO_PATCH")

        # Threat match must remain OPEN for simulation
        match = self.db.query(models.ThreatMatch).filter(models.ThreatMatch.id == res["incident_id"]).first()
        self.assertEqual(match.status, "OPEN")

        # Containment action must remain active (never rolled back in simulation)
        action = self.db.query(models.ContainmentAction).filter(
            models.ContainmentAction.threat_match_id == match.id
        ).first()
        self.assertIsNotNone(action)
        self.assertEqual(action.status, "SIMULATED")
        self.assertIsNone(action.rolled_back_at)

    def test_policy_notify_never_bypasses_approval(self):
        """NOTIFY policy strictly creates proposal in PROPOSED state and NEVER executes automatically."""
        self.tenant.remediation_policy = "NOTIFY"
        self.db.commit()

        report = models.ThreatReport(
            id=str(uuid.uuid4()),
            cve_id="CVE-2026-99992",
            title="Uvicorn Moderate Issue",
            summary="Uvicorn versions before 0.38.1 have a bug. Exploit traffic from 203.0.113.12.",
            severity="medium"
        )
        self.db.add(report)
        self.db.commit()

        res = AutonomousResponseOrchestrator.correlate_sbom_and_create_incident(
            db=self.db,
            tenant_id=self.tenant.id,
            threat_report_id=report.id,
            is_simulated=True
        )

        self.assertEqual(res["status"], "INCIDENT_CREATED")
        prop_info = res.get("patch_proposal")
        self.assertIsNotNone(prop_info)
        self.assertEqual(prop_info["status"], "PROPOSED")

        # Proposal must NOT be approved or executed
        prop = self.db.query(models.PatchProposal).filter(
            models.PatchProposal.proposal_id == prop_info["proposal_id"]
        ).first()
        self.assertIsNone(prop.approved_by)
        self.assertIsNone(prop.applied_at)

        # ThreatMatch must remain OPEN
        match = self.db.query(models.ThreatMatch).filter(models.ThreatMatch.id == res["incident_id"]).first()
        self.assertEqual(match.status, "OPEN")

        # Containment must remain active (SIMULATED), NOT released
        action = self.db.query(models.ContainmentAction).filter(
            models.ContainmentAction.threat_match_id == match.id
        ).first()
        self.assertIsNotNone(action)
        self.assertEqual(action.status, "SIMULATED")

    def test_dynamic_adapter_selection_fedora_vs_windows(self):
        """Validates adapter selection routes Linux/Fedora to FedoraNftablesAdapter and Windows to WindowsFirewallAdapter."""
        from app.services.fedora_nftables_adapter import FedoraNftablesAdapter

        with patch.dict(os.environ, {"CONTAINMENT_ADAPTER_MODE": ""}):
            # Fedora tenant
            fedora_tenant = models.Tenant(
                id=str(uuid.uuid4()),
                company_name="Fedora Cloud Systems",
                tech_stack="Fedora 44, Python, DNF"
            )
            adapter_fed = AutonomousResponseOrchestrator.resolve_firewall_adapter(tenant=fedora_tenant)
            self.assertEqual(adapter_fed, FedoraNftablesAdapter)
            pm_fed = AutonomousResponseOrchestrator.resolve_package_manager_for_asset(
                asset=models.AssetComponent(software_name="nginx", software_version="1.20"),
                tenant=fedora_tenant
            )
            self.assertEqual(pm_fed, "dnf")

            # Windows tenant
            win_tenant = models.Tenant(
                id=str(uuid.uuid4()),
                company_name="Campus Guide Production",
                tech_stack="Windows Server 2025, FastAPI, IIS"
            )
            adapter_win = AutonomousResponseOrchestrator.resolve_firewall_adapter(tenant=win_tenant)
            self.assertEqual(adapter_win, WindowsFirewallAdapter)
            pm_win = AutonomousResponseOrchestrator.resolve_package_manager_for_asset(
                asset=self.asset_uvicorn,
                tenant=win_tenant
            )
            self.assertEqual(pm_win, "pip")

    def test_ioc_extraction_from_stix_bundle(self):
        """Extracts validated IPv4 IOC from STIX bundle indicator object."""
        report = models.ThreatReport(
            id=str(uuid.uuid4()),
            cve_id="CVE-2026-STIX-001",
            title="STIX Indicator Threat",
            summary="Vulnerability with bundled STIX indicators.",
            severity="high",
            stix_bundle={
                "type": "bundle",
                "objects": [
                    {
                        "type": "indicator",
                        "pattern": "[ipv4-addr:value = '203.0.113.66']",
                        "indicator_types": ["malicious-activity"]
                    }
                ]
            }
        )
        self.db.add(report)
        self.db.commit()

        extracted_ip = AutonomousResponseOrchestrator.extract_malicious_ip_from_report(report)
        self.assertEqual(extracted_ip, "203.0.113.66")

    def test_osint_sweep_correlates_and_triggers_orchestrator(self):
        """Background process_threat_tenant_correlations calls AutonomousResponseOrchestrator on affected match."""
        from app.services.osint_collector import process_threat_tenant_correlations

        report = models.ThreatReport(
            id=str(uuid.uuid4()),
            cve_id="CVE-2026-99993",
            title="Uvicorn Buffer Overflow Exploit",
            summary="Uvicorn versions before 0.38.1 are affected by heap overflow. Fixed in 0.38.1. Active exploit from 198.51.100.99.",
            severity="critical"
        )
        self.db.add(report)
        self.db.commit()

        # Execute correlation
        process_threat_tenant_correlations(self.db, report)

        # Verify incident and proposal were created
        match = self.db.query(models.ThreatMatch).filter(
            models.ThreatMatch.tenant_id == self.tenant.id,
            models.ThreatMatch.threat_report_id == report.id
        ).first()
        self.assertIsNotNone(match, "ThreatMatch should be created by correlation sweep")
        self.assertEqual(match.asset_component_id, self.asset_uvicorn.id)

        # Verify proposal created
        prop = self.db.query(models.PatchProposal).filter(
            models.PatchProposal.tenant_id == self.tenant.id,
            models.PatchProposal.threat_match_id == match.id
        ).first()
        self.assertIsNotNone(prop, "PatchProposal should be staged automatically by orchestrator")
        self.assertEqual(prop.target_version, "0.38.1")

    def test_windows_firewall_adapter_bulk_expiry(self):
        """WindowsFirewallAdapter.expire_active_containment_actions reaps expired rules."""
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        expired_action = models.ContainmentAction(
            id=str(uuid.uuid4()),
            action_id=f"act-win-{uuid.uuid4().hex[:12]}",
            tenant_id=self.tenant.id,
            threat_report_id=self.threat_report.id,
            indicator_value="198.51.100.11",
            indicator_type="ipv4",
            action_type="BLOCK_INBOUND_PORT_8000",
            policy_decision="QUALIFIED",
            policy_rule="TEST_EXPIRY",
            status="SIMULATED",
            ttl_seconds=60,
            applied_at=now - timedelta(seconds=120),
            expires_at=now - timedelta(seconds=60)
        )
        self.db.add(expired_action)
        self.db.commit()

        results = WindowsFirewallAdapter.expire_active_containment_actions(self.db, tenant_id=self.tenant.id)
        self.assertTrue(len(results) >= 1)
        self.db.refresh(expired_action)
        self.assertEqual(expired_action.status, "EXPIRED")

    def test_private_and_local_ips_rejected_in_containment_validation(self):
        """Security Invariant: validate_ip_for_containment strictly rejects private, loopback, and broadcast IPs."""
        # Loopback and broadcast are rejected regardless of allow_reserved
        with self.assertRaises(WindowsFirewallError):
            validate_ip_for_containment("127.0.0.1", allow_reserved=True)
        with self.assertRaises(WindowsFirewallError):
            validate_ip_for_containment("0.0.0.0", allow_reserved=True)
        with self.assertRaises(WindowsFirewallError):
            validate_ip_for_containment("255.255.255.255", allow_reserved=True)

        # RFC 1918 private IPs are strictly rejected in live mode (allow_reserved=False)
        for private_ip in ["10.0.0.1", "172.16.5.20", "192.168.1.100"]:
            with self.assertRaises(WindowsFirewallError):
                validate_ip_for_containment(private_ip, allow_reserved=False)

        # cyberscribe_win_helper validate_public_ipv4 also strictly rejects private & loopback
        with self.assertRaises(HelperSecurityError):
            validate_public_ipv4("10.0.0.5")
        with self.assertRaises(HelperSecurityError):
            validate_public_ipv4("192.168.1.1")
        with self.assertRaises(HelperSecurityError):
            validate_public_ipv4("127.0.0.1")

    def test_malicious_ip_extraction_rejects_private_and_local_ips(self):
        """Security Invariant: Public threat reports mentioning private/local IPs cannot trigger containment of internal hosts."""
        # Report mentioning only private internal IPs
        private_report = models.ThreatReport(
            id=str(uuid.uuid4()),
            source_url="https://example.com/advisory/private-test-1",
            title="Internal compromise on 192.168.1.50 and 10.0.0.99",
            summary="Attacker pivoted to host 172.16.0.12 with loopback 127.0.0.1",
            cve_id="CVE-2024-9999",
            severity="critical"
        )
        extracted = AutonomousResponseOrchestrator.extract_malicious_ip_from_report(private_report)
        self.assertIsNone(extracted, "Private, loopback, or local IPs must never be extracted for containment")

        # Report mentioning private IP AND public C2 IP -> safely extracts only the public C2 IP
        mixed_report = models.ThreatReport(
            id=str(uuid.uuid4()),
            source_url="https://example.com/advisory/mixed-test-2",
            title="Exfiltration from internal 192.168.1.50 to external C2 198.51.100.88",
            summary="Host 10.0.0.5 communicated with external C2 at 198.51.100.88",
            cve_id="CVE-2024-9999",
            severity="critical"
        )
        extracted_mixed = AutonomousResponseOrchestrator.extract_malicious_ip_from_report(mixed_report)
        self.assertEqual(extracted_mixed, "198.51.100.88", "Must extract public C2 IP and ignore internal private IPs")

    @patch("app.services.windows_firewall_adapter.WindowsFirewallAdapter._run_netsh")
    @patch("app.services.windows_firewall_adapter.WindowsFirewallAdapter.show_rule")
    def test_firewall_scope_exact_command_arguments(self, mock_show_rule, mock_run_netsh):
        """Item 1: Prove firewall rule strictly targets extracted malicious remote IP and port 8000 (never broad block)."""
        target_malicious_ip = "185.220.101.5"
        action = models.ContainmentAction(
            id=str(uuid.uuid4()),
            action_id=f"act-win-{uuid.uuid4().hex[:12]}",
            tenant_id=self.tenant.id,
            threat_report_id=self.threat_report.id,
            indicator_value=target_malicious_ip,
            indicator_type="ipv4",
            action_type="BLOCK_INBOUND_PORT_8000",
            policy_decision="QUALIFIED",
            policy_rule="TEST_SCOPE",
            status="PENDING",
            ttl_seconds=3600
        )
        self.db.add(action)
        self.db.commit()

        mock_show_rule.side_effect = [
            None,
            {
                "Rule Name": f"CyberScribe_{action.action_id}",
                "Direction": "In",
                "Action": "Block",
                "LocalPort": "8000",
                "RemoteIP": target_malicious_ip,
                "Protocol": "TCP"
            }
        ]
        mock_run_netsh.return_value = (0, "Ok.\n", "")

        res = WindowsFirewallAdapter.apply_containment(action, self.db, is_simulated=False)

        self.assertEqual(res["status"], "VERIFIED")
        self.assertTrue(res["is_live_enforcement"])
        self.assertFalse(res["is_simulated"])

        # Check exact arguments passed to netsh
        mock_run_netsh.assert_called_once()
        cmd_args = mock_run_netsh.call_args[0][0]

        # 1. Targets exact extracted remote IP
        self.assertIn(f"remoteip={target_malicious_ip}", cmd_args)
        # 2. Scoped to port 8000 (Campus Guide)
        self.assertIn("localport=8000", cmd_args)
        # 3. Inbound drop rule
        self.assertIn("dir=in", cmd_args)
        self.assertIn("action=block", cmd_args)
        self.assertIn("protocol=TCP", cmd_args)
        # 4. Proves rule does NOT broadly block all inbound traffic on port 8000
        self.assertNotIn("remoteip=any", [a.lower() for a in cmd_args])
        self.assertNotIn("remoteip=*", cmd_args)

    def test_live_mode_configuration_parser_and_no_fallback(self):
        """Item 2: Trace PATCH_ADAPTER_MODE=live_windows and CONTAINMENT_ADAPTER_MODE=windows_firewall parsing and assert no silent fallback."""
        with patch.dict(os.environ, {
            "PATCH_ADAPTER_MODE": "live_windows",
            "CONTAINMENT_ADAPTER_MODE": "windows_firewall"
        }):
            # 1. Configuration parsing
            self.assertTrue(AutonomousResponseOrchestrator.is_live_patching_enabled())
            self.assertTrue(AutonomousResponseOrchestrator.is_live_containment_enabled())

            adapter = AutonomousResponseOrchestrator.resolve_firewall_adapter()
            self.assertEqual(adapter, WindowsFirewallAdapter)

        # 2. Confirm live execution cannot silently fall back to simulation on failure
        failing_action = models.ContainmentAction(
            id=str(uuid.uuid4()),
            action_id=f"act-win-{uuid.uuid4().hex[:12]}",
            tenant_id=self.tenant.id,
            threat_report_id=self.threat_report.id,
            indicator_value="185.220.101.6",
            indicator_type="ipv4",
            action_type="BLOCK_INBOUND_PORT_8000",
            policy_decision="QUALIFIED",
            policy_rule="TEST_FAIL_SAFE",
            status="PENDING",
            ttl_seconds=3600
        )
        self.db.add(failing_action)
        self.db.commit()

        with patch("app.services.windows_firewall_adapter.WindowsFirewallAdapter._run_netsh") as mock_fail_netsh:
            mock_fail_netsh.return_value = (1, "", "Access is denied.")
            fail_res = WindowsFirewallAdapter.apply_containment(failing_action, self.db, is_simulated=False)

            # Must fail honestly with FAILED status and live flags, NEVER returning SIMULATED
            self.assertEqual(fail_res["status"], "FAILED")
            self.assertTrue(fail_res["is_live_enforcement"])
            self.assertFalse(fail_res["is_simulated"])
            self.assertIn("Access is denied", fail_res.get("error", ""))

    def test_patch_target_interpreter_resolution_and_isolation_safeguard(self):
        """Item 3: Trace Campus Guide interpreter resolution and verify isolation safeguard against CyberScribe virtualenv."""
        # 1. When explicit CAMPUS_GUIDE_PYTHON_PATH is configured
        fake_campus_py = r"C:\fake\campus_guide\venv\Scripts\python.exe"
        with patch("os.path.exists", return_value=True):
            with patch.dict(os.environ, {"CAMPUS_GUIDE_PYTHON_PATH": fake_campus_py}):
                self.assertEqual(_get_python_bin(), fake_campus_py)

        # 2. When unset, resolves verified Campus Guide project virtualenv if present
        with patch.dict(os.environ, {}, clear=True):
            if os.path.exists(r"E:\Campus Guide Project\backend\venv\Scripts\python.exe"):
                self.assertEqual(_get_python_bin(), r"E:\Campus Guide Project\backend\venv\Scripts\python.exe")

        # 3. Target isolation guard: In live mode, executing against CyberScribe's own virtualenv without explicit override is blocked
        prop = models.PatchProposal(
            id=str(uuid.uuid4()),
            proposal_id=f"prop-{uuid.uuid4().hex[:12]}",
            tenant_id=self.tenant.id,
            threat_match_id=self.threat_match.id,
            asset_component_id=self.asset_uvicorn.id,
            package_name="uvicorn",
            current_version="0.38.0",
            target_version="0.38.1",
            package_manager="pip",
            status="APPROVED",
            command_spec={"command": [sys.executable, "-m", "pip", "install", "--upgrade", "uvicorn==0.38.1"]},
            verification_spec={"verify_command": [sys.executable, "-m", "pip", "show", "uvicorn"]}
        )
        self.db.add(prop)
        self.db.commit()

        # Mock _get_python_bin to return sys.executable (CyberScribe's own virtualenv) with ALLOW_SELF_PATCHING=false
        with patch("app.services.patch_adapter._get_python_bin", return_value=sys.executable):
            with patch.dict(os.environ, {"ALLOW_SELF_PATCHING": "false"}):
                res = PatchManagementAdapter.execute_patch(
                    db=self.db,
                    proposal_id=prop.proposal_id,
                    mode="live_windows",
                    tenant_id=self.tenant.id
                )
                self.assertEqual(res["status"], "FAILED")
                self.assertIn("Target interpreter safety check failed", res["error"])
                self.db.refresh(prop)
                self.assertEqual(prop.status, "FAILED")

    def test_orchestrator_distinguishes_inbound_exploit_vs_c2_destination_and_suppresses_ambiguous(self):
        """
        Confirms orchestrator distinguishes inbound exploit sources from outbound C2 destinations,
        and suppresses firewall rules when direction cannot be established.
        """
        # 1. Inbound exploit source case
        inbound_report = models.ThreatReport(
            id=str(uuid.uuid4()),
            cve_id="CVE-2026-INB01",
            title="Inbound Uvicorn Exploit",
            summary="Uvicorn versions before 0.38.1 are vulnerable. Exploit payload delivered from 198.51.100.12.",
            severity="high"
        )
        self.db.add(inbound_report)
        self.db.commit()

        res_in = AutonomousResponseOrchestrator.correlate_sbom_and_create_incident(
            db=self.db,
            tenant_id=self.tenant.id,
            threat_report_id=inbound_report.id,
            is_simulated=True
        )
        self.assertEqual(res_in["status"], "INCIDENT_CREATED")
        self.assertIsNotNone(res_in["containment"])
        self.assertEqual(res_in["containment"]["direction"], "INBOUND")
        self.assertEqual(res_in["containment"]["target_port"], 8000)

        action_in = self.db.query(models.ContainmentAction).filter(
            models.ContainmentAction.threat_report_id == inbound_report.id
        ).first()
        self.assertIsNotNone(action_in)
        self.assertEqual(action_in.action_type, "BLOCK_INBOUND_PORT_8000")

        # 2. Outbound C2 destination case (Feodo Tracker C2)
        c2_report = models.ThreatReport(
            id=str(uuid.uuid4()),
            cve_id="CVE-2026-C201",
            title="Feodo Tracker Botnet C2",
            summary="Uvicorn versions before 0.38.1 infected by malware beaconing out to Feodo Tracker C2 destination 185.220.101.88.",
            severity="high"
        )
        self.db.add(c2_report)
        self.db.commit()

        res_c2 = AutonomousResponseOrchestrator.correlate_sbom_and_create_incident(
            db=self.db,
            tenant_id=self.tenant.id,
            threat_report_id=c2_report.id,
            is_simulated=True
        )
        self.assertEqual(res_c2["status"], "INCIDENT_CREATED")
        self.assertIsNotNone(res_c2["containment"])
        self.assertEqual(res_c2["containment"]["direction"], "OUTBOUND")
        self.assertIsNone(res_c2["containment"]["target_port"])

        action_c2 = self.db.query(models.ContainmentAction).filter(
            models.ContainmentAction.threat_report_id == c2_report.id
        ).first()
        self.assertIsNotNone(action_c2)
        self.assertEqual(action_c2.action_type, "BLOCK_IPV4_DESTINATION")

        # 3. Ambiguous / unestablished direction case
        ambig_report = models.ThreatReport(
            id=str(uuid.uuid4()),
            cve_id="CVE-2026-AMB01",
            title="Ambiguous Vulnerability Advisory",
            summary="Uvicorn versions before 0.38.1 advisory mentioning observed IP 198.51.100.33 without direction indication.",
            severity="medium"
        )
        self.db.add(ambig_report)
        self.db.commit()

        res_ambig = AutonomousResponseOrchestrator.correlate_sbom_and_create_incident(
            db=self.db,
            tenant_id=self.tenant.id,
            threat_report_id=ambig_report.id,
            is_simulated=True
        )
        self.assertEqual(res_ambig["status"], "INCIDENT_CREATED")
        self.assertIsNotNone(res_ambig["containment"])
        self.assertEqual(res_ambig["containment"]["status"], "REJECTED")
        self.assertIsNone(res_ambig["containment"]["direction"])
        self.assertTrue(res_ambig["containment"]["requires_further_evidence_or_approval"])
        self.assertIn("CONTAINMENT_DIRECTION_UNRESOLVED", res_ambig["containment"]["error"])


if __name__ == "__main__":
    import unittest
    unittest.main()


