"""
CyberScribe Live Lab End-to-End Execution and Real Verification Test Suite
--------------------------------------------------------------------------
Demonstrates genuine, non-mocked operations against the dedicated disposable lab target:
Target Environment: E:\\cyber threat agent copy\\cyber_threat_agent_project\\lab_target_env
Target Python:      E:\\cyber threat agent copy\\cyber_threat_agent_project\\lab_target_env\\Scripts\\python.exe

Covers all 8 live-lab verification requirements:
 A. Controlled qualifying threat correlated to authorized lab target.
 B. Policy engine evaluates policy and selects appropriate action.
 C. Real firewall execution: invokes real netsh.exe; truthfully records actual enforcement state.
 D. Real package patch execution: runs real pip subprocess, upgrades package, verifies via pip show.
 E. Database statuses, audit records, and notifications match actual outcomes.
 F. Duplicate events do not create repeated actions; unauthorized tenants cannot execute.
 G. Failed execution or verification never produces false success status.
 H. Cleanup restores disposable lab environment to documented baseline.
"""

import os
import sys
import uuid
import subprocess
from datetime import datetime, timezone
from unittest.mock import patch

backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from tests.base import BaseTestCase
from app import models
from app.models import ContainmentAction, PatchProposal, ThreatMatch, ThreatReport, AssetComponent, PatchAuditLog, ContainmentAuditLog
from app.services.autonomous_response_orchestrator import AutonomousResponseOrchestrator
from app.services.patch_adapter import PatchManagementAdapter, PatchSecurityError, PatchStateError
from app.services.windows_firewall_adapter import WindowsFirewallAdapter, WindowsFirewallError


LAB_TARGET_ENV = os.path.abspath(os.path.join(backend_dir, "..", "lab_target_env"))
LAB_PYTHON_BIN = os.path.join(LAB_TARGET_ENV, "Scripts", "python.exe")


class TestLiveLabAutomaticExecution(BaseTestCase):
    """
    Live lab test suite executing real operating system and filesystem actions
    against the dedicated disposable target environment.
    """

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        if not os.path.exists(LAB_PYTHON_BIN):
            raise RuntimeError(
                f"Dedicated disposable lab environment missing at {LAB_PYTHON_BIN}. "
                "Initialize with 'python -m venv lab_target_env' and pip install colorama==0.4.5."
            )

    def setUp(self):
        super().setUp()
        self.orig_target_py = os.environ.get("TARGET_PYTHON_PATH")
        self.orig_allow_self = os.environ.get("ALLOW_SELF_PATCHING")
        self.orig_patch_mode = os.environ.get("PATCH_ADAPTER_MODE")
        self.orig_contain_mode = os.environ.get("CONTAINMENT_ADAPTER_MODE")
        self.orig_exec_url = os.environ.get("WINDOWS_EXECUTOR_URL")

        # Configure real target environment pointing to dedicated disposable lab
        os.environ["TARGET_PYTHON_PATH"] = LAB_PYTHON_BIN
        os.environ["ALLOW_SELF_PATCHING"] = "false"
        os.environ["PATCH_ADAPTER_MODE"] = "live_windows"
        os.environ["CONTAINMENT_ADAPTER_MODE"] = "windows_firewall"
        os.environ["WINDOWS_EXECUTOR_URL"] = ""

        # Reset disposable lab package to baseline colorama==0.4.5
        self._reset_disposable_env_baseline()

        # Seed demonstration tenant with AUTO_PATCH policy
        self.lab_tenant = models.Tenant(
            id=str(uuid.uuid4()),
            company_name="CyberScribe Live Lab Demonstration Tenant",
            tech_stack="Python:3.13, colorama:0.4.5, FastAPI:0.120.1",
            remediation_policy="AUTO_PATCH",
            subscription_status="active"
        )
        self.db.add(self.lab_tenant)

        # Standard tenant with default NOTIFY policy
        self.standard_tenant = models.Tenant(
            id=str(uuid.uuid4()),
            company_name="Standard Production Tenant",
            tech_stack="Python:3.13, colorama:0.4.5",
            remediation_policy="NOTIFY",
            subscription_status="active"
        )
        self.db.add(self.standard_tenant)

        # Target asset component in lab tenant
        self.lab_asset = models.AssetComponent(
            id=str(uuid.uuid4()),
            tenant_id=self.lab_tenant.id,
            software_name="colorama",
            software_version="0.4.5",
            environment="disposable_lab"
        )
        self.db.add(self.lab_asset)

        # Standard asset component in standard tenant
        self.standard_asset = models.AssetComponent(
            id=str(uuid.uuid4()),
            tenant_id=self.standard_tenant.id,
            software_name="colorama",
            software_version="0.4.5",
            environment="production"
        )
        self.db.add(self.standard_asset)

        self.db.commit()

    def tearDown(self):
        # Restore environment variables
        if self.orig_target_py is not None:
            os.environ["TARGET_PYTHON_PATH"] = self.orig_target_py
        else:
            os.environ.pop("TARGET_PYTHON_PATH", None)

        if self.orig_allow_self is not None:
            os.environ["ALLOW_SELF_PATCHING"] = self.orig_allow_self
        else:
            os.environ.pop("ALLOW_SELF_PATCHING", None)

        if self.orig_patch_mode is not None:
            os.environ["PATCH_ADAPTER_MODE"] = self.orig_patch_mode
        else:
            os.environ.pop("PATCH_ADAPTER_MODE", None)

        if self.orig_contain_mode is not None:
            os.environ["CONTAINMENT_ADAPTER_MODE"] = self.orig_contain_mode
        else:
            os.environ.pop("CONTAINMENT_ADAPTER_MODE", None)

        if self.orig_exec_url is not None:
            os.environ["WINDOWS_EXECUTOR_URL"] = self.orig_exec_url
        else:
            os.environ.pop("WINDOWS_EXECUTOR_URL", None)

        # Reset disposable lab environment back to baseline
        self._reset_disposable_env_baseline()
        super().tearDown()

    def _reset_disposable_env_baseline(self):
        """Restores colorama==0.4.5 on the dedicated disposable lab target."""
        proc = subprocess.run(
            [LAB_PYTHON_BIN, "-m", "pip", "install", "--quiet", "colorama==0.4.5"],
            capture_output=True,
            text=True
        )
        if proc.returncode != 0:
            raise RuntimeError(f"Failed to reset disposable lab baseline: {proc.stderr}")

    def _get_live_package_version(self, pkg_name: str = "colorama") -> str:
        """Independently queries the real installed version using pip show."""
        proc = subprocess.run(
            [LAB_PYTHON_BIN, "-m", "pip", "show", pkg_name],
            capture_output=True,
            text=True
        )
        for line in proc.stdout.splitlines():
            if line.startswith("Version:"):
                return line.split(":", 1)[1].strip()
        return ""

    # =========================================================================
    # Requirement A & B: Threat Ingestion, Asset Correlation & Policy Evaluation
    # =========================================================================
    def test_live_01_controlled_threat_correlation_and_policy_selection(self):
        """
        Ingests a controlled qualifying threat and confirms SBOM correlation and
        policy selection without human approval clicks.
        """
        report = models.ThreatReport(
            id=str(uuid.uuid4()),
            cve_id="CVE-2026-7001",
            title="Colorama ANSI Stream Corruption Exploit",
            summary="Colorama before 0.4.6 is vulnerable to stream corruption. Fixed in 0.4.6. Exploit traffic from 185.220.101.5.",
            severity="critical",
            stix_bundle={}
        )
        self.db.add(report)
        self.db.commit()

        # Initial baseline check
        self.assertEqual(self._get_live_package_version("colorama"), "0.4.5")

        result = AutonomousResponseOrchestrator.correlate_sbom_and_create_incident(
            db=self.db,
            tenant_id=self.lab_tenant.id,
            threat_report_id=report.id,
            supporting_malicious_ip="185.220.101.5",
            is_simulated=False
        )

        self.assertIsNotNone(result)
        self.assertEqual(result.get("remediation_policy"), "AUTO_PATCH")
        self.assertEqual(result.get("matched_component"), "colorama")
        self.assertEqual(result.get("fixed_version"), "0.4.6")

    # =========================================================================
    # Requirement C: Real Firewall Execution & Truthful Observation
    # =========================================================================
    def test_live_02_real_firewall_execution_observes_system_state_truthfully(self):
        """
        Executes real netsh.exe against Windows Defender Firewall.
        Observes real returncode and system error; proves that without elevation,
        it fails closed with 'requires elevation' and persists FAILED in DB.
        """
        action = ContainmentAction(
            id=str(uuid.uuid4()),
            action_id=f"act-win-live-{uuid.uuid4().hex[:8]}",
            tenant_id=self.lab_tenant.id,
            indicator_value="185.220.101.5",
            indicator_type="ipv4",
            action_type="BLOCK_INBOUND_PORT_8000",
            policy_decision="QUALIFIED",
            policy_rule="LIVE_LAB_CONTAINMENT_RULE",
            status="PENDING",
            ttl_seconds=3600
        )
        self.db.add(action)
        self.db.commit()

        # Verify rule does not exist prior to execution
        readback_before = WindowsFirewallAdapter.show_rule(f"CyberScribe_{action.action_id}")
        self.assertIsNone(readback_before)

        # Execute real adapter against the Windows host
        res = WindowsFirewallAdapter.apply_containment(action, self.db, is_simulated=False)

        self.db.refresh(action)
        # Without Administrator elevation, netsh truthfully returns exit code 1
        self.assertEqual(res["status"], "FAILED")
        self.assertEqual(action.status, "FAILED")
        self.assertIn("requires elevation", action.error_message.lower())

        # Read back Windows Defender Firewall state to prove rule was NOT created
        readback_after = WindowsFirewallAdapter.show_rule(f"CyberScribe_{action.action_id}")
        self.assertIsNone(readback_after)

    def test_live_02b_real_firewall_automatic_pipeline_execution_and_rollback(self):
        """
        Executes CyberScribe's complete automatic containment pipeline end-to-end:
        Threat Ingestion -> Threat-Tenant Correlation -> Policy Evaluation ->
        Automatic Containment Dispatch -> Authenticated Windows Executor Daemon ->
        Independent netsh.exe Query -> Supported Rollback -> Verification.
        """
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1.0)
        is_daemon_up = (sock.connect_ex(("127.0.0.1", 8089)) == 0)
        sock.close()
        if not is_daemon_up:
            self.skipTest("Windows Executor Daemon not running on 127.0.0.1:8089")

        from app.services.osint_collector import process_threat_tenant_correlations

        # Configure environment for live daemon execution
        orig_exec_url = os.environ.get("WINDOWS_EXECUTOR_URL")
        orig_exec_token = os.environ.get("WINDOWS_EXECUTOR_TOKEN")
        orig_auth_ips = os.environ.get("AUTHORIZED_PRIVATE_CONTAINMENT_IPS")
        orig_patch_mode = os.environ.get("PATCH_ADAPTER_MODE")
        orig_email_enabled = os.environ.get("EMAIL_NOTIFICATIONS_ENABLED")
        if hasattr(self, "mock_soar_patcher"):
            self.mock_soar_patcher.stop()

        os.environ["WINDOWS_EXECUTOR_URL"] = "http://127.0.0.1:8089"
        os.environ["WINDOWS_EXECUTOR_TOKEN"] = "cyberscribe_win_executor_secret_token_2026"
        os.environ["AUTHORIZED_PRIVATE_CONTAINMENT_IPS"] = "192.0.2.10"
        os.environ["PATCH_ADAPTER_MODE"] = "simulated"
        os.environ["EMAIL_NOTIFICATIONS_ENABLED"] = "false"

        test_ip = "192.0.2.10"
        dedicated_tenant = models.Tenant(
            id=str(uuid.uuid4()),
            company_name=f"Dedicated Live Lab Tenant {uuid.uuid4().hex[:6]}",
            tech_stack="uvicorn:0.25.0",
            remediation_policy="NOTIFY",
            subscription_status="active"
        )
        self.db.add(dedicated_tenant)

        dedicated_asset = models.AssetComponent(
            id=str(uuid.uuid4()),
            tenant_id=dedicated_tenant.id,
            software_name="uvicorn",
            software_version="0.25.0",
            environment="disposable_lab"
        )
        self.db.add(dedicated_asset)

        threat = models.ThreatReport(
            id=str(uuid.uuid4()),
            cve_id="CVE-2026-99902",
            title="Uvicorn Automated Containment Pipeline Advisory",
            summary=f"Uvicorn before 0.30.0 is vulnerable to remote exploit. Exploit traffic from {test_ip}. Fixed in 0.30.0.",
            severity="critical",
            stix_bundle={}
        )
        self.db.add(threat)
        self.db.commit()

        rule_name = None
        try:
            # 1. Trigger normal ingestion/correlation workflow (no manual action clicks)
            with patch("app.services.email_notification_service.EmailNotificationService.send_email_notification", return_value={"status": "SUPPRESSED", "delivered": False}):
                process_threat_tenant_correlations(self.db, threat)

            # 2. Verify orchestrator automatically created and executed containment action
            action = self.db.query(ContainmentAction).filter(
                ContainmentAction.tenant_id == dedicated_tenant.id,
                ContainmentAction.indicator_value == test_ip
            ).first()

            self.assertIsNotNone(action, "ContainmentAction was not created automatically!")
            self.assertEqual(action.status, "VERIFIED")
            self.assertEqual(action.action_type, "BLOCK_INBOUND_PORT_8000")
            self.assertEqual(action.policy_decision, "QUALIFIED")

            rule_name = f"CyberScribe_{action.action_id}"

            # 3. Independently query Windows Defender Firewall via netsh.exe
            netsh_cmd = ["netsh.exe", "advfirewall", "firewall", "show", "rule", f"name={rule_name}"]
            proc_check = subprocess.run(netsh_cmd, capture_output=True, text=True, shell=False)
            self.assertEqual(proc_check.returncode, 0, f"netsh returned non-zero exit code: {proc_check.stderr}")
            self.assertIn("Enabled:                              Yes", proc_check.stdout)
            self.assertIn("Action:                               Block", proc_check.stdout)
            self.assertIn(f"RemoteIP:                             {test_ip}/32", proc_check.stdout)
            self.assertIn("LocalPort:                            8000", proc_check.stdout)

            # 4. Verify persisted audit records
            audit_logs = self.db.query(ContainmentAuditLog).filter(
                ContainmentAuditLog.tenant_id == dedicated_tenant.id
            ).all()
            event_types = [l.event_type for l in audit_logs]
            self.assertIn("WINDOWS_FIREWALL_APPLIED_AND_VERIFIED", event_types)

            # 5. Remove test rule through supported rollback mechanism
            rollback_res = WindowsFirewallAdapter.rollback_containment(
                action=action,
                db=self.db,
                actor="TEST_LIVE_PIPELINE_CLEANUP"
            )
            self.assertEqual(rollback_res["status"], "ROLLED_BACK")
            self.db.refresh(action)
            self.assertEqual(action.status, "ROLLED_BACK")

            # 6. Independently confirm removal via netsh.exe
            proc_post = subprocess.run(netsh_cmd, capture_output=True, text=True, shell=False)
            self.assertNotEqual(proc_post.returncode, 0)
            self.assertIn("No rules match the specified criteria", proc_post.stdout)

            # 7. Verify history remains available post-cleanup
            self.db.refresh(action)
            self.assertEqual(action.status, "ROLLED_BACK")
            post_audits = self.db.query(ContainmentAuditLog).filter(
                ContainmentAuditLog.tenant_id == dedicated_tenant.id
            ).all()
            self.assertTrue(any(l.event_type == "WINDOWS_FIREWALL_ROLLED_BACK" for l in post_audits))

        finally:
            # Cleanup firewall rule if anything failed
            if rule_name:
                subprocess.run(
                    ["netsh.exe", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"],
                    capture_output=True,
                    shell=False
                )
            # Restore environment variables
            if orig_exec_url is not None:
                os.environ["WINDOWS_EXECUTOR_URL"] = orig_exec_url
            else:
                os.environ.pop("WINDOWS_EXECUTOR_URL", None)

            if orig_exec_token is not None:
                os.environ["WINDOWS_EXECUTOR_TOKEN"] = orig_exec_token
            else:
                os.environ.pop("WINDOWS_EXECUTOR_TOKEN", None)

            if orig_auth_ips is not None:
                os.environ["AUTHORIZED_PRIVATE_CONTAINMENT_IPS"] = orig_auth_ips
            else:
                os.environ.pop("AUTHORIZED_PRIVATE_CONTAINMENT_IPS", None)

            if orig_patch_mode is not None:
                os.environ["PATCH_ADAPTER_MODE"] = orig_patch_mode
            else:
                os.environ.pop("PATCH_ADAPTER_MODE", None)

            if orig_email_enabled is not None:
                os.environ["EMAIL_NOTIFICATIONS_ENABLED"] = orig_email_enabled
            else:
                os.environ.pop("EMAIL_NOTIFICATIONS_ENABLED", None)

            if hasattr(self, "mock_soar_patcher"):
                self.mock_soar_patcher.start()


    # =========================================================================
    # Requirement D: Real Package Patch Execution & Independent Version Check
    # =========================================================================
    def test_live_03_real_package_patch_execution_and_independent_readback(self):
        """
        Executes a real pip upgrade process against the disposable lab target.
        Verifies version transition from 0.4.5 to 0.4.6 independently.
        """
        # Step 1: Prove baseline version before patch
        self.assertEqual(self._get_live_package_version("colorama"), "0.4.5")

        proposal = PatchManagementAdapter.create_proposal(
            db=self.db,
            tenant_id=self.lab_tenant.id,
            package_name="colorama",
            current_version="0.4.5",
            target_version="0.4.6",
            package_manager="pip"
        )
        self.assertEqual(proposal.status, "PROPOSED")

        PatchManagementAdapter.approve_proposal(
            db=self.db,
            proposal_id=proposal.proposal_id,
            approver="LIVE_LAB_TEST_HARNESS"
        )
        self.assertEqual(proposal.status, "APPROVED")

        # Step 2: Execute real patch command against lab_target_env
        exec_res = PatchManagementAdapter.execute_patch(
            db=self.db,
            proposal_id=proposal.proposal_id,
            mode="live"
        )

        self.assertEqual(exec_res["status"], "VERIFIED")
        self.assertFalse(exec_res["is_simulated"])

        # Step 3: Independent verification directly via subprocess pip show
        real_version = self._get_live_package_version("colorama")
        self.assertEqual(real_version, "0.4.6")

        # Step 4: Verify DB persistence
        self.db.refresh(proposal)
        self.assertEqual(proposal.status, "VERIFIED")
        self.assertIsNotNone(proposal.verified_at)
        self.assertIsNotNone(proposal.applied_at)
        self.assertIn("Successfully installed colorama-0.4.6", proposal.execution_output)

    # =========================================================================
    # Requirement E: Persisted Audit Records Match Real Outcomes
    # =========================================================================
    def test_live_04_audit_records_match_real_execution_outcomes(self):
        """
        Confirms non-repudiation audit logs are recorded for real execution events.
        """
        proposal = PatchManagementAdapter.create_proposal(
            db=self.db,
            tenant_id=self.lab_tenant.id,
            package_name="colorama",
            current_version="0.4.5",
            target_version="0.4.6",
            package_manager="pip"
        )
        PatchManagementAdapter.approve_proposal(self.db, proposal.proposal_id, approver="TEST_AUDITOR")
        PatchManagementAdapter.execute_patch(self.db, proposal.proposal_id, mode="live")

        audit_logs = self.db.query(PatchAuditLog).filter(
            PatchAuditLog.proposal_id == proposal.id
        ).all()

        event_types = [log.event_type for log in audit_logs]
        self.assertIn("PROPOSAL_CREATED", event_types)
        self.assertIn("PROPOSAL_APPROVED", event_types)
        self.assertIn("PATCH_VERIFIED", event_types)

    # =========================================================================
    # Requirement F: Deduplication & Tenant Isolation
    # =========================================================================
    def test_live_05_duplicate_prevention_and_tenant_isolation(self):
        """
        Confirms duplicate patch operations are prevented and standard NOTIFY
        tenants are never automatically patched without human approval.
        """
        # 1. Standard tenant with NOTIFY policy cannot auto-patch
        standard_report = models.ThreatReport(
            id=str(uuid.uuid4()),
            cve_id="CVE-2026-7002",
            title="Colorama Standard Tenant Advisory",
            summary="Colorama before 0.4.6 has a flaw. Fixed in 0.4.6.",
            severity="critical",
            stix_bundle={}
        )
        self.db.add(standard_report)
        self.db.commit()

        notify_res = AutonomousResponseOrchestrator.correlate_sbom_and_create_incident(
            db=self.db,
            tenant_id=self.standard_tenant.id,
            threat_report_id=standard_report.id,
            is_simulated=False
        )

        self.assertEqual(notify_res["status"], "INCIDENT_CREATED")
        prop = self.db.query(PatchProposal).filter(
            PatchProposal.threat_match_id == notify_res["incident_id"]
        ).first()
        self.assertIsNotNone(prop)
        # Remained in PROPOSED status; never auto-approved
        self.assertEqual(prop.status, "PROPOSED")

        # 2. Duplicate proposal creation returns the existing proposal
        duplicate_prop = PatchManagementAdapter.create_proposal(
            db=self.db,
            tenant_id=self.standard_tenant.id,
            threat_match_id=notify_res["incident_id"],
            package_name="colorama",
            current_version="0.4.5",
            target_version="0.4.6",
            package_manager="pip"
        )
        self.assertEqual(duplicate_prop.proposal_id, prop.proposal_id)

    # =========================================================================
    # Requirement G: Missing or Unsafe Target Fails Closed
    # =========================================================================
    def test_live_06_missing_target_prevents_patch_and_never_claims_success(self):
        """
        Pointing TARGET_PYTHON_PATH to a non-existent binary fails closed with
        FAILED status and never claims success.
        """
        proposal = PatchManagementAdapter.create_proposal(
            db=self.db,
            tenant_id=self.lab_tenant.id,
            package_name="colorama",
            current_version="0.4.5",
            target_version="0.4.6",
            package_manager="pip"
        )
        PatchManagementAdapter.approve_proposal(self.db, proposal.proposal_id, approver="TEST_ADMIN")

        with patch.dict(os.environ, {"TARGET_PYTHON_PATH": r"E:\non_existent_path\python.exe"}):
            exec_res = PatchManagementAdapter.execute_patch(
                db=self.db,
                proposal_id=proposal.proposal_id,
                mode="live"
            )

            self.assertEqual(exec_res["status"], "FAILED")
            self.db.refresh(proposal)
            self.assertEqual(proposal.status, "FAILED")
            self.assertIn("does not exist", proposal.error_message)

    # =========================================================================
    # Requirement H: Full End-to-End Workflow with Complete Cleanup
    # =========================================================================
    def test_live_07_full_end_to_end_workflow_and_baseline_restoration(self):
        """
        Demonstrates the complete automatic lifecycle end-to-end:
        Threat Ingested -> SBOM Correlated -> AUTO_PATCH Approved -> Real Pip Upgrade
        -> Independent Readback -> Incident Resolved -> Cleanup Restores Baseline.
        """
        report = models.ThreatReport(
            id=str(uuid.uuid4()),
            cve_id="CVE-2026-7003",
            title="Colorama Complete Lifecycle Advisory",
            summary="Colorama before 0.4.6 allows remote code execution. Fixed in 0.4.6. Exploit traffic from 185.220.101.5.",
            severity="critical",
            stix_bundle={}
        )
        self.db.add(report)
        self.db.commit()

        # Step 1: Prove baseline before workflow
        self.assertEqual(self._get_live_package_version("colorama"), "0.4.5")

        # Step 2: Trigger orchestrator under AUTO_PATCH
        flow_result = AutonomousResponseOrchestrator.correlate_sbom_and_create_incident(
            db=self.db,
            tenant_id=self.lab_tenant.id,
            threat_report_id=report.id,
            supporting_malicious_ip="185.220.101.5",
            is_simulated=False
        )

        self.assertEqual(flow_result["status"], "AUTO_PATCHED_AND_RESOLVED")

        # Step 3: Verify real package upgrade via independent subprocess
        self.assertEqual(self._get_live_package_version("colorama"), "0.4.6")

        # Step 4: Verify incident was marked RESOLVED
        match = self.db.query(ThreatMatch).filter(ThreatMatch.id == flow_result["incident_id"]).first()
        self.assertEqual(match.status, "RESOLVED")

        # Step 5: Verify asset version updated in DB
        self.db.refresh(self.lab_asset)
        self.assertEqual(self.lab_asset.software_version, "0.4.6")

        # Step 6: Verify cleanup restores baseline
        self._reset_disposable_env_baseline()
        self.assertEqual(self._get_live_package_version("colorama"), "0.4.5")
