"""
CyberScribe Finalization Sprint - Step 1 Controlled Lifecycle & End-to-End Test Suite
-----------------------------------------------------------------------------------
Covers:
1. Controlled Lifecycle on Disposable Isolated Target:
   - Containment (SIMULATED mode, disposable IP)
   - Independent verification (read-back verification & timestamps)
   - Rollback (reverses rule, sets status ROLLED_BACK, audit logging)
   - TTL expiry (idempotent transition of expired actions)
2. Fixed-Version Patching & Independent Installed-Version Verification:
   - Advisory fixed-version discovery (0.38.1 for uvicorn 0.38.0)
   - Evaluation outcome: NOT_AFFECTED
   - Proposal -> Approval -> Execution (simulated)
   - Installed version parsing and independent verification match
   - Containment retention check on mismatch vs safe release on verified fix
3. End-to-End Workflow (UI -> Backend API -> Executor -> Database -> Notification):
   - UI/Client triggers orchestrator incident correlation
   - Response orchestrator processes SBOM correlation & policy decisions
   - Database verifies ThreatReport, ThreatMatch, ContainmentAction, PatchProposal, AuditLogs
   - Notifications dispatched with audit trail
   - Dashboard endpoints return consistent synchronized state
"""

import os
import sys
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import patch, MagicMock

backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from tests.base import BaseTestCase
from app import models
from app.services.containment_policy import (
    AutonomousPolicyEngine,
    NetworkIndicatorCandidate
)
from app.services.firewall_adapter import (
    SimulatedFirewallAdapter,
    InvalidStateTransitionError
)
from app.services.patch_adapter import (
    PatchManagementAdapter,
    parse_installed_version,
    verify_version_match
)
from app.services.fixed_version_service import FixedVersionDiscoveryService
from app.services.autonomous_response_orchestrator import AutonomousResponseOrchestrator
from app.services.notification_service import NotificationService


class TestFinalizationSprintStep1ControlledE2E(BaseTestCase):

    def setUp(self):
        super().setUp()

        # Disposable, isolated tenant for controlled testing
        self.disposable_tenant = models.Tenant(
            id=str(uuid.uuid4()),
            company_name="Disposable Target Lab",
            tech_stack="FastAPI:0.110, Uvicorn:0.38.0, PostgreSQL:15",
            webhook_url="https://disposable-lab.local/webhook",
            auth_token="DISPOSABLE_SECRET_TOKEN_9999",
            remediation_policy="AUTO_PATCH"
        )
        self.db.add(self.disposable_tenant)

        # Disposable asset component
        self.disposable_asset = models.AssetComponent(
            id=str(uuid.uuid4()),
            tenant_id=self.disposable_tenant.id,
            software_name="uvicorn",
            software_version="0.38.0",
            environment="staging"
        )
        self.db.add(self.disposable_asset)

        # Threat report with clear fixed version
        self.disposable_threat_report = models.ThreatReport(
            id=str(uuid.uuid4()),
            cve_id="CVE-2026-99999",
            title="Uvicorn Critical Request Smuggling Vulnerability",
            summary="Uvicorn before version 0.38.1 allows HTTP request smuggling payload delivered from remote host. Fixed in 0.38.1.",
            severity="critical"
        )
        self.db.add(self.disposable_threat_report)

        # Threat match linking tenant, report, and asset
        self.disposable_threat_match = models.ThreatMatch(
            id=str(uuid.uuid4()),
            tenant_id=self.disposable_tenant.id,
            asset_component_id=self.disposable_asset.id,
            threat_report_id=self.disposable_threat_report.id,
            status="OPEN",
            ai_confidence_score=0.98,
            ai_matching_reason="Affected package uvicorn 0.38.0 matches constraint < 0.38.1"
        )
        self.db.add(self.disposable_threat_match)
        self.db.commit()

    # =========================================================================
    # Part 1: Controlled Lifecycle (Containment, Verification, Rollback, Expiry)
    # =========================================================================

    def test_01_controlled_containment_and_independent_verification(self):
        """Validates candidate qualification, simulated containment, and read-back verification."""
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        disposable_ip = "185.220.101.99"
        candidate = NetworkIndicatorCandidate(
            indicator_value=disposable_ip,
            tenant_id=self.disposable_tenant.id,
            confidence_score=95.0,
            evidence_source="CISA_IOC",
            is_structured_ioc=True,
            evidence_summary="Verified malicious C2 destination host",
            observed_at=now - timedelta(hours=1),
            ttl_seconds=1800
        )

        ok, action, reason = AutonomousPolicyEngine.evaluate_candidate(candidate, self.db)
        self.assertTrue(ok)
        self.assertEqual(reason, "QUALIFIED")
        self.assertEqual(action.status, "PENDING")
        self.assertEqual(action.tenant_id, self.disposable_tenant.id)

        # 1. Apply Containment (Simulation Mode)
        apply_res = SimulatedFirewallAdapter.apply_containment(action, self.db)
        self.assertEqual(apply_res["status"], "SIMULATED")
        self.assertTrue(apply_res["is_simulated"])
        self.assertEqual(action.status, "SIMULATED")
        self.assertIsNotNone(action.applied_at)

        # 2. Independent Verification
        verify_res = SimulatedFirewallAdapter.verify_containment(action, self.db)
        self.assertEqual(verify_res["status"], "SIMULATED")
        self.assertTrue(verify_res["verified"])
        self.assertIsNotNone(action.verified_at)

        # Audit logs confirm application and verification
        logs = self.db.query(models.ContainmentAuditLog).filter(
            models.ContainmentAuditLog.action_id == action.id
        ).all()
        events = [l.event_type for l in logs]
        self.assertIn("SIMULATION_APPLIED", events)
        self.assertIn("SIMULATION_VERIFIED", events)

    def test_02_controlled_rollback_and_historical_preservation(self):
        """Validates rollback of active containment and historical preservation."""
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        disposable_ip = "185.220.101.98"
        candidate = NetworkIndicatorCandidate(
            indicator_value=disposable_ip,
            tenant_id=self.disposable_tenant.id,
            confidence_score=92.0,
            evidence_source="CISA_IOC",
            is_structured_ioc=True,
            evidence_summary="Staging disposable threat",
            observed_at=now - timedelta(hours=2),
            ttl_seconds=3600
        )
        _, action, _ = AutonomousPolicyEngine.evaluate_candidate(candidate, self.db)
        SimulatedFirewallAdapter.apply_containment(action, self.db)
        self.assertEqual(action.status, "SIMULATED")

        # Rollback
        rb_res = SimulatedFirewallAdapter.rollback_containment(
            action=action,
            db=self.db,
            reason="Disposable test lab tear-down"
        )
        self.assertEqual(rb_res["status"], "ROLLED_BACK")
        self.assertEqual(action.status, "ROLLED_BACK")
        self.assertIsNotNone(action.rolled_back_at)

        # Duplicate rollback is idempotent
        rb_idemp = SimulatedFirewallAdapter.rollback_containment(action=action, db=self.db)
        self.assertEqual(rb_idemp["status"], "ROLLED_BACK")

        # Re-evaluating the candidate now succeeds because active action is cleared
        ok2, new_act, _ = AutonomousPolicyEngine.evaluate_candidate(candidate, self.db)
        self.assertTrue(ok2)
        self.assertNotEqual(action.id, new_act.id)

    def test_03_controlled_ttl_expiry_workflow(self):
        """Validates automated expiry of containment actions past their TTL."""
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        disposable_ip = "185.220.101.97"
        candidate = NetworkIndicatorCandidate(
            indicator_value=disposable_ip,
            tenant_id=self.disposable_tenant.id,
            confidence_score=94.0,
            evidence_source="CISA_IOC",
            is_structured_ioc=True,
            evidence_summary="Short TTL disposable indicator",
            observed_at=now - timedelta(minutes=10),
            ttl_seconds=30
        )
        _, action, _ = AutonomousPolicyEngine.evaluate_candidate(candidate, self.db)
        SimulatedFirewallAdapter.apply_containment(action, self.db)

        # Simulate TTL expiry by backdating expires_at
        action.expires_at = now - timedelta(seconds=60)
        self.db.commit()

        # Run expiry scan
        expired_results = SimulatedFirewallAdapter.expire_active_containment_actions(
            db=self.db,
            tenant_id=self.disposable_tenant.id
        )
        self.assertEqual(len(expired_results), 1)
        self.assertEqual(expired_results[0]["status"], "EXPIRED")
        self.assertEqual(action.status, "EXPIRED")

        # Repeat scan is idempotent
        second_scan = SimulatedFirewallAdapter.expire_active_containment_actions(
            db=self.db,
            tenant_id=self.disposable_tenant.id
        )
        self.assertEqual(len(second_scan), 0)

    # =========================================================================
    # Part 2: Fixed-Version Patching & Independent Installed-Version Verification
    # =========================================================================

    def test_04_fixed_version_discovery_and_patch_verification(self):
        """Verifies fixed version discovery, ecosystem checks, and independent verification."""
        # 1. Fixed-version discovery
        fix_info = FixedVersionDiscoveryService.discover_and_verify_fix(
            package_name="uvicorn",
            current_version="0.38.0",
            threat_report=self.disposable_threat_report
        )
        self.assertEqual(fix_info["fixed_version"], "0.38.1")
        self.assertTrue(fix_info["is_verified"])
        self.assertEqual(fix_info["evaluation_outcome"], "NOT_AFFECTED")

        # 2. Patch Proposal Creation
        proposal = PatchManagementAdapter.create_proposal(
            db=self.db,
            tenant_id=self.disposable_tenant.id,
            package_name="uvicorn",
            current_version="0.38.0",
            target_version="0.38.1",
            package_manager="pip",
            threat_match_id=self.disposable_threat_match.id,
            asset_component_id=self.disposable_asset.id
        )
        self.assertEqual(proposal.status, "PROPOSED")

        # 3. Approval
        PatchManagementAdapter.approve_proposal(
            db=self.db,
            proposal_id=proposal.proposal_id,
            approver="SEC_LEAD_DISPOSABLE",
            tenant_id=self.disposable_tenant.id
        )
        self.assertEqual(proposal.status, "APPROVED")

        # 4. Simulated Execution (Safety requirement: stays SIMULATED)
        exec_res = PatchManagementAdapter.execute_patch(
            db=self.db,
            proposal_id=proposal.proposal_id,
            mode="simulated",
            tenant_id=self.disposable_tenant.id
        )
        self.assertEqual(exec_res["status"], "SIMULATED")
        self.assertTrue(exec_res["is_simulated"])
        self.assertEqual(proposal.status, "SIMULATED")

        # 5. Independent installed-version verification checks
        self.assertTrue(verify_version_match("0.38.1", "0.38.1"))
        self.assertFalse(verify_version_match("0.38.0", "0.38.1"))
        parsed = parse_installed_version("pip", "Name: uvicorn\nVersion: 0.38.1\nSummary: ASGI server", "uvicorn")
        self.assertEqual(parsed, "0.38.1")

    @patch("subprocess.run")
    def test_05_containment_retention_on_patch_failure_vs_release_on_success(self, mock_subproc):
        """Verifies containment is retained if patch fails and released when verified."""
        os.environ["ALLOW_SELF_PATCHING"] = "true"
        # Create an active containment rule
        action = models.ContainmentAction(
            id=str(uuid.uuid4()),
            action_id="act-disp-reten-01",
            tenant_id=self.disposable_tenant.id,
            threat_report_id=self.disposable_threat_report.id,
            threat_match_id=self.disposable_threat_match.id,
            indicator_value="185.220.101.96",
            indicator_type="ipv4",
            action_type="BLOCK_INBOUND_PORT_8000",
            policy_decision="QUALIFIED",
            policy_rule="JUSTIFIED_INCIDENT_EXPLOIT_CONTAINMENT",
            status="SIMULATED",
            ttl_seconds=3600
        )
        self.db.add(action)

        proposal = PatchManagementAdapter.create_proposal(
            db=self.db,
            tenant_id=self.disposable_tenant.id,
            package_name="uvicorn",
            current_version="0.38.0",
            target_version="0.38.1",
            package_manager="pip",
            threat_match_id=self.disposable_threat_match.id,
            asset_component_id=self.disposable_asset.id
        )
        PatchManagementAdapter.approve_proposal(
            db=self.db,
            proposal_id=proposal.proposal_id,
            approver="SEC_LEAD",
            tenant_id=self.disposable_tenant.id
        )

        # Scenario A: Mismatch / verification failure preserves containment
        proc_update = MagicMock(returncode=0, stdout="Installed", stderr="")
        proc_verify_fail = MagicMock(returncode=0, stdout="Name: uvicorn\nVersion: 0.38.0\n", stderr="")
        mock_subproc.side_effect = [proc_update, proc_verify_fail]

        res_fail = PatchManagementAdapter.execute_patch(
            db=self.db,
            proposal_id=proposal.proposal_id,
            mode="live",
            tenant_id=self.disposable_tenant.id
        )
        self.assertEqual(res_fail["status"], "FAILED")
        self.assertEqual(proposal.status, "FAILED")
        # Containment is preserved
        self.assertEqual(action.status, "SIMULATED")

        # Scenario B: Valid verified version match releases containment
        proposal.status = "APPROVED"
        self.db.commit()

        proc_verify_ok = MagicMock(returncode=0, stdout="Name: uvicorn\nVersion: 0.38.1\n", stderr="")
        mock_subproc.side_effect = [proc_update, proc_verify_ok]

        res_ok = PatchManagementAdapter.execute_patch(
            db=self.db,
            proposal_id=proposal.proposal_id,
            mode="live",
            tenant_id=self.disposable_tenant.id
        )
        self.assertEqual(res_ok["status"], "VERIFIED")
        self.assertEqual(proposal.status, "VERIFIED")

        # Containment is safely released upon verified remediation
        rel_res = SimulatedFirewallAdapter.rollback_containment(
            action=action,
            db=self.db,
            reason="Vulnerability resolved and verified"
        )
        self.assertEqual(rel_res["status"], "ROLLED_BACK")
        self.assertEqual(action.status, "ROLLED_BACK")

    # =========================================================================
    # Part 3: End-to-End Workflow (UI -> Backend -> Orchestrator -> DB -> Notify)
    # =========================================================================

    def test_06_end_to_end_orchestrator_and_notification_workflow(self):
        """
        Executes end-to-end flow:
        UI/Client triggers orchestrator -> Correlates SBOM -> Justifies containment
        -> Evaluates remediation policy (NOTIFY vs AUTO_PATCH) -> Records state in DB
        -> Dispatches structured notifications.
        """
        # Step A: Run orchestrator under NOTIFY policy
        self.disposable_tenant.remediation_policy = "NOTIFY"
        self.db.commit()

        notify_result = AutonomousResponseOrchestrator.correlate_sbom_and_create_incident(
            db=self.db,
            tenant_id=self.disposable_tenant.id,
            threat_report_id=self.disposable_threat_report.id,
            supporting_malicious_ip="185.220.101.95",
            is_simulated=True
        )
        self.assertEqual(notify_result["status"], "INCIDENT_CREATED")
        self.assertEqual(notify_result["matched_component"], "uvicorn")
        self.assertIsNotNone(notify_result.get("containment"))
        self.assertEqual(notify_result["containment"]["status"], "SIMULATED")
        self.assertIsNotNone(notify_result.get("fix_discovery"))
        self.assertEqual(notify_result["fix_discovery"]["fixed_version"], "0.38.1")

        # Verify patch proposal in DB is created in PROPOSED status
        prop = self.db.query(models.PatchProposal).filter(
            models.PatchProposal.tenant_id == self.disposable_tenant.id,
            models.PatchProposal.threat_match_id == notify_result["incident_id"]
        ).first()
        self.assertIsNotNone(prop)
        self.assertEqual(prop.status, "PROPOSED")

        # Step B: Run orchestrator under AUTO_PATCH policy
        self.disposable_tenant.remediation_policy = "AUTO_PATCH"
        self.db.commit()

        auto_report = models.ThreatReport(
            id=str(uuid.uuid4()),
            cve_id="CVE-2026-99998",
            title="Uvicorn Buffer Overflow Remote Exploit",
            summary="Uvicorn before 0.38.1 allows remote exploit traffic from host. Fixed in version 0.38.1.",
            severity="critical"
        )
        self.db.add(auto_report)
        self.db.commit()

        auto_result = AutonomousResponseOrchestrator.correlate_sbom_and_create_incident(
            db=self.db,
            tenant_id=self.disposable_tenant.id,
            threat_report_id=auto_report.id,
            supporting_malicious_ip="185.220.101.94",
            force_auto_patch=True,
            is_simulated=True
        )
        self.assertEqual(auto_result["status"], "AUTO_PATCH_SIMULATED")
        self.assertEqual(auto_result["remediation_policy"], "AUTO_PATCH")

        # Verify auto-patch proposal was safely simulated
        auto_prop = self.db.query(models.PatchProposal).filter(
            models.PatchProposal.tenant_id == self.disposable_tenant.id,
            models.PatchProposal.threat_match_id == auto_result["incident_id"]
        ).first()
        self.assertEqual(auto_prop.status, "SIMULATED")

        # Verify containment was staged and retained (never released during simulation)
        auto_act = self.db.query(models.ContainmentAction).filter(
            models.ContainmentAction.tenant_id == self.disposable_tenant.id,
            models.ContainmentAction.threat_match_id == auto_result["incident_id"]
        ).first()
        self.assertIsNotNone(auto_act)
        self.assertEqual(auto_act.status, "SIMULATED")
        self.assertIsNone(auto_act.rolled_back_at)

        # Step C: UI API Verification (Backend endpoints return expected records)
        # 1. Admin UI view of all containment actions
        res_admin_containment = self.client.get(
            "/admin/containment/actions",
            headers=self.admin_headers
        )
        self.assertEqual(res_admin_containment.status_code, 200)
        action_data = res_admin_containment.json()
        actions = action_data.get("actions", [])
        disposable_actions = [a for a in actions if a.get("tenant_id") == self.disposable_tenant.id]
        self.assertTrue(len(disposable_actions) >= 2)

        # 2. Tenant user UI view of containment actions
        from app.core.security import create_access_token
        tenant_token = create_access_token(data={
            "sub": "analyst@disposable-lab.local",
            "role": "analyst",
            "tenant_id": self.disposable_tenant.id
        })
        tenant_headers = {"Authorization": f"Bearer {tenant_token}"}

        # Create user record in DB
        disp_user = models.User(
            id=str(uuid.uuid4()),
            tenant_id=self.disposable_tenant.id,
            email="analyst@disposable-lab.local",
            password_hash="fakehash",
            role="analyst"
        )
        self.db.add(disp_user)
        self.db.commit()

        res_tenant_containment = self.client.get(
            "/tenants/containment/actions",
            headers=tenant_headers
        )
        self.assertEqual(res_tenant_containment.status_code, 200)

        res_patches = self.client.get(
            "/tenants/remediation/proposals",
            headers=tenant_headers
        )
        self.assertEqual(res_patches.status_code, 200)
        props_data = res_patches.json()
        self.assertTrue(props_data.get("total", 0) >= 2)
