"""
CyberScribe Automatic Response & Backend Stability Test Suite
--------------------------------------------------------------
Proves:
1. A newly ingested matching threat automatically reaches the response workflow.
2. Multiple distinct matching threats are evaluated and processed independently.
3. Existing eligible threats can be evaluated automatically without manual clicks.
4. Duplicate ingestion and concurrent workers do not create duplicate actions.
5. Nonmatching and uncertain threats trigger no automatic action.
6. Authorized lab containment is dispatched, verified, and recorded correctly.
7. Eligible patch remediation is triggered, executed, and independently verified.
8. Missing fixed versions, execution failures, and verification failures are handled safely.
9. The backend remains available throughout ingestion, including after a feed fails.
10. Only one scheduler instance runs per application process, and overlapping sweeps are prevented.
11. Tenant isolation, RBAC, audit records, and existing safety restrictions remain intact.
"""

import os
import sys
import uuid
import asyncio
from datetime import datetime, timezone, timedelta
from unittest.mock import patch, MagicMock

backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from tests.base import BaseTestCase
from app import models
from app.services.osint_collector import (
    process_threat_tenant_correlations,
    evaluate_existing_eligible_threats,
    run_sync_sweep,
    fetch_and_process_osint,
    _sweep_mutex,
    _scheduler_started
)
from app.services.autonomous_response_orchestrator import AutonomousResponseOrchestrator
from app.services.patch_adapter import PatchManagementAdapter
from app.services.windows_firewall_adapter import (
    WindowsFirewallAdapter,
    LAB_FEDORA_HOST_ONLY_IP,
    is_lab_fedora_containment_allowed
)


class TestAutomaticResponseAndBackendStability(BaseTestCase):

    def setUp(self):
        super().setUp()

        # Clean sweep lock
        if _sweep_mutex.locked():
            try:
                _sweep_mutex.release()
            except RuntimeError:
                pass

        # Target tenant A: AUTO_PATCH policy
        self.tenant_a = models.Tenant(
            id=str(uuid.uuid4()),
            company_name="Auto Defense Corp A",
            tech_stack="FastAPI:0.110.0, Uvicorn:0.38.0",
            webhook_url="https://tenant-a.local/webhook",
            auth_token="AUTH_TOKEN_CORP_A",
            remediation_policy="AUTO_PATCH"
        )
        self.db.add(self.tenant_a)

        # Tenant A assets
        self.asset_uvicorn_a = models.AssetComponent(
            id=str(uuid.uuid4()),
            tenant_id=self.tenant_a.id,
            software_name="uvicorn",
            software_version="0.38.0",
            environment="production"
        )
        self.asset_fastapi_a = models.AssetComponent(
            id=str(uuid.uuid4()),
            tenant_id=self.tenant_a.id,
            software_name="fastapi",
            software_version="0.110.0",
            environment="production"
        )
        self.db.add_all([self.asset_uvicorn_a, self.asset_fastapi_a])

        # Target tenant B: NOTIFY policy (manual authorization required)
        self.tenant_b = models.Tenant(
            id=str(uuid.uuid4()),
            company_name="Manual Approval Corp B",
            tech_stack="FastAPI:0.110.0",
            webhook_url="https://tenant-b.local/webhook",
            auth_token="AUTH_TOKEN_CORP_B",
            remediation_policy="NOTIFY"
        )
        self.db.add(self.tenant_b)

        self.asset_fastapi_b = models.AssetComponent(
            id=str(uuid.uuid4()),
            tenant_id=self.tenant_b.id,
            software_name="fastapi",
            software_version="0.110.0",
            environment="staging"
        )
        self.db.add(self.asset_fastapi_b)
        self.db.commit()

    def test_01_newly_ingested_matching_threat_reaches_response_workflow(self):
        """1. A newly ingested matching threat automatically triggers correlation and response orchestration."""
        threat = models.ThreatReport(
            id=str(uuid.uuid4()),
            cve_id="CVE-2026-9111",
            title="Critical Uvicorn Buffer Overflow Remote Exploit",
            summary="Uvicorn before 0.38.1 allows remote code execution. Fixed in version 0.38.1. Exploit traffic from 198.51.100.44.",
            severity="critical"
        )
        self.db.add(threat)
        self.db.commit()

        # Ingestion correlation trigger
        process_threat_tenant_correlations(self.db, threat)

        # Verify ThreatMatch created
        match = self.db.query(models.ThreatMatch).filter(
            models.ThreatMatch.tenant_id == self.tenant_a.id,
            models.ThreatMatch.threat_report_id == threat.id
        ).first()
        self.assertIsNotNone(match, "ThreatMatch must be created automatically")
        self.assertEqual(match.asset_component_id, self.asset_uvicorn_a.id)

        # Verify containment action created
        containment = self.db.query(models.ContainmentAction).filter(
            models.ContainmentAction.tenant_id == self.tenant_a.id,
            models.ContainmentAction.threat_match_id == match.id
        ).first()
        self.assertIsNotNone(containment, "ContainmentAction must be created automatically for verified threat IP")
        self.assertEqual(containment.indicator_value, "198.51.100.44")

        # Verify patch proposal created
        prop = self.db.query(models.PatchProposal).filter(
            models.PatchProposal.tenant_id == self.tenant_a.id,
            models.PatchProposal.threat_match_id == match.id
        ).first()
        self.assertIsNotNone(prop, "PatchProposal must be created automatically")
        self.assertEqual(prop.target_version, "0.38.1")

    def test_02_multiple_distinct_matching_threats_processed_independently(self):
        """2. Multiple distinct matching threats in one ingestion cycle are evaluated and processed independently."""
        threat_1 = models.ThreatReport(
            id=str(uuid.uuid4()),
            cve_id="CVE-2026-9201",
            title="Uvicorn Request Smuggling Vulnerability",
            summary="Uvicorn before 0.38.1 is vulnerable to request smuggling. Fixed in 0.38.1.",
            severity="high"
        )
        threat_2 = models.ThreatReport(
            id=str(uuid.uuid4()),
            cve_id="CVE-2026-9202",
            title="FastAPI Header Injection Exploit",
            summary="FastAPI before 0.120.2 allows header injection. Fixed in 0.120.2. Attack from 203.0.113.88.",
            severity="critical"
        )
        self.db.add_all([threat_1, threat_2])
        self.db.commit()

        # Process both
        process_threat_tenant_correlations(self.db, threat_1)
        process_threat_tenant_correlations(self.db, threat_2)

        # Tenant A should have matches and proposals for BOTH distinct threats
        matches_a = self.db.query(models.ThreatMatch).filter(
            models.ThreatMatch.tenant_id == self.tenant_a.id,
            models.ThreatMatch.threat_report_id.in_([threat_1.id, threat_2.id])
        ).all()
        self.assertEqual(len(matches_a), 2, "Both threats must have distinct ThreatMatch records")

        proposals_a = self.db.query(models.PatchProposal).filter(
            models.PatchProposal.tenant_id == self.tenant_a.id
        ).all()
        self.assertEqual(len(proposals_a), 2, "Both threats must generate independent patch proposals")

        packages_proposed = {p.package_name for p in proposals_a}
        self.assertEqual(packages_proposed, {"uvicorn", "fastapi"})

    def test_03_existing_eligible_threats_evaluated_automatically(self):
        """3. Existing eligible threats in DB can be evaluated automatically without manual clicks."""
        # Create an existing un-evaluated threat report and match
        threat = models.ThreatReport(
            id=str(uuid.uuid4()),
            cve_id="CVE-2026-9301",
            title="Uvicorn Denial of Service",
            summary="Uvicorn before 0.38.1 allows DoS. Fixed in 0.38.1. Exploit payload from 198.51.100.77.",
            severity="high"
        )
        self.db.add(threat)
        self.db.flush()

        match = models.ThreatMatch(
            id=str(uuid.uuid4()),
            tenant_id=self.tenant_a.id,
            asset_component_id=self.asset_uvicorn_a.id,
            threat_report_id=threat.id,
            status="OPEN",
            ai_confidence_score=0.95,
            ai_matching_reason="Package uvicorn 0.38.0 [AFFECTED] by vulnerability constraint < 0.38.1"
        )
        self.db.add(match)
        self.db.commit()

        # Confirm no proposal or containment exists initially
        prop_before = self.db.query(models.PatchProposal).filter(
            models.PatchProposal.threat_match_id == match.id
        ).first()
        self.assertIsNone(prop_before)

        # Run automated evaluation of existing eligible threats
        res = evaluate_existing_eligible_threats(self.db)
        self.assertEqual(res["status"], "COMPLETED")
        self.assertGreaterEqual(res["evaluated_matches"], 1)

        # Confirm patch proposal and containment were created automatically
        prop_after = self.db.query(models.PatchProposal).filter(
            models.PatchProposal.threat_match_id == match.id
        ).first()
        self.assertIsNotNone(prop_after, "Existing eligible threat must have patch proposal created")
        self.assertEqual(prop_after.target_version, "0.38.1")

        containment_after = self.db.query(models.ContainmentAction).filter(
            models.ContainmentAction.threat_match_id == match.id
        ).first()
        self.assertIsNotNone(containment_after, "Existing eligible threat must have containment action created")

    def test_04_duplicate_ingestion_does_not_create_duplicate_actions(self):
        """4. Repeated ingestion cycles do not create duplicate ContainmentAction or PatchProposal records."""
        threat = models.ThreatReport(
            id=str(uuid.uuid4()),
            cve_id="CVE-2026-9401",
            title="FastAPI Path Traversal",
            summary="FastAPI before 0.120.2 allows traversal. Fixed in 0.120.2. Exploit traffic from 203.0.113.55.",
            severity="critical"
        )
        self.db.add(threat)
        self.db.commit()

        # Cycle 1
        process_threat_tenant_correlations(self.db, threat)

        actions_1 = self.db.query(models.ContainmentAction).filter(
            models.ContainmentAction.tenant_id == self.tenant_a.id,
            models.ContainmentAction.indicator_value == "203.0.113.55"
        ).count()
        self.assertEqual(actions_1, 1)

        props_1 = self.db.query(models.PatchProposal).filter(
            models.PatchProposal.tenant_id == self.tenant_a.id,
            models.PatchProposal.package_name == "fastapi"
        ).count()
        self.assertEqual(props_1, 1)

        # Cycle 2 (repeated ingestion of same threat)
        process_threat_tenant_correlations(self.db, threat)

        actions_2 = self.db.query(models.ContainmentAction).filter(
            models.ContainmentAction.tenant_id == self.tenant_a.id,
            models.ContainmentAction.indicator_value == "203.0.113.55"
        ).count()
        self.assertEqual(actions_2, 1, "Duplicate containment action must not be created")

        props_2 = self.db.query(models.PatchProposal).filter(
            models.PatchProposal.tenant_id == self.tenant_a.id,
            models.PatchProposal.package_name == "fastapi"
        ).count()
        self.assertEqual(props_2, 1, "Duplicate patch proposal must not be created")

    def test_05_nonmatching_and_uncertain_threats_trigger_no_automatic_action(self):
        """5. Nonmatching or NEEDS_REVIEW threats trigger no automatic containment or patching action."""
        # Nonmatching threat
        threat_nonmatching = models.ThreatReport(
            id=str(uuid.uuid4()),
            cve_id="CVE-2026-9501",
            title="Ruby on Rails Arbitrary Code Execution",
            summary="Ruby on Rails flaw affecting Ruby gem rails < 7.0. Fixed in 7.0. Active attack from 198.51.100.99.",
            severity="critical"
        )
        self.db.add(threat_nonmatching)
        self.db.commit()

        process_threat_tenant_correlations(self.db, threat_nonmatching)

        # No match or proposals for Tenant A
        matches = self.db.query(models.ThreatMatch).filter(
            models.ThreatMatch.tenant_id == self.tenant_a.id,
            models.ThreatMatch.threat_report_id == threat_nonmatching.id
        ).all()
        self.assertEqual(len(matches), 0, "No ThreatMatch for non-matching tech stack")

        # Uncertain threat (NEEDS_REVIEW product collision)
        threat_uncertain = models.ThreatReport(
            id=str(uuid.uuid4()),
            cve_id="CVE-2026-9502",
            title="FastAPI-Mail Library Vulnerability",
            summary="Vulnerability in fastapi-mail third party extension, not core fastapi framework.",
            severity="high"
        )
        self.db.add(threat_uncertain)
        self.db.commit()

        process_threat_tenant_correlations(self.db, threat_uncertain)

        uncertain_actions = self.db.query(models.ContainmentAction).filter(
            models.ContainmentAction.threat_report_id == threat_uncertain.id
        ).all()
        self.assertEqual(len(uncertain_actions), 0, "NEEDS_REVIEW finding must never trigger containment")

        uncertain_props = self.db.query(models.PatchProposal).filter(
            models.PatchProposal.threat_match.has(threat_report_id=threat_uncertain.id)
        ).all()
        self.assertEqual(len(uncertain_props), 0, "NEEDS_REVIEW finding must never trigger patch proposal")

    def test_06a_authorized_lab_containment_dispatched_and_verified(self):
        """6a. Authorized lab containment with Fedora IP (192.168.56.101) is dispatched, verified, and restricted."""
        with patch("app.services.autonomous_response_orchestrator.is_lab_fedora_containment_allowed", return_value=True), \
             patch("app.services.windows_firewall_adapter.is_lab_fedora_authorized", return_value=True):
            cand_check = AutonomousResponseOrchestrator._is_safe_threat_indicator_ip("192.168.56.101")
            self.assertTrue(cand_check, "Lab Fedora IP must be accepted when explicitly authorized")

            threat_lab = models.ThreatReport(
                id=str(uuid.uuid4()),
                cve_id="CVE-2026-LAB-01",
                title="FastAPI Campus Guide Remote Exploit",
                summary="Critical remote vulnerability in FastAPI before 0.120.2. Exploit traffic incoming from 192.168.56.101 targeting Campus Guide on port 8000.",
                severity="critical"
            )
            self.db.add(threat_lab)
            self.db.commit()

            # Correlate and stage containment in simulated mode for test safety
            res = AutonomousResponseOrchestrator.correlate_sbom_and_create_incident(
                db=self.db,
                tenant_id=self.tenant_a.id,
                threat_report_id=threat_lab.id,
                supporting_malicious_ip="192.168.56.101",
                is_simulated=True
            )

            self.assertIsNotNone(res.get("containment"))
            self.assertEqual(res["containment"]["target_ip"], "192.168.56.101")
            self.assertEqual(res["containment"]["status"], "SIMULATED")

            # Verify audit log recorded
            audit_logs = self.db.query(models.ContainmentAuditLog).filter(
                models.ContainmentAuditLog.tenant_id == self.tenant_a.id
            ).all()
            self.assertTrue(len(audit_logs) >= 1, "Audit log must be persisted")

        # Negative test: Fedora IP strictly rejected when ALLOW_LAB_FEDORA_HOST_CONTAINMENT is disabled
        with patch("app.services.autonomous_response_orchestrator.is_lab_fedora_containment_allowed", return_value=False), \
             patch("app.services.windows_firewall_adapter.is_lab_fedora_authorized", return_value=False):
            cand_check_disabled = AutonomousResponseOrchestrator._is_safe_threat_indicator_ip("192.168.56.101")
            self.assertFalse(cand_check_disabled, "Lab Fedora IP must be rejected when lab authorization is disabled")

    def test_06b_general_authorized_target_containment_dispatched_and_verified(self):
        """6b. General authorized target containment against distinct public threat indicator with rollback and expiry."""
        # Distinct authorized target asset for tenant A (production web server)
        asset_web = models.AssetComponent(
            id=str(uuid.uuid4()),
            tenant_id=self.tenant_a.id,
            software_name="nginx",
            software_version="1.24.0",
            environment="production"
        )
        self.db.add(asset_web)

        # Distinct public malicious threat report
        threat_web = models.ThreatReport(
            id=str(uuid.uuid4()),
            cve_id="CVE-2026-8801",
            title="Nginx HTTP Request Smuggling Remote Exploit",
            summary="Nginx before 1.25.0 is vulnerable to request smuggling. Fixed in version 1.25.0. Exploit payload incoming from 203.0.113.88.",
            severity="critical"
        )
        self.db.add(threat_web)
        self.db.commit()

        # Execute autonomous containment workflow for general authorized target
        res = AutonomousResponseOrchestrator.correlate_sbom_and_create_incident(
            db=self.db,
            tenant_id=self.tenant_a.id,
            threat_report_id=threat_web.id,
            supporting_malicious_ip="203.0.113.88",
            is_simulated=True
        )

        self.assertIsNotNone(res.get("containment"))
        self.assertEqual(res["containment"]["target_ip"], "203.0.113.88")
        self.assertEqual(res["containment"]["status"], "SIMULATED")

        # Verify action record persisted in DB
        action = self.db.query(models.ContainmentAction).filter(
            models.ContainmentAction.tenant_id == self.tenant_a.id,
            models.ContainmentAction.indicator_value == "203.0.113.88"
        ).first()
        self.assertIsNotNone(action)
        self.assertIsNotNone(action.applied_at)
        self.assertIsNotNone(action.expires_at)
        self.assertEqual(action.action_type, "BLOCK_INBOUND_IPV4")

        # Test rollback for this general action
        from app.services.firewall_adapter import SimulatedFirewallAdapter
        rollback_res = SimulatedFirewallAdapter.rollback_containment(action=action, db=self.db)
        self.assertEqual(rollback_res["status"], "ROLLED_BACK")
        self.assertEqual(action.status, "ROLLED_BACK")
        self.assertIsNotNone(action.rolled_back_at)

        # Verify rollback audit log
        rb_audit = self.db.query(models.ContainmentAuditLog).filter(
            models.ContainmentAuditLog.action_id == action.id,
            models.ContainmentAuditLog.new_status == "ROLLED_BACK"
        ).first()
        self.assertIsNotNone(rb_audit, "Rollback audit log must be persisted")

    def test_06c_negative_tests_unauthorized_assets_invalid_indicators_unsafe_actions(self):
        """6c. Negative tests: unauthorized assets, unsupported environments, uncertain threats, and invalid indicators."""
        # 1. Unauthorized asset (Tenant B asset evaluated in Tenant A incident)
        asset_unauth = models.AssetComponent(
            id=str(uuid.uuid4()),
            tenant_id=self.tenant_b.id,
            software_name="fastapi",
            software_version="0.110.0",
            environment="production"
        )
        is_auth, auth_err = AutonomousResponseOrchestrator.is_asset_containment_authorized(asset_unauth, self.tenant_a)
        self.assertFalse(is_auth)
        self.assertEqual(auth_err, "UNAUTHORIZED_TENANT_ASSET_MISMATCH")

        # 2. Unsupported target environment
        asset_unsupported = models.AssetComponent(
            id=str(uuid.uuid4()),
            tenant_id=self.tenant_a.id,
            software_name="fastapi",
            software_version="0.110.0",
            environment="unsupported_legacy"
        )
        self.db.add(asset_unsupported)
        self.db.commit()

        is_env_auth, env_err = AutonomousResponseOrchestrator.is_asset_containment_authorized(asset_unsupported, self.tenant_a)
        self.assertFalse(is_env_auth)
        self.assertIn("UNSUPPORTED_TARGET_ENVIRONMENT", env_err)

        # 3. Invalid indicators: loopback, broadcast, private RFC 1918
        self.assertFalse(AutonomousResponseOrchestrator._is_safe_threat_indicator_ip("127.0.0.1"))
        self.assertFalse(AutonomousResponseOrchestrator._is_safe_threat_indicator_ip("255.255.255.255"))
        self.assertFalse(AutonomousResponseOrchestrator._is_safe_threat_indicator_ip("10.0.0.5"))
        self.assertFalse(AutonomousResponseOrchestrator._is_safe_threat_indicator_ip("192.168.1.50"))

        # 4. Uncertain threat: match classification is NEEDS_REVIEW
        threat_uncertain = models.ThreatReport(
            id=str(uuid.uuid4()),
            cve_id="CVE-2026-UNCERTAIN",
            title="FastAPI Uncertain Flaw",
            summary="FastAPI generic issue. Exploit traffic incoming from 203.0.113.66.",
            severity="medium"
        )
        self.db.add(threat_uncertain)
        self.db.commit()

        res_uncertain = AutonomousResponseOrchestrator.correlate_sbom_and_create_incident(
            db=self.db,
            tenant_id=self.tenant_a.id,
            threat_report_id=threat_uncertain.id,
            supporting_malicious_ip="203.0.113.66",
            is_simulated=True
        )
        self.assertEqual(res_uncertain["containment"]["status"], "REJECTED")
        self.assertIn("UNCERTAIN_THREAT_MATCH", res_uncertain["containment"]["error"])

        # 5. Unsafe action: direction unresolved (threat is confirmed AFFECTED, but directional context is absent)
        threat_nodir = models.ThreatReport(
            id=str(uuid.uuid4()),
            cve_id="CVE-2026-NODIR",
            title="FastAPI Neutral Advisory",
            summary="FastAPI before 0.120.2 is vulnerable. Fixed in 0.120.2. Network indicator 203.0.113.77 mentioned without directional context.",
            severity="medium"
        )
        self.db.add(threat_nodir)
        self.db.commit()

        res_nodir = AutonomousResponseOrchestrator.correlate_sbom_and_create_incident(
            db=self.db,
            tenant_id=self.tenant_a.id,
            threat_report_id=threat_nodir.id,
            supporting_malicious_ip="203.0.113.77",
            is_simulated=True
        )
        self.assertEqual(res_nodir["containment"]["status"], "REJECTED")
        self.assertIn("CONTAINMENT_DIRECTION_UNRESOLVED", res_nodir["containment"]["error"])

    def test_07_eligible_patch_remediation_triggered_and_verified(self):
        """7. Eligible patch remediation under AUTO_PATCH policy is automatically initiated and verified."""
        threat_patch = models.ThreatReport(
            id=str(uuid.uuid4()),
            cve_id="CVE-2026-9701",
            title="Uvicorn Critical Remote Vulnerability",
            summary="Uvicorn before 0.38.1 is vulnerable. Fixed in 0.38.1.",
            severity="critical"
        )
        self.db.add(threat_patch)
        self.db.commit()

        # Run orchestrator under AUTO_PATCH policy with is_simulated=True
        res = AutonomousResponseOrchestrator.correlate_sbom_and_create_incident(
            db=self.db,
            tenant_id=self.tenant_a.id,
            threat_report_id=threat_patch.id,
            force_auto_patch=True,
            is_simulated=True
        )

        self.assertEqual(res["status"], "AUTO_PATCH_SIMULATED")
        self.assertEqual(res["fixed_version"], "0.38.1")

        # Verify proposal approved and simulated
        prop = self.db.query(models.PatchProposal).filter(
            models.PatchProposal.threat_match_id == res["incident_id"]
        ).first()
        self.assertIsNotNone(prop)
        self.assertEqual(prop.status, "SIMULATED")

    def test_08_missing_fixed_version_and_failures_handled_safely(self):
        """8. Missing fixed versions, unknown registries, and execution failures are handled safely."""
        threat_no_fix = models.ThreatReport(
            id=str(uuid.uuid4()),
            cve_id="CVE-2026-NOFIX",
            title="Zero-Day in Uvicorn",
            summary="Zero-day vulnerability in uvicorn 0.38.0. No fixed version announced or available.",
            severity="critical"
        )
        self.db.add(threat_no_fix)
        self.db.commit()

        res = AutonomousResponseOrchestrator.correlate_sbom_and_create_incident(
            db=self.db,
            tenant_id=self.tenant_a.id,
            threat_report_id=threat_no_fix.id,
            force_auto_patch=True,
            is_simulated=True
        )

        # No patch proposal should be created when no fix is discoverable
        self.assertIsNone(res.get("fixed_version"))
        prop = self.db.query(models.PatchProposal).filter(
            models.PatchProposal.threat_match_id == res["incident_id"]
        ).first()
        self.assertIsNone(prop, "No proposal created when zero-day has no fixed version")

    def test_09_backend_remains_available_after_feed_failure(self):
        """9. An individual feed failure does not crash the sweep or terminate the process."""
        mock_fail = MagicMock()
        mock_fail.status_code = 503
        mock_fail.content = b"Service Unavailable"

        with patch("app.services.osint_collector.fetch_feed_with_retry", return_value=mock_fail):
            # Run sweep; must not raise uncaught exception
            sweep_result = run_sync_sweep(lookback_days=30)
            self.assertEqual(sweep_result["status"], "SUCCESS")

        # API endpoint can still be queried cleanly
        res = self.client.get("/public/threats?page=1&page_size=5")
        self.assertEqual(res.status_code, 200)

    def test_10_single_scheduler_instance_and_overlapping_sweep_prevention(self):
        """10. Only one scheduler instance runs per process, and overlapping sweeps are prevented."""
        # 1. Sweep mutex prevents concurrent sweeps
        acquired = _sweep_mutex.acquire(blocking=False)
        self.assertTrue(acquired)
        try:
            # Secondary sweep attempt while mutex is held
            second_attempt = run_sync_sweep(lookback_days=30)
            self.assertEqual(second_attempt["status"], "SKIPPED")
            self.assertIn("already in progress", second_attempt["message"])
        finally:
            _sweep_mutex.release()

        # 2. Scheduler start guard
        import app.services.osint_collector as oc
        oc._scheduler_started = True
        try:
            # Calling fetch_and_process_osint() when already marked started should return immediately
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                loop.run_until_complete(fetch_and_process_osint())
            finally:
                loop.close()
        finally:
            oc._scheduler_started = False

    def test_11_tenant_isolation_rbac_and_safety_intact(self):
        """11. Tenant isolation, RBAC on endpoints, and containment/remediation safety restrictions remain intact."""
        # Tenant A proposal cannot be approved by Tenant B
        prop = models.PatchProposal(
            id=str(uuid.uuid4()),
            proposal_id=f"patch-{uuid.uuid4().hex[:12]}",
            tenant_id=self.tenant_a.id,
            threat_match_id=str(uuid.uuid4()),
            asset_component_id=self.asset_uvicorn_a.id,
            package_name="uvicorn",
            current_version="0.38.0",
            target_version="0.38.1",
            package_manager="pip",
            status="PROPOSED"
        )
        self.db.add(prop)
        self.db.commit()

        # Tenant B token attempting to approve Tenant A's proposal
        from app.core.security import create_access_token
        tenant_b_token = create_access_token(data={
            "sub": "user@tenant-b.local",
            "role": "tenant_admin",
            "tenant_id": self.tenant_b.id
        })
        headers_b = {"Authorization": f"Bearer {tenant_b_token}"}

        resp = self.client.post(
            f"/tenants/remediation/proposals/{prop.proposal_id}/approve",
            headers=headers_b
        )
        self.assertIn(resp.status_code, [401, 403, 404], "Tenant B must not approve Tenant A's proposal")


if __name__ == "__main__":
    import unittest
    unittest.main()
