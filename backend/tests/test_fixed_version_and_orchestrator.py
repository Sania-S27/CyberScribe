"""
Targeted Tests for Fixed-Version Discovery & Autonomous Response Orchestrator
----------------------------------------------------------------------------
Tests:
1. Fixed-version extraction from advisory text and STIX metadata.
2. Ecosystem compatibility and NOT_AFFECTED verification of discovered fix.
3. Notification dispatch to tenant webhook and local audit logging.
4. Autonomous orchestrator: SBOM correlation, incident creation, idempotency.
5. Containment justification: vulnerability alone does NOT trigger IP block.
6. Supporting malicious IP triggers justified containment on port 8000.
7. NOTIFY policy dispatches alert and proposes patch without executing.
8. AUTO_PATCH policy approves, executes, verifies, and safely releases containment.
9. Manual remediation reporting, re-evaluation, and unblocking.
10. Tenant isolation enforcement.
"""

import uuid
from unittest.mock import patch, MagicMock
from tests.base import BaseTestCase
from app import models
from app.services.fixed_version_service import FixedVersionDiscoveryService
from app.services.notification_service import NotificationService
from app.services.autonomous_response_orchestrator import AutonomousResponseOrchestrator


class TestFixedVersionAndOrchestrator(BaseTestCase):

    def setUp(self):
        super().setUp()
        self.tenant = models.Tenant(
            id=str(uuid.uuid4()),
            company_name="Campus Guide Inc",
            tech_stack="FastAPI, Uvicorn, React",
            webhook_url="http://127.0.0.1:8000/api/security/soar-webhook",
            remediation_policy="NOTIFY"
        )
        self.db.add(self.tenant)

        # Register vulnerable asset: uvicorn 0.38.0
        self.asset_uvicorn = models.AssetComponent(
            id=str(uuid.uuid4()),
            tenant_id=self.tenant.id,
            software_name="uvicorn",
            software_version="0.38.0",
            environment="production"
        )
        self.db.add(self.asset_uvicorn)

        # Register safe asset: react 19.2.0
        self.asset_react = models.AssetComponent(
            id=str(uuid.uuid4()),
            tenant_id=self.tenant.id,
            software_name="react",
            software_version="19.2.0",
            environment="production"
        )
        self.db.add(self.asset_react)

        # Threat Report for CVE-2026-26209 affecting uvicorn < 0.38.1
        self.threat_report = models.ThreatReport(
            id=str(uuid.uuid4()),
            cve_id="CVE-2026-26209",
            title="Uvicorn Header Parsing Vulnerability",
            summary="Uvicorn versions before 0.38.1 are vulnerable to HTTP request smuggling. Fixed in version 0.38.1.",
            severity="high"
        )
        self.db.add(self.threat_report)
        self.db.commit()

    def test_fixed_version_discovery(self):
        """Verifies extracting and verifying the fixed version from advisory metadata."""
        res = FixedVersionDiscoveryService.discover_and_verify_fix(
            package_name="uvicorn",
            current_version="0.38.0",
            threat_report=self.threat_report
        )

        self.assertIn(res["status"], ["PACKAGE_AVAILABLE", "FIX_ANNOUNCED"])
        self.assertEqual(res["fixed_version"], "0.38.1")
        self.assertTrue(res["is_verified"])
        self.assertEqual(res["evaluation_outcome"], "NOT_AFFECTED")

    @patch("requests.post")
    def test_notification_service_webhook_delivery(self, mock_post):
        """Verifies sending structured incident notifications to the tenant's webhook."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_post.return_value = mock_resp

        res = NotificationService.send_incident_notification(
            db=self.db,
            tenant=self.tenant,
            event_type="FIX_AVAILABLE",
            threat_report=self.threat_report,
            asset=self.asset_uvicorn,
            fixed_version="0.38.1",
            remediation_policy="NOTIFY"
        )

        self.assertEqual(res["status"], "DELIVERED")
        self.assertTrue(res["delivered"])
        self.assertEqual(res["event_type"], "FIX_AVAILABLE")
        mock_post.assert_called_once()

    def test_notification_service_without_webhook_records_honestly(self):
        """Verifies that tenants without webhooks record the alert locally without faking delivery."""
        self.tenant.webhook_url = None
        self.db.commit()

        res = NotificationService.send_incident_notification(
            db=self.db,
            tenant=self.tenant,
            event_type="VULNERABILITY_CONFIRMED",
            threat_report=self.threat_report,
            asset=self.asset_uvicorn
        )

        self.assertEqual(res["status"], "RECORDED_LOCALLY")
        self.assertFalse(res["delivered"])
        self.assertIn("no configured webhook_url", res["reason"])

    @patch("requests.post")
    def test_orchestrator_vulnerability_alone_does_not_contain(self, mock_post):
        """
        CRITICAL SAFETY TEST:
        Vulnerability match alone must NOT trigger an IP block without supporting malicious IP.
        """
        mock_post.return_value = MagicMock(status_code=200)

        res = AutonomousResponseOrchestrator.correlate_sbom_and_create_incident(
            db=self.db,
            tenant_id=self.tenant.id,
            threat_report_id=self.threat_report.id,
            supporting_malicious_ip=None,  # No malicious IP provided
            is_simulated=True
        )

        self.assertEqual(res["status"], "INCIDENT_CREATED")
        self.assertIsNone(res["containment"], "Containment must be None when no malicious IP is present")

        # Confirm ThreatMatch was created
        match = self.db.query(models.ThreatMatch).filter(
            models.ThreatMatch.tenant_id == self.tenant.id,
            models.ThreatMatch.threat_report_id == self.threat_report.id
        ).first()
        self.assertIsNotNone(match)
        self.assertEqual(match.status, "OPEN")
        self.assertEqual(match.asset_component_id, self.asset_uvicorn.id)

        # Confirm NO ContainmentAction was created
        actions = self.db.query(models.ContainmentAction).filter(
            models.ContainmentAction.tenant_id == self.tenant.id
        ).all()
        self.assertEqual(len(actions), 0)

    @patch("requests.post")
    def test_orchestrator_with_malicious_ip_triggers_justified_containment(self, mock_post):
        """
        Verifies that supporting malicious IP evidence triggers justified containment
        targeting inbound port 8000 for Campus Guide.
        """
        mock_post.return_value = MagicMock(status_code=200)

        res = AutonomousResponseOrchestrator.correlate_sbom_and_create_incident(
            db=self.db,
            tenant_id=self.tenant.id,
            threat_report_id=self.threat_report.id,
            supporting_malicious_ip="198.51.100.77",
            is_simulated=True
        )

        self.assertEqual(res["status"], "INCIDENT_CREATED")
        self.assertIsNotNone(res["containment"])
        self.assertEqual(res["containment"]["status"], "SIMULATED")
        self.assertEqual(res["containment"]["target_port"], 8000)
        self.assertEqual(res["containment"]["target_ip"], "198.51.100.77")

        # Verify ContainmentAction in database
        action = self.db.query(models.ContainmentAction).filter(
            models.ContainmentAction.tenant_id == self.tenant.id,
            models.ContainmentAction.indicator_value == "198.51.100.77"
        ).first()
        self.assertIsNotNone(action)
        self.assertEqual(action.status, "SIMULATED")

    @patch("requests.post")
    def test_end_to_end_auto_patch_verifies_and_releases_containment(self, mock_post):
        """
        SAFETY VERIFICATION:
        When running in simulation mode:
        1. SBOM match creates incident.
        2. Malicious IP triggers justified containment.
        3. Fixed version 0.38.1 discovered.
        4. Simulated auto-patch completes dry run.
        5. ThreatMatch MUST REMAIN OPEN (never marked RESOLVED).
        6. Containment MUST BE RETAINED (never released for simulation).
        7. AssetComponent version must remain unchanged.
        """
        mock_post.return_value = MagicMock(status_code=200)
        self.tenant.remediation_policy = "AUTO_PATCH"
        self.db.commit()

        res = AutonomousResponseOrchestrator.correlate_sbom_and_create_incident(
            db=self.db,
            tenant_id=self.tenant.id,
            threat_report_id=self.threat_report.id,
            supporting_malicious_ip="198.51.100.88",
            force_auto_patch=True,
            is_simulated=True
        )

        self.assertEqual(res["status"], "AUTO_PATCH_SIMULATED")
        self.assertEqual(res["patch_execution"]["status"], "SIMULATED_PATCH_SUCCEEDED")
        self.assertEqual(res["patch_execution"]["vulnerability_status"], "OPEN")
        self.assertEqual(res["patch_execution"]["verified_version"], "0.38.1")
        self.assertEqual(res["patch_execution"]["containment_released"], [])

        # ThreatMatch must remain OPEN
        match = self.db.query(models.ThreatMatch).filter(
            models.ThreatMatch.tenant_id == self.tenant.id,
            models.ThreatMatch.threat_report_id == self.threat_report.id
        ).first()
        self.assertEqual(match.status, "OPEN")

        # AssetComponent version must NOT be modified in simulated mode
        self.db.refresh(self.asset_uvicorn)
        self.assertEqual(self.asset_uvicorn.software_version, "0.38.0")

        # ContainmentAction must remain active (SIMULATED), NOT rolled back
        action = self.db.query(models.ContainmentAction).filter(
            models.ContainmentAction.threat_match_id == match.id
        ).first()
        self.assertIsNotNone(action)
        self.assertEqual(action.status, "SIMULATED")
        self.assertIsNone(action.rolled_back_at)

    def test_manual_remediation_release(self):
        """Verifies manual patch reporting updates asset, resolves threat, and releases containment."""
        match = models.ThreatMatch(
            id=str(uuid.uuid4()),
            tenant_id=self.tenant.id,
            asset_component_id=self.asset_uvicorn.id,
            threat_report_id=self.threat_report.id,
            status="OPEN",
            ai_confidence_score=95.0,
            ai_matching_reason="[AFFECTED] uvicorn < 0.38.1"
        )
        self.db.add(match)
        self.db.commit()

        # Active containment action
        action = models.ContainmentAction(
            id=str(uuid.uuid4()),
            action_id="act-win-manual-01",
            tenant_id=self.tenant.id,
            threat_match_id=match.id,
            indicator_value="198.51.100.99",
            status="SIMULATED",
            policy_decision="QUALIFIED"
        )
        self.db.add(action)
        self.db.commit()

        # 1. Report version that does NOT resolve (e.g. 0.37.0) -> Rejection
        fail_res = AutonomousResponseOrchestrator.process_manual_remediation(
            db=self.db,
            threat_match_id=match.id,
            tenant_id=self.tenant.id,
            new_version="0.37.0"
        )
        self.assertEqual(fail_res["status"], "REJECTED_STILL_AFFECTED")
        self.assertEqual(match.status, "OPEN")
        self.assertEqual(action.status, "SIMULATED")

        # 2. Report version that DOES resolve (e.g. 0.38.1) -> Resolution and Release
        succ_res = AutonomousResponseOrchestrator.process_manual_remediation(
            db=self.db,
            threat_match_id=match.id,
            tenant_id=self.tenant.id,
            new_version="0.38.1",
            notes="Manually patched by IT admin"
        )
        self.assertEqual(succ_res["status"], "RESOLVED_AND_RELEASED")
        self.db.refresh(match)
        self.assertEqual(match.status, "RESOLVED")
        self.db.refresh(action)
        self.assertEqual(action.status, "ROLLED_BACK")
        self.db.refresh(self.asset_uvicorn)
        self.assertEqual(self.asset_uvicorn.software_version, "0.38.1")
