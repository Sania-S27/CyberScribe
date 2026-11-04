# backend/tests/test_four_critical_findings_and_dashboard.py
import unittest
import os
import sys

# Ensure backend root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.core.database import SessionLocal
from app.models import Tenant, ThreatMatch, ThreatReport, AssetComponent, ContainmentAction, PatchProposal
from app.services.fixed_version_service import FixedVersionDiscoveryService
from app.services.autonomous_response_orchestrator import AutonomousResponseOrchestrator
from app.api.tenants import get_tenant_containment_actions

class TestFourCriticalFindingsAndDashboard(unittest.TestCase):
    def setUp(self):
        self.db = SessionLocal()
        self.tenant = self.db.query(Tenant).filter(Tenant.company_name == "Campus Guide").first()
        self.finding_ids = [
            "0e99f39c-6dcd-4982-802b-0840d3a02c51", # uvicorn / CVE-2026-26209
            "165c0177-e661-43d6-99b3-1a7fc2600b58", # bcrypt / CVE-2019-13421
            "4dc043da-1610-4b35-97b5-d7087d209449", # bcrypt / CVE-2020-5229
            "9c84831b-0360-4c06-b23e-a72e25a6da8c", # bcrypt / CVE-2015-0833
        ]

    def tearDown(self):
        self.db.close()

    def test_01_all_four_findings_exist_and_are_open(self):
        """Confirm all 4 findings exist in database with OPEN status and are linked to Campus Guide."""
        self.assertIsNotNone(self.tenant, "Tenant Campus Guide must exist")
        self.assertEqual(self.tenant.remediation_policy, "AUTO_PATCH")

        for mid in self.finding_ids:
            match = self.db.query(ThreatMatch).filter(ThreatMatch.id == mid).first()
            self.assertIsNotNone(match, f"Match {mid} must exist")
            self.assertEqual(match.tenant_id, self.tenant.id)
            self.assertEqual(match.status, "OPEN")
            self.assertIn("[AFFECTED]", match.ai_matching_reason)

    def test_02_fixed_version_discovery_blocks_unverified_candidates(self):
        """Confirm FixedVersionDiscoveryService correctly blocks live execution for all 4 findings."""
        # Finding 1: CVE-2026-26209 (uvicorn against < 5.9.0 constraint)
        m1 = self.db.query(ThreatMatch).filter(ThreatMatch.id == self.finding_ids[0]).first()
        t1 = self.db.query(ThreatReport).filter(ThreatReport.id == m1.threat_report_id).first()
        a1 = self.db.query(AssetComponent).filter(AssetComponent.id == m1.asset_component_id).first()
        
        fix1 = FixedVersionDiscoveryService.discover_and_verify_fix(
            package_name=a1.software_name,
            current_version=a1.software_version,
            threat_report=t1,
            package_manager="pip"
        )
        self.assertTrue(fix1.get("live_execution_blocked"), "Finding 1 must block live execution")
        self.assertIn("does not resolve the advisory constraint", fix1.get("blocking_reason", ""))

        # Findings 2, 3, 4: bcrypt advisories where CVE applies to another product
        for mid in self.finding_ids[1:]:
            m = self.db.query(ThreatMatch).filter(ThreatMatch.id == mid).first()
            t = self.db.query(ThreatReport).filter(ThreatReport.id == m.threat_report_id).first()
            a = self.db.query(AssetComponent).filter(AssetComponent.id == m.asset_component_id).first()

            fix = FixedVersionDiscoveryService.discover_and_verify_fix(
                package_name=a.software_name,
                current_version=a.software_version,
                threat_report=t,
                package_manager="pip"
            )
            self.assertTrue(fix.get("live_execution_blocked"), f"Finding {mid} must block live execution")
            self.assertEqual(fix.get("status"), "FIX_UNKNOWN")
            self.assertIsNone(fix.get("fixed_version"))
            self.assertIn("No authoritative fixed version", fix.get("blocking_reason", ""))

    def test_03_orchestrator_creates_no_unauthorized_proposals(self):
        """Confirm AutonomousResponseOrchestrator refuses to create or execute patch proposals for blocked findings."""
        for mid in self.finding_ids:
            match = self.db.query(ThreatMatch).filter(ThreatMatch.id == mid).first()
            threat = self.db.query(ThreatReport).filter(ThreatReport.id == match.threat_report_id).first()
            asset = self.db.query(AssetComponent).filter(AssetComponent.id == match.asset_component_id).first()

            result = AutonomousResponseOrchestrator.correlate_sbom_and_create_incident(
                db=self.db,
                tenant_id=self.tenant.id,
                threat_report_id=match.threat_report_id
            )
            # Proposals should not be executed; status should indicate incident processed without false auto-patch
            self.assertIn(result.get("status"), ["INCIDENT_CREATED", "AUTO_PATCH_SKIPPED_LOW_SEVERITY", "ALREADY_RESOLVED"])
            
            # Confirm no verified proposal was created for these 4 blocked findings
            proposals = self.db.query(PatchProposal).filter(
                PatchProposal.threat_match_id == mid,
                PatchProposal.status == "VERIFIED"
            ).all()
            self.assertEqual(len(proposals), 0, f"No verified patch proposal should exist for {mid}")

    def test_04_dashboard_containment_counts_are_zero_because_rules_rolled_back(self):
        """Explain and verify why CompanyContainment.jsx cards display 0:
        1. 'Staged Containment Rules' counts actions with status='SIMULATED' (currently 0)
        2. 'Pending Evaluation' counts actions with status='PENDING' (currently 0)
        3. 'Verified / Mitigated' counts actions with status in ('VERIFIED', 'APPLIED') (currently 0)
        All existing actions for Campus Guide are ROLLED_BACK, EXPIRED, or FAILED.
        """
        actions = self.db.query(ContainmentAction).filter(
            ContainmentAction.tenant_id == self.tenant.id
        ).all()
        
        simulated_count = sum(1 for a in actions if a.status == "SIMULATED")
        pending_count = sum(1 for a in actions if a.status == "PENDING")
        verified_count = sum(1 for a in actions if a.status in ("VERIFIED", "APPLIED"))
        rolled_back_count = sum(1 for a in actions if a.status == "ROLLED_BACK")
        expired_count = sum(1 for a in actions if a.status == "EXPIRED")

        self.assertEqual(simulated_count, 0, "Active simulated count must be 0")
        self.assertEqual(pending_count, 0, "Pending count must be 0")
        self.assertEqual(verified_count, 0, "Active verified count must be 0")
        self.assertGreater(rolled_back_count + expired_count, 0, "Rollback and expired actions exist from past testing")

    def test_05_production_assets_safely_protected_from_unattended_patching(self):
        """Verify that Campus Guide's assets have environment='production', preventing unsafe unattended patching."""
        assets = self.db.query(AssetComponent).filter(
            AssetComponent.tenant_id == self.tenant.id,
            AssetComponent.software_name.in_(["uvicorn", "bcrypt"])
        ).all()
        self.assertGreater(len(assets), 0)
        for a in assets:
            self.assertEqual(a.environment, "production", "Campus Guide asset environment must be production")

if __name__ == "__main__":
    unittest.main()
