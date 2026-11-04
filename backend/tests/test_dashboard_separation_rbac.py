import os
import sys
import unittest

backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

try:
    from tests.base import BaseTestCase
except ImportError:
    from base import BaseTestCase

from unittest.mock import patch, MagicMock
from app import models
from app.core.security import get_password_hash, create_access_token


class TestDashboardSeparationRBAC(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.mock_sweep_patcher = patch("app.services.osint_collector.run_sync_sweep")
        self.mock_sweep = self.mock_sweep_patcher.start()

    def tearDown(self):
        self.mock_sweep_patcher.stop()
        super().tearDown()

    def test_tenant_user_access_to_company_dashboard_endpoints(self):
        """Authenticated tenant users can access their company dashboard endpoints."""
        headers = {"Authorization": f"Bearer {self.user_token}"}

        # 1. Threat Overview & Matches
        res_matches = self.client.get("/threats/matches", headers=headers)
        self.assertEqual(res_matches.status_code, 200)
        self.assertIn("matches", res_matches.json())
        self.assertIn("summary", res_matches.json())

        # 2. Asset Security & SBOM Profile
        res_profile = self.client.get("/tenants/profile", headers=headers)
        self.assertEqual(res_profile.status_code, 200)
        self.assertIn("assets", res_profile.json())
        self.assertIn("company_name", res_profile.json())

        # 3. Tenant Response Actions
        res_actions = self.client.get("/tenants/containment/actions", headers=headers)
        self.assertEqual(res_actions.status_code, 200)
        self.assertIn("actions", res_actions.json())

        # 4. Threat Reports Summary
        res_report = self.client.get("/tenants/reports/summary", headers=headers)
        self.assertEqual(res_report.status_code, 200)
        self.assertIn("total_threat_matches", res_report.json())

    def test_tenant_user_denied_access_to_administrative_endpoints(self):
        """Tenant users must receive 403 Forbidden when attempting to access admin APIs."""
        headers = {"Authorization": f"Bearer {self.user_token}"}

        admin_endpoints = [
            ("GET", "/admin/metrics"),
            ("GET", "/admin/tenants"),
            ("GET", "/admin/users"),
            ("GET", "/admin/containment/actions"),
            ("GET", "/admin/containment/audit-logs"),
            ("GET", "/admin/system-health"),
            ("GET", "/admin/integrations"),
            ("POST", "/admin/threats/trigger-osint-sweep"),
            ("GET", "/admin/threats/sources/status"),
            ("POST", "/public/threats/trigger-osint-sweep"),
            ("GET", "/public/threats/sources/status"),
            ("GET", "/tenants/containment/audit-logs"),
            ("POST", "/tenants/notifications/test-email"),
        ]

        for method, endpoint in admin_endpoints:
            with self.subTest(method=method, endpoint=endpoint):
                if method == "GET":
                    res = self.client.get(endpoint, headers=headers)
                else:
                    res = self.client.post(endpoint, headers=headers)
                self.assertEqual(
                    res.status_code,
                    403,
                    f"Tenant user was not forbidden from accessing administrative endpoint {method} {endpoint}. Received status {res.status_code}: {res.text}"
                )

    def test_super_admin_access_to_administrative_endpoints(self):
        """Platform administrators can access all administrative monitoring features."""
        headers = {"Authorization": f"Bearer {self.admin_token}"}

        # 1. Admin Metrics
        res_metrics = self.client.get("/admin/metrics", headers=headers)
        self.assertEqual(res_metrics.status_code, 200)

        # 2. Tenants Directory
        res_tenants = self.client.get("/admin/tenants", headers=headers)
        self.assertEqual(res_tenants.status_code, 200)

        # 3. Users Directory
        res_users = self.client.get("/admin/users", headers=headers)
        self.assertEqual(res_users.status_code, 200)

        # 4. Global Containment Actions
        res_actions = self.client.get("/admin/containment/actions", headers=headers)
        self.assertEqual(res_actions.status_code, 200)

        # 5. Security Audit Ledger
        res_audit = self.client.get("/admin/containment/audit-logs", headers=headers)
        self.assertEqual(res_audit.status_code, 200)

        # 6. System Health
        res_health = self.client.get("/admin/system-health", headers=headers)
        self.assertEqual(res_health.status_code, 200)

        # 7. OSINT Feed Status
        res_feed = self.client.get("/admin/threats/sources/status", headers=headers)
        self.assertEqual(res_feed.status_code, 200)

        # 8. OSINT Sweep Trigger
        res_sweep = self.client.post("/admin/threats/trigger-osint-sweep", headers=headers)
        self.assertEqual(res_sweep.status_code, 200)

    def test_tenant_isolation_between_companies(self):
        """Ensure strict tenant isolation so Company A cannot view or manipulate Company B data."""
        # 1. Create a second distinct tenant organization
        tenant_b = models.Tenant(
            company_name="Beta Cyber Systems",
            tech_stack="Python:3.11, Django:4.2"
        )
        self.db.add(tenant_b)
        self.db.commit()
        self.db.refresh(tenant_b)

        user_b = models.User(
            email="analyst@beta.local",
            password_hash=get_password_hash("BetaPass123!"),
            role="analyst",
            tenant_id=tenant_b.id
        )
        self.db.add(user_b)
        self.db.commit()
        self.db.refresh(user_b)

        user_b_token = create_access_token(data={
            "sub": user_b.email,
            "role": user_b.role,
            "tenant_id": user_b.tenant_id
        })

        # 2. Add SBOM assets for Tenant A and Tenant B
        asset_a = models.AssetComponent(
            tenant_id=self.tenant.id,
            software_name="fastapi",
            software_version="0.100.0"
        )
        asset_b = models.AssetComponent(
            tenant_id=tenant_b.id,
            software_name="django",
            software_version="4.1.0"
        )
        self.db.add_all([asset_a, asset_b])
        self.db.commit()

        # 3. Add Threat Matches for Tenant A and Tenant B
        report = models.ThreatReport(
            title="CVE-2026-TEST Vulnerability",
            cve_id="CVE-2026-TEST",
            severity="critical",
            summary="Test Advisory"
        )
        self.db.add(report)
        self.db.commit()

        match_a = models.ThreatMatch(
            tenant_id=self.tenant.id,
            asset_component_id=asset_a.id,
            threat_report_id=report.id,
            status="OPEN",
            ai_confidence_score=95.0,
            ai_matching_reason="Installed fastapi 0.100.0 satisfies vulnerable constraint [AFFECTED]"
        )
        match_b = models.ThreatMatch(
            tenant_id=tenant_b.id,
            asset_component_id=asset_b.id,
            threat_report_id=report.id,
            status="OPEN",
            ai_confidence_score=90.0,
            ai_matching_reason="Installed django 4.1.0 satisfies vulnerable constraint [AFFECTED]"
        )
        self.db.add_all([match_a, match_b])
        self.db.commit()

        # 4. Add Containment Actions for Tenant A and Tenant B
        action_a = models.ContainmentAction(
            action_id="act-acme-001",
            tenant_id=self.tenant.id,
            indicator_value="198.51.100.1",
            policy_decision="QUALIFIED",
            status="SIMULATED"
        )
        action_b = models.ContainmentAction(
            action_id="act-beta-002",
            tenant_id=tenant_b.id,
            indicator_value="203.0.113.5",
            policy_decision="QUALIFIED",
            status="SIMULATED"
        )
        self.db.add_all([action_a, action_b])
        self.db.commit()

        # 5. Verify User A only sees Tenant A's threats
        res_a_matches = self.client.get("/threats/matches", headers={"Authorization": f"Bearer {self.user_token}"})
        self.assertEqual(res_a_matches.status_code, 200)
        match_ids_a = [m["id"] for m in res_a_matches.json()["matches"]]
        self.assertIn(match_a.id, match_ids_a)
        self.assertNotIn(match_b.id, match_ids_a)

        # 6. Verify User B only sees Tenant B's threats
        res_b_matches = self.client.get("/threats/matches", headers={"Authorization": f"Bearer {user_b_token}"})
        self.assertEqual(res_b_matches.status_code, 200)
        match_ids_b = [m["id"] for m in res_b_matches.json()["matches"]]
        self.assertIn(match_b.id, match_ids_b)
        self.assertNotIn(match_a.id, match_ids_b)

        # 7. Verify User A cannot access or rollback Tenant B's containment action
        res_rollback_cross = self.client.post(
            f"/tenants/containment/actions/{action_b.id}/rollback",
            headers={"Authorization": f"Bearer {self.user_token}"}
        )
        self.assertEqual(res_rollback_cross.status_code, 404)

        # 8. Verify User A cannot mitigate Tenant B's threat match
        res_mitigate_cross = self.client.post(
            f"/threats/matches/{match_b.id}/mitigate",
            headers={"Authorization": f"Bearer {self.user_token}"}
        )
        self.assertEqual(res_mitigate_cross.status_code, 403)

        # 9. Verify User A only sees Tenant A's assets
        res_profile_a = self.client.get("/tenants/profile", headers={"Authorization": f"Bearer {self.user_token}"})
        asset_names_a = [a["software_name"] for a in res_profile_a.json()["assets"]]
        self.assertIn("fastapi", asset_names_a)
        self.assertNotIn("django", asset_names_a)


if __name__ == "__main__":
    unittest.main()
