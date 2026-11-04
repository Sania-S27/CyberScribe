import unittest
import sys
import os

backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from app import models
from app.core.security import create_access_token

try:
    from tests.base import BaseTestCase
except ImportError:
    from base import BaseTestCase

class TestThreatsIntegration(BaseTestCase):
    def test_ingest_threat_and_get_public_feed(self):
        ingest_payload = {
            "title": "PostgreSQL Remote Code Execution via Function Call",
            "cve_id": "CVE-2026-7777",
            "severity": "critical",
            "summary": "An unauthenticated remote attacker can execute arbitrary code on vulnerable PostgreSQL servers.",
            "affected_software": ["postgresql"]
        }

        # 1. Ingest threat
        res = self.client.post("/public/threats/ingest", json=ingest_payload)
        self.assertEqual(res.status_code, 201)
        data = res.json()
        self.assertEqual(data["status"], "SUCCESS")
        report_id = data["report_id"]

        # 2. Get global threats list
        feed_res = self.client.get("/public/threats")
        self.assertEqual(feed_res.status_code, 200)
        threats = feed_res.json()["threats"]
        self.assertTrue(any(t["cve"] == "CVE-2026-7777" for t in threats))

        # 3. Get STIX bundle
        stix_res = self.client.get(f"/public/threats/{report_id}/stix")
        self.assertEqual(stix_res.status_code, 200)
        self.assertIn("stix_bundle", stix_res.json())

        # 4. Get SOAR playbook
        playbook_res = self.client.get(f"/public/threats/{report_id}/playbook")
        self.assertEqual(playbook_res.status_code, 200)
        self.assertIn("playbook", playbook_res.json())

    def test_tenant_matched_threats_and_mitigate(self):
        # Create threat report
        report = models.ThreatReport(
            title="FastAPI Request Smuggling Vulnerability",
            summary="A critical vulnerability in FastAPI endpoints allows remote attackers to bypass security filters.",
            severity="critical",
            cve_id="CVE-2026-9999",
            source_url="https://nvd.nist.gov/vuln/detail/CVE-2026-9999",
            stix_bundle={"type": "bundle", "id": "bundle--cve-2026-9999", "objects": []}
        )
        self.db.add(report)
        self.db.commit()

        # Create threat match
        match = models.ThreatMatch(
            tenant_id=self.tenant.id,
            threat_report_id=report.id,
            status="unmitigated",
            ai_confidence_score=98.0,
            ai_matching_reason="Critical match: FastAPI in tech stack"
        )
        self.db.add(match)
        self.db.commit()
        self.db.refresh(match)

        # 2. Fetch matches for tenant
        matches_res = self.client.get("/threats/matches", headers={"Authorization": f"Bearer {self.user_token}"})
        self.assertEqual(matches_res.status_code, 200)
        matches_data = matches_res.json()
        matches_list = matches_data.get("matches", matches_data) if isinstance(matches_data, dict) else matches_data
        self.assertGreaterEqual(len(matches_list), 1)
        self.assertEqual(matches_list[0]["id"], match.id)

        # 3. Apply mitigation with UUID
        mitigate_res = self.client.post(
            f"/public/threats/{match.id}/mitigate",
            headers={"Authorization": f"Bearer {self.user_token}"}
        )
        self.assertEqual(mitigate_res.status_code, 200)
        self.assertEqual(mitigate_res.json()["new_status"], "RESOLVED")

    def test_tenant_matched_threats_status_filtering_and_metadata(self):
        report_open = models.ThreatReport(
            title="Uvicorn Header Smuggling",
            summary="Header smuggling flaw in uvicorn",
            severity="high",
            cve_id="CVE-2026-8888",
            source_url="https://nvd.nist.gov/vuln/detail/CVE-2026-8888",
            stix_bundle={"type": "bundle", "id": "bundle--cve-2026-8888", "objects": []}
        )
        report_resolved = models.ThreatReport(
            title="Bcrypt Denial of Service",
            summary="DoS flaw in bcrypt",
            severity="medium",
            cve_id="CVE-2026-7777",
            source_url="https://nvd.nist.gov/vuln/detail/CVE-2026-7777",
            stix_bundle={"type": "bundle", "id": "bundle--cve-2026-7777", "objects": []}
        )
        self.db.add_all([report_open, report_resolved])
        self.db.commit()

        match_open = models.ThreatMatch(
            tenant_id=self.tenant.id,
            threat_report_id=report_open.id,
            status="OPEN",
            ai_confidence_score=95.0,
            ai_matching_reason="[AFFECTED] Installed uvicorn 0.38.0 satisfies constraint <= 0.38.0"
        )
        match_resolved = models.ThreatMatch(
            tenant_id=self.tenant.id,
            threat_report_id=report_resolved.id,
            status="RESOLVED",
            ai_confidence_score=90.0,
            ai_matching_reason="[NOT AFFECTED] Installed bcrypt 4.3.0 is outside vulnerable range"
        )
        self.db.add_all([match_open, match_resolved])
        self.db.commit()

        # Query OPEN filter
        res_open = self.client.get("/threats/matches?status=OPEN", headers={"Authorization": f"Bearer {self.user_token}"})
        self.assertEqual(res_open.status_code, 200)
        open_matches = res_open.json()["matches"]
        self.assertTrue(all(m["status"] == "OPEN" for m in open_matches))
        self.assertTrue(any(m["id"] == match_open.id for m in open_matches))

        # Query RESOLVED filter
        res_resolved = self.client.get("/threats/matches?status=RESOLVED", headers={"Authorization": f"Bearer {self.user_token}"})
        self.assertEqual(res_resolved.status_code, 200)
        resolved_matches = res_resolved.json()["matches"]
        self.assertTrue(all(m["status"] == "RESOLVED" for m in resolved_matches))
        self.assertTrue(any(m["id"] == match_resolved.id for m in resolved_matches))

        # Verify metadata
        sample_open = next(m for m in open_matches if m["id"] == match_open.id)
        self.assertEqual(sample_open["assessment_outcome"], "AFFECTED")
        sample_resolved = next(m for m in resolved_matches if m["id"] == match_resolved.id)
        self.assertEqual(sample_resolved["assessment_outcome"], "NOT_AFFECTED")

    def test_active_threats_view_and_summary_counts(self):
        """Verify active view excludes NOT_AFFECTED and keeps NEEDS_REVIEW in review view."""
        rep_aff = models.ThreatReport(
            title="Django SQL Injection Advisory",
            summary="SQL injection flaw in Django ORM",
            severity="critical",
            cve_id="CVE-2026-1111",
            source_url="https://nvd.nist.gov/vuln/detail/CVE-2026-1111",
            stix_bundle={"type": "bundle", "id": "bundle--cve-2026-1111", "objects": []}
        )
        rep_not_aff = models.ThreatReport(
            title="Requests Header Parsing Advisory",
            summary="Advisory for requests library",
            severity="low",
            cve_id="CVE-2026-2222",
            source_url="https://nvd.nist.gov/vuln/detail/CVE-2026-2222",
            stix_bundle={"type": "bundle", "id": "bundle--cve-2026-2222", "objects": []}
        )
        rep_rev = models.ThreatReport(
            title="Redis Memory Corruption Advisory",
            summary="Redis advisory requiring investigation",
            severity="high",
            cve_id="CVE-2026-3333",
            source_url="https://nvd.nist.gov/vuln/detail/CVE-2026-3333",
            stix_bundle={"type": "bundle", "id": "bundle--cve-2026-3333", "objects": []}
        )
        self.db.add_all([rep_aff, rep_not_aff, rep_rev])
        self.db.commit()

        m_aff = models.ThreatMatch(
            tenant_id=self.tenant.id,
            threat_report_id=rep_aff.id,
            status="OPEN",
            ai_confidence_score=97.0,
            ai_matching_reason="[AFFECTED] Installed django 4.2 satisfies vulnerable constraint <= 4.2.1"
        )
        m_not_aff = models.ThreatMatch(
            tenant_id=self.tenant.id,
            threat_report_id=rep_not_aff.id,
            status="OPEN",
            ai_confidence_score=92.0,
            ai_matching_reason="[NOT AFFECTED] Installed requests 2.31.0 is outside vulnerable range"
        )
        m_rev = models.ThreatMatch(
            tenant_id=self.tenant.id,
            threat_report_id=rep_rev.id,
            status="OPEN",
            ai_confidence_score=75.0,
            ai_matching_reason="Component match detected for redis; requires version review"
        )
        self.db.add_all([m_aff, m_not_aff, m_rev])
        self.db.commit()

        # 1. Default Active view: returns confirmed AFFECTED only, excludes NOT_AFFECTED and NEEDS_REVIEW
        res_active = self.client.get("/threats/matches?view=active", headers={"Authorization": f"Bearer {self.user_token}"})
        self.assertEqual(res_active.status_code, 200)
        data_active = res_active.json()
        active_ids = [m["id"] for m in data_active["matches"]]
        self.assertIn(m_aff.id, active_ids)
        self.assertNotIn(m_not_aff.id, active_ids)
        self.assertNotIn(m_rev.id, active_ids)

        # Confirm summary metrics accurately count categories
        summary = data_active["summary"]
        self.assertGreaterEqual(summary["active_affected"], 1)
        self.assertGreaterEqual(summary["not_affected"], 1)
        self.assertGreaterEqual(summary["review_required"], 1)

        # 2. Review view: returns NEEDS_REVIEW findings
        res_rev = self.client.get("/threats/matches?view=review", headers={"Authorization": f"Bearer {self.user_token}"})
        self.assertEqual(res_rev.status_code, 200)
        rev_ids = [m["id"] for m in res_rev.json()["matches"]]
        self.assertIn(m_rev.id, rev_ids)
        self.assertNotIn(m_aff.id, rev_ids)
        self.assertNotIn(m_not_aff.id, rev_ids)

        # 3. Safe / Not Affected view: returns NOT_AFFECTED findings
        res_safe = self.client.get("/threats/matches?view=safe", headers={"Authorization": f"Bearer {self.user_token}"})
        self.assertEqual(res_safe.status_code, 200)
        safe_ids = [m["id"] for m in res_safe.json()["matches"]]
        self.assertIn(m_not_aff.id, safe_ids)
        self.assertNotIn(m_aff.id, safe_ids)
        self.assertNotIn(m_rev.id, safe_ids)

        # 4. Mitigate confirmed affected threat and verify Resolved History view
        res_mitigate = self.client.post(
            f"/threats/matches/{m_aff.id}/mitigate",
            headers={"Authorization": f"Bearer {self.user_token}"}
        )
        self.assertEqual(res_mitigate.status_code, 200)
        self.assertEqual(res_mitigate.json()["new_status"], "RESOLVED")

        res_resolved = self.client.get("/threats/matches?view=resolved", headers={"Authorization": f"Bearer {self.user_token}"})
        self.assertEqual(res_resolved.status_code, 200)
        resolved_ids = [m["id"] for m in res_resolved.json()["matches"]]
        self.assertIn(m_aff.id, resolved_ids)

    def test_top_impacted_software_components_distinct_threat_counts(self):
        """
        Regression Test for CyberScribe Dashboard Component Threat Counting Bug:
        Verifies that component threat counts are calculated by distinct relevant threats,
        not hardcoding or assigning identical totals to every component.
        Includes components with varying threat counts and a component with 0 threats.
        """
        # 1. Create a controlled isolated tenant
        tenant = models.Tenant(
            company_name="Regression Test Tenant",
            tech_stack="FastAPI:0.115, Uvicorn:0.34, SQLAlchemy:2.0, Nginx:1.24"
        )
        self.db.add(tenant)
        self.db.commit()
        self.db.refresh(tenant)

        user = models.User(
            email="tenant_tester@regression.local",
            password_hash="mock_hash",
            role="tenant_admin",
            tenant_id=tenant.id
        )
        self.db.add(user)
        self.db.commit()
        user_token = create_access_token(data={"sub": user.email, "role": user.role, "tenant_id": tenant.id})
        headers = {"Authorization": f"Bearer {user_token}"}

        # 2. Register inventory components with different expected threat profiles
        comp_fastapi = models.AssetComponent(
            tenant_id=tenant.id,
            software_name="fastapi",
            software_version="0.115.0"
        )
        comp_uvicorn = models.AssetComponent(
            tenant_id=tenant.id,
            software_name="uvicorn",
            software_version="0.34.0"
        )
        comp_sqlalchemy = models.AssetComponent(
            tenant_id=tenant.id,
            software_name="sqlalchemy",
            software_version="2.0.30"
        )
        comp_nginx = models.AssetComponent(
            tenant_id=tenant.id,
            software_name="nginx",
            software_version="1.24.0"
        )
        self.db.add_all([comp_fastapi, comp_uvicorn, comp_sqlalchemy, comp_nginx])
        self.db.commit()

        # 3. Create distinct threat reports
        rep_f1 = models.ThreatReport(title="FastAPI CVE 1", cve_id="CVE-2026-0001", severity="high")
        rep_f2 = models.ThreatReport(title="FastAPI CVE 2", cve_id="CVE-2026-0002", severity="critical")
        rep_f3 = models.ThreatReport(title="FastAPI CVE 3", cve_id="CVE-2026-0003", severity="medium")
        rep_u1 = models.ThreatReport(title="Uvicorn CVE 1", cve_id="CVE-2026-0004", severity="high")
        rep_s1 = models.ThreatReport(title="SQLAlchemy Safe CVE", cve_id="CVE-2026-0005", severity="low")
        rep_s2 = models.ThreatReport(title="SQLAlchemy Patched CVE", cve_id="CVE-2026-0006", severity="high")
        self.db.add_all([rep_f1, rep_f2, rep_f3, rep_u1, rep_s1, rep_s2])
        self.db.commit()

        # 4. Associate threat matches:
        # - fastapi: 3 distinct active threats + 1 duplicate match for rep_f1 (should count as 3 distinct)
        m_f1 = models.ThreatMatch(tenant_id=tenant.id, asset_component_id=comp_fastapi.id, threat_report_id=rep_f1.id, status="OPEN", ai_confidence_score=95.0, ai_matching_reason="[AFFECTED] Installed fastapi <= 0.115")
        m_f1_dup = models.ThreatMatch(tenant_id=tenant.id, asset_component_id=comp_fastapi.id, threat_report_id=rep_f1.id, status="OPEN", ai_confidence_score=95.0, ai_matching_reason="[AFFECTED] Installed fastapi <= 0.115 (duplicate observation)")
        m_f2 = models.ThreatMatch(tenant_id=tenant.id, asset_component_id=comp_fastapi.id, threat_report_id=rep_f2.id, status="OPEN", ai_confidence_score=98.0, ai_matching_reason="[AFFECTED] Installed fastapi <= 0.115")
        m_f3 = models.ThreatMatch(tenant_id=tenant.id, asset_component_id=comp_fastapi.id, threat_report_id=rep_f3.id, status="OPEN", ai_confidence_score=85.0, ai_matching_reason="[NEEDS REVIEW] Component fastapi requires validation")

        # - uvicorn: 1 distinct active threat
        m_u1 = models.ThreatMatch(tenant_id=tenant.id, asset_component_id=comp_uvicorn.id, threat_report_id=rep_u1.id, status="OPEN", ai_confidence_score=90.0, ai_matching_reason="[AFFECTED] Installed uvicorn <= 0.34")

        # - sqlalchemy: 1 NOT_AFFECTED and 1 RESOLVED (active count must be 0)
        m_s1 = models.ThreatMatch(tenant_id=tenant.id, asset_component_id=comp_sqlalchemy.id, threat_report_id=rep_s1.id, status="OPEN", ai_confidence_score=90.0, ai_matching_reason="[NOT AFFECTED] Installed sqlalchemy is outside vulnerable range")
        m_s2 = models.ThreatMatch(tenant_id=tenant.id, asset_component_id=comp_sqlalchemy.id, threat_report_id=rep_s2.id, status="RESOLVED", ai_confidence_score=90.0, ai_matching_reason="[AFFECTED] Installed sqlalchemy satisfies constraint")

        # - nginx: 0 threat matches (no associated threats)

        self.db.add_all([m_f1, m_f1_dup, m_f2, m_f3, m_u1, m_s1, m_s2])
        self.db.commit()

        # 5. Query /threats/matches endpoint supplying the analytics dashboard
        res = self.client.get("/threats/matches?view=all", headers=headers)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        summary = data.get("summary", {})
        top_components = summary.get("top_components") or data.get("top_components")
        exposure = summary.get("component_exposure") or data.get("component_exposure")

        # Verify component_exposure map exists and counts distinct relevant threats
        self.assertIsNotNone(exposure)
        self.assertEqual(exposure.get("fastapi"), 3, "fastapi must have 3 distinct active threats (duplicate excluded)")
        self.assertEqual(exposure.get("uvicorn"), 1, "uvicorn must have 1 active threat")
        self.assertEqual(exposure.get("sqlalchemy"), 0, "sqlalchemy must have 0 active threats (NOT_AFFECTED and RESOLVED excluded)")
        self.assertEqual(exposure.get("nginx"), 0, "nginx must have 0 threats (component with no threats)")

        # Verify counts are diverse and not all identical (e.g. not all 5)
        counts = [cnt for comp, cnt in top_components]
        self.assertIn(3, counts)
        self.assertIn(1, counts)
        self.assertIn(0, counts)
        self.assertFalse(all(c == 5 for c in counts), "Bug regression: all components should not display exactly 5 threats")

        # Verify sorted ordering: fastapi (3) > uvicorn (1) > nginx/sqlalchemy (0)
        self.assertEqual(top_components[0][0], "fastapi")
        self.assertEqual(top_components[0][1], 3)
        self.assertEqual(top_components[1][0], "uvicorn")
        self.assertEqual(top_components[1][1], 1)

if __name__ == '__main__':
    unittest.main()


