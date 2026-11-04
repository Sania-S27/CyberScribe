import unittest
import sys
import os
from datetime import datetime

backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from app import models

try:
    from tests.base import BaseTestCase
except ImportError:
    from base import BaseTestCase

class TestModels(BaseTestCase):
    def test_threat_match_status_enum(self):
        report = models.ThreatReport(
            title="FastAPI Smuggling",
            summary="Smuggling vulnerability",
            severity="critical",
            cve_id="CVE-2026-9999",
            source_url="https://cve.org/CVE-2026-9999",
            stix_bundle={"type": "bundle", "id": "bundle--1", "objects": []}
        )
        self.db.add(report)
        self.db.commit()

        valid_statuses = ['OPEN', 'IN_PROGRESS', 'RESOLVED', 'unmitigated', 'mitigated', 'triaged', 'patched', 'active']
        for status in valid_statuses:
            match = models.ThreatMatch(
                tenant_id=self.tenant.id,
                threat_report_id=report.id,
                status=status,
                ai_confidence_score=98.5,
                ai_matching_reason=f"Testing status {status}"
            )
            self.db.add(match)
            self.db.commit()
            self.db.refresh(match)
            self.assertEqual(match.status, status)
            self.assertEqual(len(match.id), 36)

    def test_threat_report_published_and_created_at(self):
        test_pub_date = datetime(2026, 8, 15, 12, 0, 0)
        report = models.ThreatReport(
            title="Linux Kernel Privilege Escalation",
            summary="Local privilege escalation flaw",
            severity="high",
            cve_id="CVE-2026-1111",
            source_url="https://cve.mitre.org/cve-2026-1111",
            published_at=test_pub_date,
            stix_bundle={"type": "bundle", "id": "bundle--1", "objects": []}
        )
        self.db.add(report)
        self.db.commit()
        self.db.refresh(report)

        self.assertEqual(report.published_at, test_pub_date)
        self.assertIsNotNone(report.created_at)
        self.assertEqual(report.severity, "high")

    def test_tenant_relationships(self):
        asset = models.AssetComponent(
            tenant_id=self.tenant.id,
            software_name="nginx",
            software_version="1.24",
            environment="production"
        )
        self.db.add(asset)
        self.db.commit()
        self.db.refresh(self.tenant)

        self.assertGreaterEqual(len(self.tenant.users), 1)
        self.assertGreaterEqual(len(self.tenant.assets), 1)
        self.assertEqual(self.tenant.users[0].email, self.user.email)

if __name__ == '__main__':
    unittest.main()
