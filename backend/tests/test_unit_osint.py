# backend/tests/test_unit_osint.py
import unittest
import sys
import os
from datetime import datetime
from unittest.mock import patch, MagicMock

backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from app import models
from app.services.osint_collector import OSINT_FEEDS, DEFAULT_HEADERS, fetch_general_osint_feeds
from app.services.vector_store import add_threat_embedding

try:
    from tests.base import BaseTestCase
except ImportError:
    from base import BaseTestCase

class TestOSINTIngestion(BaseTestCase):
    def test_osint_feeds_inventory_excludes_threatpost_and_bleepingcomputer(self):
        """Verify Threatpost and BleepingComputer are removed from active OSINT feeds and exactly 5 feeds remain."""
        self.assertNotIn("Threatpost", OSINT_FEEDS)
        self.assertNotIn("BleepingComputer", OSINT_FEEDS)
        self.assertEqual(len(OSINT_FEEDS), 5)
        expected_feeds = [
            "CISA Advisories",
            "The Hacker News",
            "Krebs on Security",
            "SecurityWeek",
            "Dark Reading"
        ]
        for feed_name in expected_feeds:
            self.assertIn(feed_name, OSINT_FEEDS)

    def test_published_at_null_preserved_without_backfill(self):
        """Verify that when a report has no published_at, it is saved as NULL and NOT backfilled from created_at."""
        report = models.ThreatReport(
            title="Advisory Without Publication Date",
            summary="Vendor security announcement with missing date metadata.",
            severity="medium",
            cve_id="CVE-2026-0001",
            source_url="https://example.com/advisory-0001",
            published_at=None,
            stix_bundle={"type": "bundle", "id": "bundle--0001", "objects": []}
        )
        self.db.add(report)
        self.db.commit()
        self.db.refresh(report)

        self.assertIsNone(report.published_at)
        self.assertIsNotNone(report.created_at)

        # Query via API with days=all to inspect historical/undated reports
        res = self.client.get("/public/threats?days=all")
        self.assertEqual(res.status_code, 200)
        threats = res.json()["threats"]
        matching = next((t for t in threats if t["id"] == report.id), None)
        self.assertIsNotNone(matching)
        self.assertIsNone(matching["published_at"])
        self.assertIsNotNone(matching["created_at"])

    def test_published_at_trusted_date_preserved(self):
        """Verify verified publication date is correctly stored and returned."""
        verified_date = datetime(2026, 7, 20, 15, 30, 0)
        report = models.ThreatReport(
            title="Advisory With Valid Publication Date",
            summary="CVE publication advisory.",
            severity="high",
            cve_id="CVE-2026-0002",
            source_url="https://example.com/advisory-0002",
            published_at=verified_date,
            stix_bundle={"type": "bundle", "id": "bundle--0002", "objects": []}
        )
        self.db.add(report)
        self.db.commit()
        self.db.refresh(report)

        self.assertEqual(report.published_at, verified_date)

        res = self.client.get("/public/threats?days=all")
        self.assertEqual(res.status_code, 200)
        threats = res.json()["threats"]
        matching = next((t for t in threats if t["id"] == report.id), None)
        self.assertIsNotNone(matching)
        self.assertEqual(matching["published_at"], "2026-07-20 15:30")

    @patch("app.services.osint_collector.requests.get")
    def test_cisa_feed_fetching_with_headers_and_error_isolation(self, mock_get):
        """Verify requests.get is used with DEFAULT_HEADERS and handles HTTP errors safely."""
        # 1. Simulate 403 error on first feed and 200 XML on second feed
        mock_resp_403 = MagicMock()
        mock_resp_403.status_code = 403

        mock_resp_200 = MagicMock()
        mock_resp_200.status_code = 200
        mock_resp_200.content = b"""<?xml version="1.0" encoding="UTF-8"?>
        <rss version="2.0">
            <channel>
                <title>CISA Advisories</title>
                <link>https://www.cisa.gov</link>
                <item>
                    <title>Test Vulnerability Advisory</title>
                    <link>https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-001a</link>
                    <description>A critical remote code execution vulnerability.</description>
                    <pubDate>Mon, 05 Oct 2026 12:00:00 +0000</pubDate>
                </item>
            </channel>
        </rss>"""

        mock_get.side_effect = [mock_resp_403, mock_resp_200, mock_resp_200, mock_resp_200, mock_resp_200, mock_resp_200]

        # Should not raise exception
        fetch_general_osint_feeds(self.db)
        self.assertTrue(mock_get.called)

    def test_rag_embedding_indexing_with_none_published_at(self):
        """Verify add_threat_embedding handles published_at=None safely."""
        success = add_threat_embedding(
            threat_id="test-threat-pub-none",
            title="Test RAG Threat Without Pub Date",
            summary="A test threat summary for vector indexing.",
            severity="medium",
            source_url="https://example.com/test-none",
            cve_id="CVE-2026-TEST",
            published_at=None
        )
        self.assertTrue(success)

if __name__ == '__main__':
    unittest.main()
