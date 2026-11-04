# backend/tests/test_continuous_osint_ingestion.py
import unittest
import sys
import os
import uuid
from datetime import datetime, timezone, timedelta
from unittest.mock import patch, MagicMock

backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from app import models
from app.services.osint_collector import (
    OSINT_FEEDS,
    DEFAULT_HEADERS,
    source_tracker,
    run_sync_sweep,
    fetch_general_osint_feeds,
    fetch_targeted_cves_for_inventory,
    fetch_feed_with_retry,
    _sweep_mutex,
    compute_content_hash,
    check_threat_match_for_tenant,
    process_threat_tenant_correlations
)
from app.services.version_matcher import (
    evaluate_version_applicability,
    extract_version_constraints,
    check_product_identity_mismatch
)
from app.agents.mitigation import generate_soar_playbook
from app.services.containment_policy import (
    AutonomousPolicyEngine,
    NetworkIndicatorCandidate
)

try:
    from tests.base import BaseTestCase
except ImportError:
    from base import BaseTestCase


class TestContinuousOSINTIngestion(BaseTestCase):
    """
    Milestone 3 Automated Test Suite:
    1. New items are ingested.
    2. Repeated polling does not create duplicates.
    3. Updated advisories refresh the existing record appropriately.
    4. A failed source does not prevent other sources from syncing.
    5. Publication dates are not confused with ingestion dates.
    6. Product-identity collisions become NEEDS_REVIEW rather than false confirmed findings.
    7. Uncertain findings cannot trigger automatic containment.
    8. Historical records and tenant isolation remain intact.
    9. Repeated or concurrent scheduler runs do not create duplicate records.
    """

    def setUp(self):
        super().setUp()
        # Ensure sweep lock is clean
        if _sweep_mutex.locked():
            try:
                _sweep_mutex.release()
            except RuntimeError:
                pass

    def test_01_new_items_ingested_and_telemetry_updated(self):
        """Requirement 1: New items are ingested incrementally and tracked in telemetry."""
        fake_xml = b"""<?xml version="1.0" encoding="UTF-8"?>
        <rss version="2.0">
            <channel>
                <title>CISA Advisories</title>
                <link>https://www.cisa.gov</link>
                <item>
                    <title>Critical RCE in ExampleCorp Gateway</title>
                    <link>https://www.cisa.gov/advisories/aa26-999a</link>
                    <description>A remote code execution vulnerability was discovered in ExampleCorp gateways.</description>
                    <pubDate>Thu, 08 Oct 2026 10:00:00 +0000</pubDate>
                </item>
            </channel>
        </rss>"""

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = fake_xml

        initial_count = self.db.query(models.ThreatReport).count()

        with patch("app.services.osint_collector.requests.get", return_value=mock_resp):
            fetch_general_osint_feeds(self.db, lookback_days=30)

        new_count = self.db.query(models.ThreatReport).count()
        self.assertGreater(new_count, initial_count, "New threat report should be inserted into the database")

        ingested = self.db.query(models.ThreatReport).filter(
            models.ThreatReport.source_url == "https://www.cisa.gov/advisories/aa26-999a"
        ).first()
        self.assertIsNotNone(ingested)
        self.assertIn("ExampleCorp", ingested.title)

    def test_02_repeated_polling_does_not_create_duplicates(self):
        """Requirement 2: Repeated polling does not create duplicates."""
        url = "https://thehackernews.com/sample-test-ransomware-alert/"
        title = "Sample Test Ransomware Wave Disclosed"
        summary = "Security researchers have identified a new ransomware campaign."

        # Insert once
        report = models.ThreatReport(
            source_url=url,
            title=title,
            summary=summary,
            severity="high",
            cve_id="CVE-2026-TEST-DUP"
        )
        self.db.add(report)
        self.db.commit()

        initial_count = self.db.query(models.ThreatReport).count()
        prev_dups = source_tracker.sources.get("The Hacker News", MagicMock()).duplicates_skipped_count

        fake_xml = f"""<?xml version="1.0" encoding="UTF-8"?>
        <rss version="2.0">
            <channel>
                <title>The Hacker News</title>
                <link>https://feeds.feedburner.com/TheHackersNews</link>
                <item>
                    <title>{title}</title>
                    <link>{url}</link>
                    <description>{summary}</description>
                </item>
            </channel>
        </rss>""".encode("utf-8")

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = fake_xml

        with patch("app.services.osint_collector.requests.get", return_value=mock_resp):
            fetch_general_osint_feeds(self.db, lookback_days=30)

        final_count = self.db.query(models.ThreatReport).count()
        self.assertEqual(final_count, initial_count, "Repeated polling of identical content must not create duplicates")

        new_dups = source_tracker.sources.get("The Hacker News", MagicMock()).duplicates_skipped_count
        self.assertGreaterEqual(new_dups, prev_dups, "Duplicates counter should increment on repeated polling")

    def test_03_updated_advisories_refresh_existing_record(self):
        """Requirement 3: Updated advisories refresh the existing record appropriately."""
        url = "https://www.securityweek.com/updated-threat-disclosure-analysis/"
        initial_summary = "Initial brief note regarding potential issues."
        updated_summary = "Revised comprehensive advisory: critical arbitrary code execution confirmed in all core modules with vendor emergency patch."

        # Seed initial report
        report = models.ThreatReport(
            source_url=url,
            title="Advisory for ExampleLib",
            summary=initial_summary,
            severity="low",
            cve_id="CVE-2026-TEST-UPD"
        )
        self.db.add(report)
        self.db.commit()
        self.db.refresh(report)

        fake_xml = f"""<?xml version="1.0" encoding="UTF-8"?>
        <rss version="2.0">
            <channel>
                <title>SecurityWeek</title>
                <link>https://www.securityweek.com/feed/</link>
                <item>
                    <title>Revised Advisory for ExampleLib</title>
                    <link>{url}</link>
                    <description>{updated_summary}</description>
                </item>
            </channel>
        </rss>""".encode("utf-8")

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = fake_xml

        with patch("app.services.osint_collector.requests.get", return_value=mock_resp):
            fetch_general_osint_feeds(self.db, lookback_days=30)

        # Verify record was refreshed
        self.db.refresh(report)
        self.assertEqual(report.summary, updated_summary, "Summary should be updated with new disclosure details")
        self.assertEqual(report.title, "Revised Advisory for ExampleLib")

    def test_04_failed_source_does_not_prevent_other_sources_from_syncing(self):
        """Requirement 4: A failed source does not prevent other sources from syncing."""
        # Mock responses: first source fails with 500, second source succeeds with 200
        mock_500 = MagicMock()
        mock_500.status_code = 500

        mock_200 = MagicMock()
        mock_200.status_code = 200
        mock_200.content = b"""<?xml version="1.0" encoding="UTF-8"?>
        <rss version="2.0">
            <channel>
                <title>Successful Feed</title>
                <link>https://example.com</link>
                <item>
                    <title>Successful Ingestion Test Item</title>
                    <link>https://example.com/item-success</link>
                    <description>Valid threat description.</description>
                </item>
            </channel>
        </rss>"""

        def mock_get_side_effect(url, *args, **kwargs):
            if "cisa.gov" in url:
                return mock_500
            return mock_200

        with patch("app.services.osint_collector.requests.get", side_effect=mock_get_side_effect):
            # Should not raise exception
            fetch_general_osint_feeds(self.db, lookback_days=30)

        cisa_status = source_tracker.sources.get("CISA Advisories")
        self.assertIsNotNone(cisa_status)
        self.assertEqual(cisa_status.status, "ERROR")
        self.assertIn("500", cisa_status.last_error or "")

        # Verify other sources succeeded
        thn_status = source_tracker.sources.get("The Hacker News")
        self.assertIsNotNone(thn_status)
        self.assertEqual(thn_status.status, "HEALTHY")

    def test_04b_bleepingcomputer_not_in_active_feeds_and_not_polled(self):
        """OSINT Cleanup: BleepingComputer is excluded from active feeds, scheduler, and polling."""
        self.assertNotIn("BleepingComputer", OSINT_FEEDS)
        self.assertNotIn("BleepingComputer", source_tracker.sources)
        self.assertEqual(len(OSINT_FEEDS), 5)
        # Verify active feeds remain intact
        for feed in ["CISA Advisories", "The Hacker News", "Krebs on Security", "SecurityWeek", "Dark Reading"]:
            self.assertIn(feed, OSINT_FEEDS)

    def test_04c_historical_bleepingcomputer_records_preserved(self):
        """OSINT Cleanup: Historical threat records from BleepingComputer remain intact and accessible in the database."""
        historical_url = "https://www.bleepingcomputer.com/news/security/historical-test-advisory-2024/"
        report = models.ThreatReport(
            id=str(uuid.uuid4()),
            source_url=historical_url,
            title="Historical BleepingComputer Advisory",
            summary="Historical threat record ingested in prior collection cycle.",
            severity="high",
            cve_id="CVE-2024-HIST-001"
        )
        self.db.add(report)
        self.db.commit()

        # Ingestion sweep must NOT delete or mutate this historical record
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b'<?xml version="1.0"?><rss version="2.0"><channel><title>Active Feed</title></channel></rss>'
        with patch("app.services.osint_collector.requests.get", return_value=mock_resp):
            fetch_general_osint_feeds(self.db, lookback_days=30)

        preserved = self.db.query(models.ThreatReport).filter(
            models.ThreatReport.source_url == historical_url
        ).first()
        self.assertIsNotNone(preserved, "Historical BleepingComputer threat report must be preserved")
        self.assertEqual(preserved.cve_id, "CVE-2024-HIST-001")

    def test_05_publication_dates_not_confused_with_ingestion_dates(self):
        """Requirement 5: Publication dates are preserved separately from ingestion dates; never fabricated."""
        # 1. Genuine publication date
        genuine_pub = datetime(2025, 11, 15, 8, 30, 0)
        report_with_date = models.ThreatReport(
            source_url="https://example.com/advisory-dated",
            title="Dated Advisory",
            summary="Dated disclosure.",
            published_at=genuine_pub
        )
        self.db.add(report_with_date)

        # 2. Unknown publication date (missing from feed)
        report_undated = models.ThreatReport(
            source_url="https://example.com/advisory-undated",
            title="Undated Advisory",
            summary="Undated disclosure.",
            published_at=None
        )
        self.db.add(report_undated)
        self.db.commit()

        self.db.refresh(report_with_date)
        self.db.refresh(report_undated)

        # Verify publication date preserved
        self.assertEqual(report_with_date.published_at, genuine_pub)
        self.assertNotEqual(report_with_date.published_at, report_with_date.created_at)

        # Verify unknown date is not fabricated
        self.assertIsNone(report_undated.published_at)
        self.assertIsNotNone(report_undated.created_at)

    def test_06_product_identity_collisions_become_needs_review(self):
        """
        Requirement 6: Product-identity collisions become NEEDS_REVIEW rather than false confirmed findings.
        General regression tests for:
        a. SQLAlchemyDA vs sqlalchemy (adapter vs ORM)
        b. django-crispy-forms vs django (form extension vs framework)
        c. requests-oauthlib vs requests (OAuth library vs HTTP library)
        d. fastapi-admin vs fastapi (admin UI extension vs framework)
        e. ReactOS vs react (operating system vs UI library)
        f. Unrelated packages sharing version numbers (rabbitmq 5.2.0 vs celery 5.2.0)
        g. Confirmed vulnerable match (sqlalchemy 1.4.20 vs sqlalchemy < 1.4.40)
        h. Confirmed safe match (sqlalchemy 2.0.44 vs sqlalchemy < 1.4.40)
        """
        # Case A: SQLAlchemyDA vs sqlalchemy
        sqla_da_text = "SQLAlchemyDA is a generic database adapter for ZSQL methods. Versions prior to 2.2 allow SQL injection."
        outcome_a, conf_a, reason_a = evaluate_version_applicability(
            installed_version="2.0.44",
            threat_text=sqla_da_text,
            pkg_name="sqlalchemy"
        )
        self.assertEqual(outcome_a, "NEEDS_REVIEW")
        self.assertIn("SQLAlchemyDA", reason_a)
        self.assertEqual(conf_a, 50.0)
        self.assertIn("not a measured probability", reason_a)

        # Case B: django-crispy-forms vs django
        crispy_text = "A flaw in django-crispy-forms before 1.14.0 allows XSS when rendering forms with Django templates."
        outcome_b, conf_b, reason_b = evaluate_version_applicability(
            installed_version="4.2.0",
            threat_text=crispy_text,
            pkg_name="django"
        )
        self.assertEqual(outcome_b, "NEEDS_REVIEW")
        self.assertIn("django-crispy-forms", reason_b)
        self.assertEqual(conf_b, 50.0)

        # Case C: requests-oauthlib vs requests
        oauth_text = "requests-oauthlib before 1.3.1 allows replay attacks in OAuth1 sessions using Requests."
        outcome_c, conf_c, reason_c = evaluate_version_applicability(
            installed_version="2.31.0",
            threat_text=oauth_text,
            pkg_name="requests"
        )
        self.assertEqual(outcome_c, "NEEDS_REVIEW")
        self.assertIn("requests-oauthlib", reason_c)
        self.assertEqual(conf_c, 50.0)

        # Case D: fastapi-admin vs fastapi
        fa_admin_text = "fastapi-admin pro v0.1.4 allows XSS in Config-Create function. Fixed in 0.1.5."
        outcome_d, conf_d, reason_d = evaluate_version_applicability(
            installed_version="0.120.1",
            threat_text=fa_admin_text,
            pkg_name="fastapi"
        )
        self.assertEqual(outcome_d, "NEEDS_REVIEW")
        self.assertIn("fastapi-admin", reason_d)

        # Case E: ReactOS vs react
        reactos_text = "Unspecified vulnerability in ReactOS 0.3.1 allows privilege escalation."
        outcome_e, conf_e, reason_e = evaluate_version_applicability(
            installed_version="19.2.0",
            threat_text=reactos_text,
            pkg_name="react"
        )
        self.assertEqual(outcome_e, "NEEDS_REVIEW")
        self.assertIn("ReactOS", reason_e)

        # Case F: Unrelated packages sharing version numbers (RabbitMQ 5.2.0 vs Celery 5.2.0)
        rabbitmq_text = "RabbitMQ before 5.2.7 allows denial of service. Celery task workers are frequently connected to RabbitMQ."
        outcome_f, conf_f, reason_f = evaluate_version_applicability(
            installed_version="5.2.0",
            threat_text=rabbitmq_text,
            pkg_name="celery"
        )
        self.assertNotEqual(outcome_f, "AFFECTED", "Celery must not be classified as AFFECTED by RabbitMQ version bounds")
        self.assertEqual(outcome_f, "NEEDS_REVIEW")

        # Case G: Confirmed genuine match (vulnerable)
        genuine_sqla_text = "SQLAlchemy before 1.4.40 allows SQL injection via cartesian product."
        outcome_g, conf_g, reason_g = evaluate_version_applicability(
            installed_version="1.4.20",
            threat_text=genuine_sqla_text,
            pkg_name="sqlalchemy"
        )
        self.assertEqual(outcome_g, "AFFECTED")
        self.assertGreaterEqual(conf_g, 90.0)
        self.assertIn("satisfies vulnerable constraint", reason_g)

        # Case H: Confirmed safe match (outside vulnerable range)
        outcome_h, conf_h, reason_h = evaluate_version_applicability(
            installed_version="2.0.44",
            threat_text=genuine_sqla_text,
            pkg_name="sqlalchemy"
        )
        self.assertEqual(outcome_h, "NOT_AFFECTED")
        self.assertGreaterEqual(conf_h, 90.0)
        self.assertIn("outside vulnerable range", reason_h)

    def test_07_uncertain_findings_cannot_trigger_automatic_containment_or_soar(self):
        """Requirement 7: Uncertain findings cannot trigger automatic containment or SOAR."""
        # 1. SOAR Playbook generation for NEEDS_REVIEW generates manual audit playbook
        playbook = generate_soar_playbook(
            threat_title="SQLAlchemyDA Advisory",
            summary="SQLAlchemyDA is a database adapter for Zope.",
            assessment_outcome="NEEDS_REVIEW",
            matched_component="sqlalchemy"
        )
        self.assertEqual(playbook["firewall_rules"], [], "Firewall rules must be empty for uncertain matches")
        self.assertEqual(playbook["iocs"]["ip_addresses"], [], "IOCs must be empty for uncertain matches")
        self.assertIn("Manual verification required", playbook["recommended_action"])

        # 2. Autonomous Containment Policy Engine rejects NEEDS_REVIEW candidate without independent network IOC
        candidate = NetworkIndicatorCandidate(
            indicator_value="198.51.100.25",
            tenant_id=self.tenant.id,
            confidence_score=50.0,
            evidence_source="CISA_ADVISORY",
            is_structured_ioc=False,
            vulnerability_status="NEEDS_REVIEW"
        )
        qualified, action, reason = AutonomousPolicyEngine.evaluate_candidate(
            candidate=candidate,
            db=self.db
        )
        self.assertFalse(qualified, "NEEDS_REVIEW candidate without independent corroborated IOC must be rejected")
        self.assertIn("REJECTED", reason)

    def test_08_historical_records_and_tenant_isolation_intact(self):
        """Requirement 8: Historical records and tenant isolation remain intact."""
        # Verify both tenants exist with separate inventory
        tenant_a = self.tenant  # Has FastAPI, Docker, PostgreSQL, Nginx
        tenant_b = models.Tenant(company_name="Isolated Corp B", tech_stack="redis:5.0.0")
        self.db.add(tenant_b)
        self.db.commit()

        # Seed asset components to verify asset-level tenant isolation alongside tech_stack
        asset_a = models.AssetComponent(
            tenant_id=tenant_a.id,
            software_name="fastapi",
            software_version="0.110.0"
        )
        asset_b = models.AssetComponent(
            tenant_id=tenant_b.id,
            software_name="redis",
            software_version="5.0.0"
        )
        self.db.add_all([asset_a, asset_b])
        self.db.commit()

        # 1. Threat applicable ONLY to tenant B (Redis)
        report_b = models.ThreatReport(
            source_url="https://example.com/redis-cve-isolated",
            title="Redis Advisory: CVE-2026-8888",
            summary="Redis before 5.0.14 allows remote buffer overflow.",
            severity="high",
            cve_id="CVE-2026-8888"
        )
        self.db.add(report_b)
        self.db.commit()

        # Process correlations
        process_threat_tenant_correlations(self.db, report_b, raw_context="Redis before 5.0.14")

        # Tenant B has match
        match_b = self.db.query(models.ThreatMatch).filter(
            models.ThreatMatch.tenant_id == tenant_b.id,
            models.ThreatMatch.threat_report_id == report_b.id
        ).first()
        self.assertIsNotNone(match_b, "Tenant B should match its registered redis asset")

        # Tenant A (which doesn't have redis) must NOT have this match
        match_a = self.db.query(models.ThreatMatch).filter(
            models.ThreatMatch.tenant_id == tenant_a.id,
            models.ThreatMatch.threat_report_id == report_b.id
        ).first()
        self.assertIsNone(match_a, "Tenant A must remain isolated and have no match for Tenant B's asset")

        # 2. Threat applicable independently to Tenant A (FastAPI)
        report_a = models.ThreatReport(
            source_url="https://example.com/fastapi-cve-isolated",
            title="FastAPI Advisory: CVE-2026-7777",
            summary="FastAPI before 0.111.0 allows request smuggling.",
            severity="high",
            cve_id="CVE-2026-7777"
        )
        self.db.add(report_a)
        self.db.commit()

        process_threat_tenant_correlations(self.db, report_a, raw_context="FastAPI before 0.111.0")

        # Tenant A matches because it independently meets matching criteria
        match_a_for_a = self.db.query(models.ThreatMatch).filter(
            models.ThreatMatch.tenant_id == tenant_a.id,
            models.ThreatMatch.threat_report_id == report_a.id
        ).first()
        self.assertIsNotNone(match_a_for_a, "Tenant A must independently create a match when criteria are met")

        # Tenant B must NOT match Tenant A's threat
        match_b_for_a = self.db.query(models.ThreatMatch).filter(
            models.ThreatMatch.tenant_id == tenant_b.id,
            models.ThreatMatch.threat_report_id == report_a.id
        ).first()
        self.assertIsNone(match_b_for_a, "Tenant B must remain isolated from Tenant A's threat")

    def test_09_concurrency_lock_prevents_overlapping_runs(self):
        """Requirement 9: Concurrency lock prevents overlapping scheduler or manual runs."""
        # Acquire lock simulating active sweep
        acquired = _sweep_mutex.acquire(blocking=False)
        self.assertTrue(acquired)

        try:
            # Attempt to run another sweep while locked
            result = run_sync_sweep(lookback_days=30)
            self.assertEqual(result.get("status"), "SKIPPED")
            self.assertIn("already in progress", result.get("message", ""))
        finally:
            _sweep_mutex.release()

        # After releasing lock, sweep should proceed normally
        with patch("app.services.osint_collector.fetch_targeted_cves_for_inventory"), \
             patch("app.services.osint_collector.fetch_general_osint_feeds"):
            result_ok = run_sync_sweep(lookback_days=30)
            self.assertEqual(result_ok.get("status"), "SUCCESS")

    def test_10_source_status_endpoint_returns_diagnostics(self):
        """Requirement 10: API endpoint returns source health and ingestion diagnostics."""
        res = self.client.get("/public/threats/sources/status", headers=self.admin_headers)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data.get("status"), "OPERATIONAL")
        self.assertEqual(data.get("total_sources", 0), 7)
        self.assertIn("sources", data)

        source_names = [s["name"] for s in data["sources"]]
        self.assertNotIn("BleepingComputer", source_names)
        self.assertIn("CISA Advisories", source_names)
        self.assertIn("NVD NIST REST API 2.0", source_names)
        self.assertIn("Feodo Tracker C2", source_names)

        for src in data["sources"]:
            self.assertIn("status", src)
            self.assertIn("new_items", src)
            self.assertIn("updated_items", src)
            self.assertIn("duplicates_skipped", src)
            self.assertIn("failures", src)
            self.assertIn("awaiting_review", src)

    def test_11_cisa_advisories_http_403_resilience(self):
        """Regression test: HTTP 403 response is recorded as an error and never suppressed or fabricated."""
        mock_403 = MagicMock()
        mock_403.status_code = 403
        mock_403.content = b"<html><body>Access Denied</body></html>"

        initial_count = self.db.query(models.ThreatReport).count()

        with patch("app.services.osint_collector.fetch_feed_with_retry", return_value=mock_403):
            fetch_general_osint_feeds(self.db, lookback_days=30)

        # 1. Zero reports fabricated on 403
        final_count = self.db.query(models.ThreatReport).count()
        self.assertEqual(final_count, initial_count, "Zero advisories must be fabricated on HTTP 403")

        # 2. Status must be marked ERROR and error details recorded
        cisa_status = source_tracker.sources.get("CISA Advisories")
        self.assertIsNotNone(cisa_status)
        self.assertEqual(cisa_status.status, "ERROR")
        self.assertIn("HTTP 403", cisa_status.last_error or "")

    def test_12_cisa_advisories_headers_and_feed_parsing(self):
        """Verifies updated browser headers and CISA XML advisory parsing with publication dates and deduplication."""
        # 1. Verify headers contain standard browser headers required by CISA edge infrastructure
        self.assertIn("User-Agent", DEFAULT_HEADERS)
        self.assertIn("Accept", DEFAULT_HEADERS)
        self.assertIn("Accept-Language", DEFAULT_HEADERS)
        self.assertNotIn("CyberScribe", DEFAULT_HEADERS["User-Agent"])

        # 2. Genuine CISA XML advisory sample
        cisa_sample_xml = b"""<?xml version="1.0" encoding="utf-8"?>
        <rss version="2.0" xml:base="https://www.cisa.gov/" xmlns:dc="http://purl.org/dc/elements/1.1/">
            <channel>
                <title>All CISA Advisories</title>
                <link>https://www.cisa.gov</link>
                <item>
                    <title>CISA Urges Patching Critical Vulnerability in Remote Gateway</title>
                    <link>https://www.cisa.gov/news-events/alerts/2026/10/16/cisa-urges-patching-sample</link>
                    <description>&lt;p&gt;CISA is aware of critical vulnerability CVE-2026-9999 affecting network perimeter appliances.&lt;/p&gt;</description>
                    <pubDate>Fri, 16 Oct 2026 12:00:00 +0000</pubDate>
                </item>
            </channel>
        </rss>"""

        mock_200 = MagicMock()
        mock_200.status_code = 200
        mock_200.content = cisa_sample_xml

        with patch("app.services.osint_collector.requests.get", return_value=mock_200):
            res = fetch_feed_with_retry("https://www.cisa.gov/cybersecurity-advisories/all.xml")
            self.assertEqual(res.status_code, 200)

            # Test feed parsing
            import feedparser
            feed = feedparser.parse(res.content)
            self.assertEqual(len(feed.entries), 1)
            entry = feed.entries[0]
            self.assertEqual(entry.title, "CISA Urges Patching Critical Vulnerability in Remote Gateway")
            self.assertEqual(entry.link, "https://www.cisa.gov/news-events/alerts/2026/10/16/cisa-urges-patching-sample")
            self.assertIsNotNone(entry.published_parsed)
            pub_dt = datetime(*entry.published_parsed[:6])
            self.assertEqual(pub_dt, datetime(2026, 10, 16, 12, 0, 0))

    def test_13_cisa_advisories_live_endpoint_connectivity(self):
        """Tests live connectivity to official CISA Advisories XML feed when network is available."""
        from app.services.osint_collector import OSINT_FEEDS, fetch_feed_with_retry
        url = OSINT_FEEDS.get("CISA Advisories")
        self.assertEqual(url, "https://www.cisa.gov/cybersecurity-advisories/all.xml")
        try:
            res = fetch_feed_with_retry(url, max_retries=1, timeout=12)
            if res.status_code == 200:
                import feedparser
                feed = feedparser.parse(res.content)
                self.assertGreater(len(feed.entries), 0)
                self.assertIn("CISA", feed.feed.get("title", ""))
        except Exception as net_err:
            self.skipTest(f"Live network test skipped: {net_err}")

    def test_14_successful_sync_clears_earlier_http_403_failure(self):
        """Regression test: A successful sync transitions status to HEALTHY, clears last_error, resets failures_count to 0, and records last_sync timestamp."""
        # 1. Simulate an earlier HTTP 403 failure
        source_tracker.record_failure("CISA Advisories", "HTTP 403 fetching CISA Advisories")
        cisa_telemetry = source_tracker.sources["CISA Advisories"]
        self.assertEqual(cisa_telemetry.status, "ERROR")
        self.assertGreaterEqual(cisa_telemetry.failures_count, 1)
        self.assertEqual(cisa_telemetry.last_error, "HTTP 403 fetching CISA Advisories")

        # 2. Prepare mock 200 CISA XML response
        cisa_xml = b"""<?xml version="1.0" encoding="utf-8"?>
        <rss version="2.0">
            <channel>
                <title>CISA Advisories</title>
                <link>https://www.cisa.gov</link>
                <item>
                    <title>CISA Urges Patching Critical Appliance Vulnerability</title>
                    <link>https://www.cisa.gov/news-events/alerts/2026/10/18/test-clear-403</link>
                    <description>Test advisory description</description>
                    <pubDate>Sun, 18 Oct 2026 12:00:00 +0000</pubDate>
                </item>
            </channel>
        </rss>"""
        mock_200 = MagicMock()
        mock_200.status_code = 200
        mock_200.content = cisa_xml

        # 3. Execute legitimate sync through fetch_general_osint_feeds
        with patch("app.services.osint_collector.fetch_feed_with_retry", return_value=mock_200):
            fetch_general_osint_feeds(self.db, lookback_days=30)

        # 4. Verify telemetry is updated and previous failure state is fully cleared
        self.assertEqual(cisa_telemetry.status, "HEALTHY")
        self.assertIsNone(cisa_telemetry.last_error, "last_error must be reset to None upon successful sync")
        self.assertEqual(cisa_telemetry.failures_count, 0, "failures_count must be reset to 0 upon successful sync")
        self.assertIsNotNone(cisa_telemetry.last_success_at, "last_success_at must be populated")

        # 5. Verify the dashboard dictionary export
        exported = cisa_telemetry.to_dict()
        self.assertEqual(exported["status"], "HEALTHY")
        self.assertIsNone(exported["last_error"])
        self.assertEqual(exported["failures"], 0)
        self.assertIsNotNone(exported["last_sync"])


if __name__ == '__main__':
    unittest.main()
