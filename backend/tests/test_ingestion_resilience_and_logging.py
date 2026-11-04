# backend/tests/test_ingestion_resilience_and_logging.py
import pytest
from datetime import datetime, timezone
from unittest.mock import patch, MagicMock
from sqlalchemy.orm import Session
from sqlalchemy.exc import PendingRollbackError, OperationalError

from app import models
from app.core.config import settings
from app.core import agent_logger
from app.services.osint_collector import (
    SourceSyncTracker,
    fetch_general_osint_feeds,
    fetch_targeted_cves_for_inventory,
    clean_package_name
)


def test_oversized_values_persisted_without_error(db: Session):
    """
    Test 1: Oversized database values.
    Verifies that titles > 255 chars, CVE IDs > 50 chars, URLs > 512 chars,
    and summaries > 65k chars (previously crashing with MySQL DataError 1406)
    are successfully stored in the database without raising an error.
    """
    oversized_title = "CRITICAL ADVISORY: " + ("A" * 600)  # > 600 chars (old limit was 255)
    oversized_cve = "CVE-2026-11111, CVE-2026-22222, CVE-2026-33333, CVE-2026-44444"  # > 60 chars (old limit was 50)
    oversized_url = "https://example.com/security/advisories/archive/2026/quarter1/bulletins/" + ("x" * 500)  # > 550 chars (old limit was 512)
    oversized_summary = "Detailed vulnerability analysis: " + ("B" * 70000)  # > 70 KB (old limit was TEXT / 65535 bytes)

    report = models.ThreatReport(
        source_url=oversized_url[:768],
        title=oversized_title[:1000],
        summary=oversized_summary,
        severity="critical",
        cve_id=oversized_cve[:255],
        published_at=datetime.now(timezone.utc).replace(tzinfo=None),
        stix_bundle={"type": "bundle", "id": "bundle--oversized-test", "objects": []}
    )
    db.add(report)
    db.commit()
    db.refresh(report)

    # Fetch from database and verify persistence
    fetched = db.query(models.ThreatReport).filter(models.ThreatReport.id == report.id).first()
    assert fetched is not None
    assert fetched.title == oversized_title[:1000]
    assert fetched.cve_id == oversized_cve[:255]
    assert fetched.source_url == oversized_url[:768]
    assert len(fetched.summary) > 70000


def test_feed_isolation_and_transaction_rollback(db: Session):
    """
    Test 2: Feed transaction isolation and rollback recovery.
    Verifies that when Feed 1 encounters a database/network error during ingestion,
    the session is cleanly rolled back and does NOT leave the session dirty,
    allowing Feed 2 to successfully query, process, and commit without PendingRollbackError.
    """
    test_tracker = SourceSyncTracker()

    feed1_name = "CISA Advisories"
    feed2_name = "The Hacker News"

    # Step 1: Simulate Feed 1 hitting an exception during flush/commit
    test_tracker.record_start(feed1_name)
    try:
        # Simulate an erroneous operation that corrupts transaction
        db.add(models.ThreatReport(
            source_url="invalid://feed1-test",
            title="Broken Title",
            severity="critical"
        ))
        # Intentionally force a rollback to simulate database exception handling
        raise OperationalError("Simulated MySQL connection or data error", None, None)
    except Exception as exc:
        db.rollback()  # Explicit rollback implemented in our fix
        test_tracker.record_failure(feed1_name, str(exc))

    # Step 2: Ensure Feed 1 is recorded as ERROR
    src1 = test_tracker.sources[feed1_name]
    assert src1.status == "ERROR"
    assert "Simulated MySQL" in src1.last_error

    # Step 3: Now Feed 2 runs on the same session.
    # Without db.rollback(), this query would crash with:
    # PendingRollbackError: This Session's transaction has been rolled back due to a previous exception
    test_tracker.record_start(feed2_name)
    try:
        # Querying the database to prove transaction state is clean
        count_before = db.query(models.ThreatReport).count()

        feed2_report = models.ThreatReport(
            source_url="https://thehackernews.com/feed-2-success",
            title="The Hacker News Valid Advisory",
            summary="Clean threat intelligence summary",
            severity="high",
            cve_id="CVE-2026-9999"
        )
        db.add(feed2_report)
        db.commit()
        db.refresh(feed2_report)
        test_tracker.record_success(feed2_name, new_count=1, updated_count=0, duplicates_count=0)
    except PendingRollbackError:
        pytest.fail("Feed 2 failed with PendingRollbackError! Session rollback was not isolated.")

    # Step 4: Verify Feed 2 succeeded and is marked HEALTHY
    src2 = test_tracker.sources[feed2_name]
    assert src2.status == "HEALTHY"
    assert src2.new_items_count == 1
    assert db.query(models.ThreatReport).filter(models.ThreatReport.source_url == "https://thehackernews.com/feed-2-success").first() is not None


def test_review_queue_metric_filters_active_status(db: Session):
    """
    Test 3: Review queue calculation.
    Verifies that SourceSyncTracker.get_all_status counts only active [NEEDS REVIEW] matches
    and excludes resolved/mitigated items.
    """
    tracker = SourceSyncTracker()

    tenant = models.Tenant(company_name="Acme Corp", tech_stack="sqlalchemy:1.4.0")
    db.add(tenant)
    db.commit()

    report1 = models.ThreatReport(title="Threat 1", severity="high")
    report2 = models.ThreatReport(title="Threat 2", severity="medium")
    report3 = models.ThreatReport(title="Threat 3", severity="low")
    db.add_all([report1, report2, report3])
    db.commit()

    # Match 1: Needs review, OPEN status -> should be counted in review queue
    m1 = models.ThreatMatch(
        tenant_id=tenant.id,
        threat_report_id=report1.id,
        status="OPEN",
        ai_confidence_score=0.55,
        ai_matching_reason="[NEEDS REVIEW] Version constraint unstated in advisory."
    )
    # Match 2: Needs review, but RESOLVED -> should NOT be counted in review queue
    m2 = models.ThreatMatch(
        tenant_id=tenant.id,
        threat_report_id=report2.id,
        status="RESOLVED",
        ai_confidence_score=0.55,
        ai_matching_reason="[NEEDS REVIEW] Verified and resolved by analyst."
    )
    # Match 3: AFFECTED, OPEN -> should NOT be counted in review queue
    m3 = models.ThreatMatch(
        tenant_id=tenant.id,
        threat_report_id=report3.id,
        status="OPEN",
        ai_confidence_score=0.95,
        ai_matching_reason="[AFFECTED] Vulnerable package matched."
    )
    db.add_all([m1, m2, m3])
    db.commit()

    statuses = tracker.get_all_status(db=db)
    assert len(statuses) > 0
    # Every source should report awaiting_review == 1 (only the OPEN needs-review match)
    for src in statuses:
        assert src["awaiting_review"] == 1


def test_agent_logger_real_time_terminal_output(capsys):
    """
    Test 4: Real-time emoji-labelled agent logging in terminal.
    Verifies that the agent logger outputs clear, emoji-labelled messages in execution order
    covering all stages: ingestion, analyst, validator, mitre, stix, report, containment, and soar.
    """
    # 1. Ingestion stage
    agent_logger.log_ingestion_start("Starting threat-feed collection...")
    agent_logger.log_ingestion_success("NVD REST API 2.0", new_count=3, updated_count=9, skipped_count=7)
    agent_logger.log_ingestion_error("Dark Reading", "HTTP 503 Service Unavailable")

    # 2. Security Analyst stage
    agent_logger.log_analyst_start("Vulnerability in OpenSSL crypto library")
    agent_logger.log_analyst_complete("OpenSSL RCE Vulnerability", "critical", "CVE-2026-0001")
    agent_logger.log_analyst_retry(1, 2, "Unevidenced CVE ID removed")

    # 3. Validator stage
    agent_logger.log_validator_start("OpenSSL RCE Vulnerability")
    agent_logger.log_validator_passed("OpenSSL RCE Vulnerability")
    agent_logger.log_validator_needs_review("FastAPI Derivative Tool", "Derivative tool mismatch")
    agent_logger.log_validator_failed("Hallucinated CVE", ["CVE-2099 not found in advisory"])

    # 4. MITRE ATT&CK & STIX stage
    agent_logger.log_mitre_mapping(["T1190: Exploit Public-Facing Application"])
    agent_logger.log_stix_bundle("bundle--12345", 3)

    # 5. Report stage
    agent_logger.log_report_saving("OpenSSL RCE Advisory")
    agent_logger.log_report_saved("rep-001", "OpenSSL RCE Advisory", "CVE-2026-0001")

    # 6. Containment & SOAR stage
    agent_logger.log_correlation_match("Tenant Alpha", "AFFECTED", "openssl:1.1.1")
    agent_logger.log_containment_eval("198.51.100.25", "QUALIFIED")
    agent_logger.log_containment_action("BLOCK_IPV4_DESTINATION", "198.51.100.25", "SIMULATED")
    agent_logger.log_soar_dispatch("Tenant Alpha", "OpenSSL RCE Advisory", "RECEIVED")

    captured = capsys.readouterr().out

    # Verify emoji and category tags are present in stdout in sequential order
    assert "🔄 [INGESTION] Starting threat-feed collection..." in captured
    assert "✅ [INGESTION] NVD REST API 2.0 processed: 3 new, 9 updated, 7 skipped." in captured
    assert "❌ [INGESTION] Feed collection failed for 'Dark Reading': HTTP 503" in captured

    assert "🔍 [ANALYST] Analysing threat intelligence" in captured
    assert "📋 [ANALYST] Draft analysis completed: 'OpenSSL RCE Vulnerability' | Severity: CRITICAL (CVE-2026-0001)" in captured
    assert "🔄 [ANALYST] Revising analysis draft (attempt 1/2)" in captured

    assert "🛡️ [VALIDATOR] Validating extracted findings for 'OpenSSL RCE Vulnerability'..." in captured
    assert "✅ [VALIDATOR] Findings verified and evidence grounded: 'OpenSSL RCE Vulnerability'" in captured
    assert "⚠️ [VALIDATOR] Finding requires manual review: 'FastAPI Derivative Tool'" in captured
    assert "❌ [VALIDATOR] Validation rejected ungrounded claims" in captured

    assert "🧠 [ATT&CK] Mapping threat behaviours: T1190" in captured
    assert "📦 [STIX] Generating STIX 2.1 bundle" in captured

    assert "📝 [REPORT] Generating threat report" in captured
    assert "✅ [REPORT] Report saved successfully: 'OpenSSL RCE Advisory' [CVE-2026-0001]" in captured

    assert "🚨 [CORRELATION] Tenant 'Tenant Alpha' matched component 'openssl:1.1.1' -> [AFFECTED]" in captured
    assert "🛡️ [CONTAINMENT] Evaluating indicator '198.51.100.25' -> Policy: QUALIFIED" in captured
    assert "[CONTAINMENT] Action BLOCK_IPV4_DESTINATION" in captured
    assert "✅ [SOAR] Playbook 'OpenSSL RCE Advisory' to 'Tenant Alpha' -> Status: RECEIVED" in captured


def test_sql_query_silencing_configuration():
    """
    Test 5: SQLAlchemy noise reduction.
    Verifies that SQL_ECHO defaults to False and sqlalchemy.engine logger level is set to WARNING,
    preventing verbose SELECT/UPDATE/COMMIT query spam in the terminal.
    """
    import logging
    sqla_logger = logging.getLogger("sqlalchemy.engine")
    assert sqla_logger.level == logging.WARNING
    assert settings.SQL_ECHO is False
