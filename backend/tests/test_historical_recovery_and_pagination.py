import pytest
import os
import sys
from datetime import datetime, timedelta
from fastapi.testclient import TestClient
from sqlalchemy import text

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from main import app
from app.core.database import SessionLocal, engine
from app import models
from app.services.osint_collector import prune_old_threats, is_test_fixture
from app.services.vector_store import add_threat_embedding
from app.core.chroma import get_threat_collection

client = TestClient(app)


def test_zero_deletion_retention():
    """Verify that prune_old_threats retains 100% of historical records and executes 0 deletions."""
    db = SessionLocal()
    try:
        initial_count = db.query(models.ThreatReport).count()
        assert initial_count >= 427, f"Expected at least 427 records, got {initial_count}"

        # Run retention sweep with strict 1-day retention
        prune_old_threats(db, retention_days=1)

        post_prune_count = db.query(models.ThreatReport).count()
        assert post_prune_count == initial_count, f"Pruning deleted records! Initial: {initial_count}, Post: {post_prune_count}"
    finally:
        db.close()


def test_test_fixture_isolation():
    """Verify that mock test fixtures are identified and isolated from live ingestion."""
    assert is_test_fixture(cve_id="CVE-2024-TEST-1234") is True
    assert is_test_fixture(cve_id="CVE-2026-AUTO") is True
    assert is_test_fixture(source_url="manual-feed://mock-report") is True
    assert is_test_fixture(title="[TEST FIXTURE] Mock buffer overflow") is True
    assert is_test_fixture(cve_id="CVE-2024-14043", source_url="https://nvd.nist.gov/vuln/detail/CVE-2024-14043", title="Open5GS Advisory") is False


def test_global_osint_pagination_and_date_filtering():
    """Verify server-side pagination, 90-day default window, and All Time filter."""
    # 1. Default 90-day window (no days param passed or days=90)
    res_def = client.get("/public/threats?page=1&page_size=10")
    assert res_def.status_code == 200
    data_def = res_def.json()
    assert "total" in data_def
    assert "threats" in data_def
    assert data_def["page"] == 1
    assert data_def["page_size"] == 10
    assert len(data_def["threats"]) <= 10

    res_90 = client.get("/public/threats?page=1&page_size=10&days=90")
    assert res_90.status_code == 200
    data_90 = res_90.json()
    assert data_90["total"] == data_def["total"]

    # 2. All Time historical window
    res_all = client.get("/public/threats?page=1&page_size=25&days=all")
    assert res_all.status_code == 200
    data_all = res_all.json()
    assert data_all["total"] >= 427, f"Expected at least 427 total reports in all time view, got {data_all['total']}"
    assert data_all["page_size"] == 25
    assert len(data_all["threats"]) == 25
    assert data_all["total_pages"] >= 18

    # 3. Severity filter
    res_high = client.get("/public/threats?page=1&page_size=10&days=all&severity=HIGH")
    assert res_high.status_code == 200
    data_high = res_high.json()
    for item in data_high["threats"]:
        assert item["severity"].lower() == "high"


def test_chromadb_idempotence():
    """Verify that vector store embeddings use deterministic upsert and do not produce duplicates."""
    collection = get_threat_collection()
    initial_chroma_count = collection.count()
    assert initial_chroma_count >= 518

    # Re-index a test ID
    success = add_threat_embedding(
        threat_id="test-idempotent-check",
        title="Test Idempotency Advisory",
        summary="Testing that re-upserting does not duplicate vectors",
        severity="low",
        source_url="https://example.com/test-idempotent"
    )
    assert success is True

    count_after_first = collection.count()

    # Repeat upsert with same ID
    add_threat_embedding(
        threat_id="test-idempotent-check",
        title="Test Idempotency Advisory Updated",
        summary="Testing that re-upserting does not duplicate vectors",
        severity="low",
        source_url="https://example.com/test-idempotent"
    )

    count_after_second = collection.count()
    assert count_after_second == count_after_first, "Duplicate vector created on re-indexing!"


def test_database_no_duplicate_reports():
    """Verify that threat_reports table has zero duplicate primary keys or IDs."""
    db = SessionLocal()
    try:
        dups = db.execute(text("SELECT id, COUNT(*) FROM threat_reports GROUP BY id HAVING COUNT(*) > 1")).fetchall()
        assert len(dups) == 0, f"Found duplicate IDs in threat_reports: {dups}"

        # Verify no orphaned threat matches
        orphans = db.execute(text("SELECT m.id FROM _threat_matches m LEFT JOIN threat_reports t ON m.threat_report_id = t.id WHERE t.id IS NULL")).fetchall()
        assert len(orphans) == 0, f"Found orphaned threat matches: {orphans}"
    finally:
        db.close()
