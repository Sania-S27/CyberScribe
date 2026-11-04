"""
Tests for Structured Threat Indicator Ingestion
------------------------------------------------
Validates:
1. Parsing and validation of structured IPv4 indicators.
2. Grounded deterministic confidence from feed telemetry (no LLMs).
3. Preservation of provenance and observation timestamps.
4. Autonomous policy evaluation and automatic hand-off to SimulatedFirewallAdapter.
5. Rejection handling: malformed IPs, bogons/private IPs, protected IPs, missing timestamps,
   stale/expired indicators, untrusted sources, and low confidence.
6. Tenant isolation and duplicate action prevention.
7. End-to-end feed ingestion orchestration with simulated staging.
"""

import os
import sys
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch, MagicMock

backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from tests.base import BaseTestCase
from app import models
from app.models import ContainmentAction, ContainmentAuditLog
from app.services.structured_indicator_collector import (
    process_structured_indicator_record,
    ingest_and_process_structured_indicators,
    calculate_grounded_confidence,
    parse_timestamp,
    SOURCE_NAME
)


class TestStructuredIndicatorIngestion(BaseTestCase):

    def setUp(self):
        super().setUp()
        self.tenant_b = models.Tenant(
            company_name="Bravo Defense Systems",
            tech_stack="Python:3.11, FastAPI:0.110, Nginx:1.24",
            webhook_url="https://mock-soar-webhook.bravo.local/containment",
            auth_token="BRAVO_AUTH_TOKEN_778899"
        )
        self.db.add(self.tenant_b)
        self.db.commit()
        self.db.refresh(self.tenant_b)

    # -------------------------------------------------------------------------
    # 1. Grounded Confidence & Timestamp Parsing
    # -------------------------------------------------------------------------

    def test_grounded_confidence_calculation(self):
        # Online C2 receives 95.0%
        self.assertEqual(calculate_grounded_confidence({"status": "online"}), 95.0)
        # Offline C2 receives 88.0%
        self.assertEqual(calculate_grounded_confidence({"status": "offline"}), 88.0)
        # Ambiguous / unverified status receives 65.0% (below 85% policy threshold)
        self.assertEqual(calculate_grounded_confidence({"status": "unknown"}), 65.0)
        self.assertEqual(calculate_grounded_confidence({}), 65.0)

    def test_parse_timestamp_formats(self):
        # Standard datetime strings
        dt1 = parse_timestamp("2026-10-11 08:30:00")
        self.assertIsNotNone(dt1)
        self.assertEqual(dt1.year, 2026)
        self.assertEqual(dt1.month, 10)
        self.assertEqual(dt1.day, 11)

        # Date only
        dt2 = parse_timestamp("2026-10-10")
        self.assertIsNotNone(dt2)
        self.assertEqual(dt2.day, 10)

        # ISO 8601 with Z and timezone offsets
        dt_z = parse_timestamp("2026-10-11T08:30:00Z")
        self.assertIsNotNone(dt_z)
        self.assertEqual(dt_z.hour, 8)

        dt_offset = parse_timestamp("2026-10-11T08:30:00+00:00")
        self.assertIsNotNone(dt_offset)
        self.assertEqual(dt_offset.hour, 8)

        # Timezone conversion from -05:00 to UTC (08:30 -05:00 == 13:30 UTC)
        dt_est = parse_timestamp("2026-10-11T08:30:00-05:00")
        self.assertIsNotNone(dt_est)
        self.assertEqual(dt_est.hour, 13)

        # Timezone-aware datetime object
        dt_aware = datetime(2026, 10, 11, 8, 30, tzinfo=timezone.utc)
        dt_parsed_aware = parse_timestamp(dt_aware)
        self.assertIsNone(dt_parsed_aware.tzinfo)
        self.assertEqual(dt_parsed_aware.hour, 8)

        # None / invalid
        self.assertIsNone(parse_timestamp(None))
        self.assertIsNone(parse_timestamp("invalid-date-string"))

    # -------------------------------------------------------------------------
    # 2. Valid Indicator Processing & Automated Simulated Staging
    # -------------------------------------------------------------------------

    def test_valid_active_indicator_qualifies_and_stages_simulated_rule(self):
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        record = {
            "ip_address": "185.220.101.5",
            "port": 443,
            "status": "online",
            "hostname": "c2-node-185.tor-exit.net",
            "as_number": 60729,
            "as_name": "TOR-EXIT-ASN",
            "country": "DE",
            "first_seen": (now - timedelta(days=2)).strftime("%Y-%m-%d %H:%M:%S"),
            "last_online": (now - timedelta(hours=3)).strftime("%Y-%m-%d %H:%M:%S"),
            "malware": "QakBot"
        }

        success, action, outcome = process_structured_indicator_record(
            record=record,
            tenant=self.tenant,
            db=self.db,
            source_name=SOURCE_NAME
        )

        self.assertTrue(success, f"Expected success but got outcome: {outcome}")
        self.assertIsNotNone(action)
        # Verify action transitioned automatically to SIMULATED
        self.assertEqual(action.status, "SIMULATED")
        self.assertEqual(outcome, "SIMULATED")
        self.assertEqual(action.indicator_value, "185.220.101.5")
        self.assertEqual(action.tenant_id, self.tenant.id)
        self.assertIsNotNone(action.applied_at)
        self.assertIn("[SIMULATED]", action.execution_output)

        # Verify audit logs created: POLICY_EVALUATION followed by SIMULATION_APPLIED
        audit_logs = self.db.query(ContainmentAuditLog).filter(
            ContainmentAuditLog.action_id == action.id
        ).order_by(ContainmentAuditLog.created_at.asc()).all()

        event_types = [a.event_type for a in audit_logs]
        self.assertIn("POLICY_EVALUATION", event_types)
        self.assertIn("SIMULATION_APPLIED", event_types)

    def test_port_stripping_and_host_normalization(self):
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        record = {
            "ip_address": "185.220.101.12:8080",  # IP with port attached
            "port": 8080,
            "status": "online",
            "last_online": now.strftime("%Y-%m-%d %H:%M:%S"),
            "malware": "Emotet"
        }

        success, action, outcome = process_structured_indicator_record(
            record=record,
            tenant=self.tenant,
            db=self.db
        )

        self.assertTrue(success)
        self.assertEqual(action.indicator_value, "185.220.101.12")
        self.assertEqual(action.status, "SIMULATED")

    # -------------------------------------------------------------------------
    # 3. Policy Rejection Test Cases
    # -------------------------------------------------------------------------

    def test_malformed_ip_rejected(self):
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        record = {
            "ip_address": "999.999.999.999",
            "status": "online",
            "last_online": now.strftime("%Y-%m-%d"),
            "malware": "QakBot"
        }
        success, action, reason = process_structured_indicator_record(record, self.tenant, self.db)
        self.assertFalse(success)
        self.assertIsNone(action)
        self.assertEqual(reason, "REJECTED_MALFORMED_IP_ADDRESS")

    def test_bogon_and_private_ip_rejected(self):
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        bogon_records = [
            ({"ip_address": "127.0.0.1", "status": "online", "last_online": now.strftime("%Y-%m-%d")}, "REJECTED_LOOPBACK_ADDRESS"),
            ({"ip_address": "10.0.0.1", "status": "online", "last_online": now.strftime("%Y-%m-%d")}, "REJECTED_PRIVATE_ADDRESS"),
            ({"ip_address": "192.168.1.1", "status": "online", "last_online": now.strftime("%Y-%m-%d")}, "REJECTED_PRIVATE_ADDRESS"),
            ({"ip_address": "169.254.1.1", "status": "online", "last_online": now.strftime("%Y-%m-%d")}, "REJECTED_LINK_LOCAL_ADDRESS"),
            ({"ip_address": "224.0.0.1", "status": "online", "last_online": now.strftime("%Y-%m-%d")}, "REJECTED_MULTICAST_ADDRESS"),
            ({"ip_address": "255.255.255.255", "status": "online", "last_online": now.strftime("%Y-%m-%d")}, "REJECTED_BROADCAST_ADDRESS"),
        ]
        for rec, expected_err in bogon_records:
            success, action, reason = process_structured_indicator_record(rec, self.tenant, self.db)
            self.assertFalse(success)
            self.assertIsNone(action)
            self.assertEqual(reason, expected_err)

    def test_protected_infrastructure_ip_rejected(self):
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        record = {
            "ip_address": "8.8.8.8",
            "status": "online",
            "last_online": now.strftime("%Y-%m-%d"),
            "malware": "Spoofed_DNS"
        }
        success, action, reason = process_structured_indicator_record(record, self.tenant, self.db)
        self.assertFalse(success)
        self.assertIsNone(action)
        self.assertEqual(reason, "REJECTED_PROTECTED_INFRASTRUCTURE_IP")

    def test_missing_timestamp_rejected(self):
        record = {
            "ip_address": "185.220.101.50",
            "status": "online",
            "last_online": None,
            "first_seen": None,
            "malware": "QakBot"
        }
        success, action, reason = process_structured_indicator_record(record, self.tenant, self.db)
        self.assertFalse(success)
        self.assertIsNone(action)
        self.assertEqual(reason, "REJECTED_MISSING_EVIDENCE_TIMESTAMP")

    def test_stale_indicator_rejected(self):
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        stale_date = (now - timedelta(days=20)).strftime("%Y-%m-%d %H:%M:%S")
        record = {
            "ip_address": "185.220.101.60",
            "status": "online",
            "last_online": stale_date,
            "malware": "QakBot"
        }
        success, action, reason = process_structured_indicator_record(record, self.tenant, self.db)
        self.assertFalse(success)
        self.assertIsNone(action)
        self.assertIn("REJECTED_EXPIRED_INDICATOR_EVIDENCE", reason)

    def test_untrusted_source_rejected(self):
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        record = {
            "ip_address": "185.220.101.70",
            "status": "online",
            "last_online": now.strftime("%Y-%m-%d %H:%M:%S"),
            "malware": "QakBot"
        }
        success, action, reason = process_structured_indicator_record(
            record=record,
            tenant=self.tenant,
            db=self.db,
            source_name="UNTRUSTED_SCRAPER_FEED"
        )
        self.assertFalse(success)
        self.assertIsNone(action)
        self.assertIn("REJECTED_UNTRUSTED_EVIDENCE_SOURCE", reason)

    def test_low_confidence_rejected(self):
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        # Status 'unknown' results in 65.0% confidence, below the 85.0% policy requirement
        record = {
            "ip_address": "185.220.101.80",
            "status": "unknown",
            "last_online": now.strftime("%Y-%m-%d %H:%M:%S"),
            "malware": "Unconfirmed_Sample"
        }
        success, action, reason = process_structured_indicator_record(record, self.tenant, self.db)
        self.assertFalse(success)
        self.assertIsNone(action)
        self.assertIn("REJECTED_INSUFFICIENT_CONFIDENCE", reason)

    # -------------------------------------------------------------------------
    # 4. Multi-Tenant Isolation & Duplicate Action Prevention
    # -------------------------------------------------------------------------

    def test_duplicate_indicator_rejected_for_same_tenant(self):
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        record = {
            "ip_address": "185.220.101.90",
            "status": "online",
            "last_online": now.strftime("%Y-%m-%d %H:%M:%S"),
            "malware": "QakBot"
        }

        # First ingestion qualifies and stages
        success1, action1, outcome1 = process_structured_indicator_record(record, self.tenant, self.db)
        self.assertTrue(success1)
        self.assertEqual(action1.status, "SIMULATED")

        # Second ingestion for same tenant must be rejected as duplicate
        success2, action2, reason2 = process_structured_indicator_record(record, self.tenant, self.db)
        self.assertFalse(success2)
        self.assertIsNone(action2)
        self.assertIn("REJECTED_DUPLICATE_ACTIVE_CONTAINMENT_ACTION", reason2)

    def test_tenant_isolation_allows_independent_containment_across_tenants(self):
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        record = {
            "ip_address": "185.220.101.95",
            "status": "online",
            "last_online": now.strftime("%Y-%m-%d %H:%M:%S"),
            "malware": "QakBot"
        }

        # Tenant A containment
        success_a, action_a, _ = process_structured_indicator_record(record, self.tenant, self.db)
        self.assertTrue(success_a)

        # Tenant B containment for same IP should qualify independently
        success_b, action_b, _ = process_structured_indicator_record(record, self.tenant_b, self.db)
        self.assertTrue(success_b)

        self.assertNotEqual(action_a.tenant_id, action_b.tenant_id)
        self.assertNotEqual(action_a.id, action_b.id)
        self.assertEqual(action_a.status, "SIMULATED")
        self.assertEqual(action_b.status, "SIMULATED")

    def test_tenant_rollback_independence(self):
        """Verifies that rolling back or expiring an action for Tenant A does NOT affect Tenant B's active action."""
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        record = {
            "ip_address": "185.220.101.98",
            "status": "online",
            "last_online": now.strftime("%Y-%m-%d %H:%M:%S"),
            "malware": "QakBot"
        }

        # Stage for Tenant A and Tenant B
        _, action_a, _ = process_structured_indicator_record(record, self.tenant, self.db)
        _, action_b, _ = process_structured_indicator_record(record, self.tenant_b, self.db)

        self.assertEqual(action_a.status, "SIMULATED")
        self.assertEqual(action_b.status, "SIMULATED")

        # Roll back Tenant A's containment
        from app.services.firewall_adapter import SimulatedFirewallAdapter
        SimulatedFirewallAdapter.rollback_containment(action_a, self.db, reason="TENANT_A_MANUAL_OVERRIDE")

        self.db.refresh(action_a)
        self.db.refresh(action_b)

        self.assertEqual(action_a.status, "ROLLED_BACK")
        self.assertEqual(action_b.status, "SIMULATED", "Tenant B's containment must remain active and unaffected by Tenant A's rollback")

    def test_invalid_tenant_fails_relevance_check(self):
        """Verifies that an indicator evaluated for an invalid or deleted tenant is rejected."""
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        record = {
            "ip_address": "185.220.101.99",
            "status": "online",
            "last_online": now.strftime("%Y-%m-%d %H:%M:%S"),
            "malware": "QakBot"
        }
        # Fake tenant object not saved in DB
        fake_tenant = models.Tenant(id="non-existent-tenant-uuid-12345", company_name="Ghost Corp")
        success, action, reason = process_structured_indicator_record(record, fake_tenant, self.db)
        self.assertFalse(success)
        self.assertIsNone(action)
        self.assertEqual(reason, "REJECTED_INVALID_OR_MISSING_TENANT")

    # -------------------------------------------------------------------------
    # 5. Full Ingestion Orchestrator Batch Processing
    # -------------------------------------------------------------------------

    def test_ingest_and_process_structured_indicators_batch(self):
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        feed_fixture = [
            # Valid active C2
            {
                "ip_address": "185.220.101.101",
                "port": 443,
                "status": "online",
                "malware": "QakBot",
                "last_online": now.strftime("%Y-%m-%d %H:%M:%S")
            },
            # Stale C2 (should be rejected)
            {
                "ip_address": "185.220.101.102",
                "port": 8080,
                "status": "online",
                "malware": "Emotet",
                "last_online": (now - timedelta(days=15)).strftime("%Y-%m-%d %H:%M:%S")
            },
            # Private IP (should be rejected)
            {
                "ip_address": "192.168.1.50",
                "port": 443,
                "status": "online",
                "malware": "Test",
                "last_online": now.strftime("%Y-%m-%d %H:%M:%S")
            }
        ]

        summary = ingest_and_process_structured_indicators(
            db=self.db,
            raw_indicators=feed_fixture,
            target_tenant_id=self.tenant.id
        )

        self.assertEqual(summary["status"], "COMPLETED")
        self.assertEqual(summary["total_indicators_received"], 3)
        self.assertEqual(summary["qualified_actions"], 1)
        self.assertEqual(summary["rejected_actions"], 2)
        self.assertEqual(len(summary["actions"]), 1)
        self.assertEqual(summary["actions"][0]["indicator"], "185.220.101.101")
        self.assertEqual(summary["actions"][0]["status"], "SIMULATED")
        self.assertTrue(summary["actions"][0]["is_simulated"])
