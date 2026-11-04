"""
Tests for Phase 1 Autonomous Threat Containment:
------------------------------------------------
1. Deterministic Policy Engine IP validation and bogon filters.
2. High-confidence, recency, and trusted evidence source policy qualification.
3. Separation of vulnerability assessment (CVE) from network containment.
4. Tenant isolation and duplicate action prevention.
5. Simulated firewall adapter lifecycle (SIMULATED, verify, rollback, expire) and invalid state transitions.
6. Audit logging and secrets redaction.
7. Regression test for SOAR webhook lifecycle: RECEIVED delivery does NOT mark ThreatMatch RESOLVED.
"""

import os
import sys
import uuid
import ipaddress
from datetime import datetime, timedelta, timezone
from unittest.mock import patch, MagicMock

backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from tests.base import BaseTestCase
from app import models
from app.models import ContainmentAction, ContainmentAuditLog
from app.services.containment_policy import (
    AutonomousPolicyEngine,
    NetworkIndicatorCandidate,
    MIN_CONFIDENCE_THRESHOLD,
    MAX_INDICATOR_AGE_DAYS,
    PROTECTED_IPV4_HOSTS,
    sanitize_audit_details
)
from app.services.firewall_adapter import (
    SimulatedFirewallAdapter,
    InvalidStateTransitionError
)
from app.services.osint_collector import process_threat_tenant_correlations


class TestAutonomousContainmentPolicy(BaseTestCase):

    def setUp(self):
        super().setUp()
        # Create a second tenant for multi-tenant isolation tests
        self.tenant_b = models.Tenant(
            company_name="Beta Global Security",
            tech_stack="Python:3.11, Django:4.2, PostgreSQL:14",
            webhook_url="https://mock-soar-webhook.beta.local/containment",
            auth_token="BETA_SECRET_TOKEN_445566"
        )
        self.db.add(self.tenant_b)
        self.db.commit()
        self.db.refresh(self.tenant_b)

    # -------------------------------------------------------------------------
    # 1. Deterministic IP Validation & Bogon Filtering
    # -------------------------------------------------------------------------

    def test_valid_public_ipv4_passes_validation(self):
        valid_ips = ["185.220.101.5", "93.184.216.34", "151.101.1.69", "142.250.190.46"]
        for ip in valid_ips:
            valid, parsed, err = AutonomousPolicyEngine.validate_ip_address(ip)
            self.assertTrue(valid, f"Expected {ip} to be valid, got error {err}")
            self.assertIsInstance(parsed, ipaddress.IPv4Address)
            self.assertIsNone(err)

    def test_bogon_and_private_ips_rejected(self):
        bogon_cases = [
            ("127.0.0.1", "REJECTED_LOOPBACK_ADDRESS"),
            ("127.0.0.53", "REJECTED_LOOPBACK_ADDRESS"),
            ("10.0.0.1", "REJECTED_PRIVATE_ADDRESS"),
            ("192.168.1.100", "REJECTED_PRIVATE_ADDRESS"),
            ("172.16.0.1", "REJECTED_PRIVATE_ADDRESS"),
            ("198.51.100.25", "REJECTED_PRIVATE_ADDRESS"),
            ("203.0.113.42", "REJECTED_PRIVATE_ADDRESS"),
            ("169.254.1.1", "REJECTED_LINK_LOCAL_ADDRESS"),
            ("224.0.0.1", "REJECTED_MULTICAST_ADDRESS"),
            ("239.255.255.250", "REJECTED_MULTICAST_ADDRESS"),
            ("240.0.0.1", "REJECTED_RESERVED_ADDRESS"),
            ("0.0.0.0", "REJECTED_UNSPECIFIED_ADDRESS"),
            ("255.255.255.255", "REJECTED_BROADCAST_ADDRESS"),
        ]
        for ip, expected_err in bogon_cases:
            valid, _, err = AutonomousPolicyEngine.validate_ip_address(ip)
            self.assertFalse(valid, f"Expected {ip} to be rejected")
            self.assertEqual(err, expected_err)

    def test_protected_infrastructure_ips_rejected(self):
        protected_ips = ["8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9"]
        for ip in protected_ips:
            valid, _, err = AutonomousPolicyEngine.validate_ip_address(ip)
            self.assertFalse(valid)
            self.assertEqual(err, "REJECTED_PROTECTED_INFRASTRUCTURE_IP")

    def test_malformed_and_ipv6_addresses_rejected(self):
        invalid_inputs = [
            ("not-an-ip", "REJECTED_MALFORMED_IP_ADDRESS"),
            ("999.999.999.999", "REJECTED_MALFORMED_IP_ADDRESS"),
            ("192.168.1.1/24", "REJECTED_MALFORMED_IP_ADDRESS"),
            ("2001:db8::1", "REJECTED_NON_IPV4_ADDRESS_FAMILY"),
            ("", "REJECTED_EMPTY_OR_NON_STRING_IP"),
            (None, "REJECTED_EMPTY_OR_NON_STRING_IP"),
        ]
        for val, expected_err in invalid_inputs:
            valid, _, err = AutonomousPolicyEngine.validate_ip_address(val)
            self.assertFalse(valid)
            self.assertEqual(err, expected_err)

    # -------------------------------------------------------------------------
    # 2. Deterministic Policy Engine Candidate Qualification
    # -------------------------------------------------------------------------

    def test_qualifying_candidate_creates_pending_action_and_audit(self):
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        candidate = NetworkIndicatorCandidate(
            indicator_value="185.220.101.5",
            tenant_id=self.tenant.id,
            confidence_score=92.5,
            evidence_source="CISA_IOC",
            is_structured_ioc=True,
            evidence_summary="Verified malicious C2 node observed conducting active scanning.",
            observed_at=now - timedelta(hours=2),
            ttl_seconds=3600
        )

        qualified, action, reason = AutonomousPolicyEngine.evaluate_candidate(candidate, self.db)
        self.assertTrue(qualified)
        self.assertIsNotNone(action)
        self.assertEqual(reason, "QUALIFIED")
        self.assertEqual(action.status, "PENDING")
        self.assertEqual(action.policy_decision, "QUALIFIED")
        self.assertEqual(action.indicator_value, "185.220.101.5")
        self.assertEqual(action.tenant_id, self.tenant.id)

        # Verify audit log was recorded
        audit = self.db.query(ContainmentAuditLog).filter(
            ContainmentAuditLog.action_id == action.id
        ).first()
        self.assertIsNotNone(audit)
        self.assertEqual(audit.event_type, "POLICY_EVALUATION")
        self.assertEqual(audit.details["decision"], "QUALIFIED")

    def test_low_confidence_candidate_rejected(self):
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        candidate = NetworkIndicatorCandidate(
            indicator_value="185.220.101.5",
            tenant_id=self.tenant.id,
            confidence_score=75.0,  # Below 85.0 threshold
            evidence_source="CISA_IOC",
            is_structured_ioc=True,
            observed_at=now - timedelta(hours=1)
        )
        qualified, action, reason = AutonomousPolicyEngine.evaluate_candidate(candidate, self.db)
        self.assertFalse(qualified)
        self.assertIsNone(action)
        self.assertIn("REJECTED_INSUFFICIENT_CONFIDENCE", reason)

    def test_expired_evidence_rejected(self):
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        candidate = NetworkIndicatorCandidate(
            indicator_value="185.220.101.5",
            tenant_id=self.tenant.id,
            confidence_score=90.0,
            evidence_source="CISA_IOC",
            is_structured_ioc=True,
            observed_at=now - timedelta(days=10)  # > 7 days old
        )
        qualified, action, reason = AutonomousPolicyEngine.evaluate_candidate(candidate, self.db)
        self.assertFalse(qualified)
        self.assertIsNone(action)
        self.assertIn("REJECTED_EXPIRED_INDICATOR_EVIDENCE", reason)

    def test_untrusted_source_rejected(self):
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        candidate = NetworkIndicatorCandidate(
            indicator_value="185.220.101.5",
            tenant_id=self.tenant.id,
            confidence_score=95.0,
            evidence_source="UNVERIFIED_BLOG_POST",
            is_structured_ioc=True,
            observed_at=now - timedelta(hours=2)
        )
        qualified, action, reason = AutonomousPolicyEngine.evaluate_candidate(candidate, self.db)
        self.assertFalse(qualified)
        self.assertIsNone(action)
        self.assertIn("REJECTED_UNTRUSTED_EVIDENCE_SOURCE", reason)

    def test_arbitrary_rss_mention_without_structured_ioc_rejected(self):
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        candidate = NetworkIndicatorCandidate(
            indicator_value="185.220.101.5",
            tenant_id=self.tenant.id,
            confidence_score=95.0,
            evidence_source="CISA_IOC",
            is_structured_ioc=False,  # Unstructured RSS mention
            observed_at=now - timedelta(hours=2)
        )
        qualified, action, reason = AutonomousPolicyEngine.evaluate_candidate(candidate, self.db)
        self.assertFalse(qualified)
        self.assertIsNone(action)
        self.assertEqual(reason, "REJECTED_UNSTRUCTURED_OR_ARBITRARY_INDICATOR")

    # -------------------------------------------------------------------------
    # 3. Separation of Vulnerability Remediation vs Network Indicator Containment
    # -------------------------------------------------------------------------

    def test_not_affected_finding_rejected_as_remediation_trigger(self):
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        candidate = NetworkIndicatorCandidate(
            indicator_value="185.220.101.5",
            tenant_id=self.tenant.id,
            confidence_score=95.0,
            evidence_source="CISA_IOC",
            is_structured_ioc=True,
            observed_at=now - timedelta(hours=1),
            vulnerability_status="NOT_AFFECTED"
        )
        qualified, action, reason = AutonomousPolicyEngine.evaluate_candidate(candidate, self.db)
        self.assertFalse(qualified)
        self.assertEqual(reason, "REJECTED_NOT_AFFECTED_TRIGGER")

    def test_needs_review_rejected_without_independent_corroboration(self):
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        # Needs review with low confidence
        candidate = NetworkIndicatorCandidate(
            indicator_value="185.220.101.5",
            tenant_id=self.tenant.id,
            confidence_score=60.0,
            evidence_source="UNVERIFIED_SOURCE",
            is_structured_ioc=False,
            observed_at=now - timedelta(hours=1),
            vulnerability_status="NEEDS_REVIEW"
        )
        qualified, action, reason = AutonomousPolicyEngine.evaluate_candidate(candidate, self.db)
        self.assertFalse(qualified)
        self.assertEqual(reason, "REJECTED_NEEDS_REVIEW_WITHOUT_INDEPENDENT_CORROBORATION")

    def test_independent_network_ioc_qualifies_without_affected_cve(self):
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        # Independent malicious indicator (no CVE associated)
        candidate = NetworkIndicatorCandidate(
            indicator_value="185.220.101.10",
            tenant_id=self.tenant.id,
            confidence_score=91.0,
            evidence_source="SURICATA_ALERT",
            is_structured_ioc=True,
            observed_at=now - timedelta(hours=1),
            threat_report_id=None,
            threat_match_id=None
        )
        qualified, action, reason = AutonomousPolicyEngine.evaluate_candidate(candidate, self.db)
        self.assertTrue(qualified)
        self.assertIsNotNone(action)
        self.assertEqual(reason, "QUALIFIED")

    # -------------------------------------------------------------------------
    # 4. Multi-Tenant Isolation & Duplicate Action Prevention
    # -------------------------------------------------------------------------

    def test_duplicate_active_action_rejected_for_same_tenant(self):
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        candidate1 = NetworkIndicatorCandidate(
            indicator_value="185.220.101.5",
            tenant_id=self.tenant.id,
            confidence_score=92.0,
            evidence_source="CISA_IOC",
            is_structured_ioc=True,
            observed_at=now - timedelta(hours=1)
        )
        qualified1, action1, _ = AutonomousPolicyEngine.evaluate_candidate(candidate1, self.db)
        self.assertTrue(qualified1)

        # Attempt to create duplicate action for same tenant
        candidate2 = NetworkIndicatorCandidate(
            indicator_value="185.220.101.5",
            tenant_id=self.tenant.id,
            confidence_score=95.0,
            evidence_source="CISA_IOC",
            is_structured_ioc=True,
            observed_at=now - timedelta(minutes=30)
        )
        qualified2, action2, reason2 = AutonomousPolicyEngine.evaluate_candidate(candidate2, self.db)
        self.assertFalse(qualified2)
        self.assertIsNone(action2)
        self.assertIn("REJECTED_DUPLICATE_ACTIVE_CONTAINMENT_ACTION", reason2)

    def test_same_ip_qualifies_independently_for_different_tenant(self):
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        candidate_tenant_a = NetworkIndicatorCandidate(
            indicator_value="185.220.101.5",
            tenant_id=self.tenant.id,
            confidence_score=90.0,
            evidence_source="CISA_IOC",
            is_structured_ioc=True,
            observed_at=now - timedelta(hours=1)
        )
        qualified_a, action_a, _ = AutonomousPolicyEngine.evaluate_candidate(candidate_tenant_a, self.db)
        self.assertTrue(qualified_a)

        # Candidate for Tenant B with the same IP should qualify independently
        candidate_tenant_b = NetworkIndicatorCandidate(
            indicator_value="185.220.101.5",
            tenant_id=self.tenant_b.id,
            confidence_score=90.0,
            evidence_source="CISA_IOC",
            is_structured_ioc=True,
            observed_at=now - timedelta(hours=1)
        )
        qualified_b, action_b, _ = AutonomousPolicyEngine.evaluate_candidate(candidate_tenant_b, self.db)
        self.assertTrue(qualified_b)
        self.assertNotEqual(action_a.tenant_id, action_b.tenant_id)

    # -------------------------------------------------------------------------
    # 5. Simulated Firewall Adapter Lifecycle & Strict State Transitions
    # -------------------------------------------------------------------------

    def test_simulated_adapter_full_lifecycle(self):
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        candidate = NetworkIndicatorCandidate(
            indicator_value="185.220.101.20",
            tenant_id=self.tenant.id,
            confidence_score=94.0,
            evidence_source="CISA_IOC",
            is_structured_ioc=True,
            observed_at=now - timedelta(hours=1),
            ttl_seconds=3600
        )
        _, action, _ = AutonomousPolicyEngine.evaluate_candidate(candidate, self.db)
        self.assertEqual(action.status, "PENDING")

        # Step 1: Apply containment (PENDING -> SIMULATED)
        apply_res = SimulatedFirewallAdapter.apply_containment(action, self.db)
        self.assertEqual(apply_res["status"], "SIMULATED")
        self.assertFalse(apply_res["is_live_enforcement"])
        self.assertTrue(apply_res["is_simulated"])
        self.assertEqual(action.status, "SIMULATED")
        self.assertIsNotNone(action.applied_at)
        self.assertIn("[SIMULATED]", action.execution_output)

        # Step 2: Idempotent apply returns SIMULATED
        apply_idempotent = SimulatedFirewallAdapter.apply_containment(action, self.db)
        self.assertEqual(apply_idempotent["status"], "SIMULATED")

        # Step 3: Verify containment (status remains SIMULATED; verified_at is set)
        verify_res = SimulatedFirewallAdapter.verify_containment(action, self.db)
        self.assertEqual(verify_res["status"], "SIMULATED")
        self.assertTrue(verify_res["verified"])
        self.assertFalse(verify_res["is_live_enforcement"])
        self.assertEqual(action.status, "SIMULATED")
        self.assertIsNotNone(action.verified_at)

        # Step 4: Rollback containment (SIMULATED -> ROLLED_BACK)
        rollback_res = SimulatedFirewallAdapter.rollback_containment(action, self.db)
        self.assertEqual(rollback_res["status"], "ROLLED_BACK")
        self.assertFalse(rollback_res["is_live_enforcement"])
        self.assertEqual(action.status, "ROLLED_BACK")
        self.assertIsNotNone(action.rolled_back_at)

        # Step 5: Idempotent rollback returns ROLLED_BACK
        rollback_idempotent = SimulatedFirewallAdapter.rollback_containment(action, self.db)
        self.assertEqual(rollback_idempotent["status"], "ROLLED_BACK")

    def test_simulated_adapter_expiry(self):
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        candidate = NetworkIndicatorCandidate(
            indicator_value="185.220.101.30",
            tenant_id=self.tenant.id,
            confidence_score=94.0,
            evidence_source="CISA_IOC",
            is_structured_ioc=True,
            observed_at=now - timedelta(hours=1),
            ttl_seconds=10
        )
        _, action, _ = AutonomousPolicyEngine.evaluate_candidate(candidate, self.db)
        SimulatedFirewallAdapter.apply_containment(action, self.db)

        # Manually advance expires_at into the past to simulate TTL expiration
        action.expires_at = now - timedelta(seconds=1)
        self.db.commit()

        exp_res = SimulatedFirewallAdapter.check_and_expire(action, self.db)
        self.assertTrue(exp_res["expired"])
        self.assertEqual(exp_res["status"], "EXPIRED")
        self.assertEqual(action.status, "EXPIRED")

    def test_illegal_state_transitions_raise_error(self):
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        candidate = NetworkIndicatorCandidate(
            indicator_value="185.220.101.40",
            tenant_id=self.tenant.id,
            confidence_score=94.0,
            evidence_source="CISA_IOC",
            is_structured_ioc=True,
            observed_at=now - timedelta(hours=1)
        )
        _, action, _ = AutonomousPolicyEngine.evaluate_candidate(candidate, self.db)

        # Cannot verify a PENDING action
        with self.assertRaises(InvalidStateTransitionError):
            SimulatedFirewallAdapter.verify_containment(action, self.db)

        # Cannot rollback a PENDING action
        with self.assertRaises(InvalidStateTransitionError):
            SimulatedFirewallAdapter.rollback_containment(action, self.db)

        # Apply action -> SIMULATED
        SimulatedFirewallAdapter.apply_containment(action, self.db)
        # Rollback action -> ROLLED_BACK
        SimulatedFirewallAdapter.rollback_containment(action, self.db)

        # Cannot apply an already ROLLED_BACK action
        with self.assertRaises(InvalidStateTransitionError):
            SimulatedFirewallAdapter.apply_containment(action, self.db)

        # Cannot verify a ROLLED_BACK action
        with self.assertRaises(InvalidStateTransitionError):
            SimulatedFirewallAdapter.verify_containment(action, self.db)

    # -------------------------------------------------------------------------
    # 6. Audit Logging & Secrets Redaction
    # -------------------------------------------------------------------------

    def test_secrets_redacted_from_audit_logs(self):
        raw_details = {
            "auth_token": "SUPER_SECRET_TOKEN_999",
            "password": "Password123!",
            "api_key": "sk-secret-key-abcdef",
            "safe_metric": 95.5,
            "nested": {
                "bearer_token": "Bearer xyz123",
                "destination_ip": "185.220.101.5"
            }
        }
        sanitized = sanitize_audit_details(raw_details)
        self.assertEqual(sanitized["auth_token"], "[REDACTED_SECRET]")
        self.assertEqual(sanitized["password"], "[REDACTED_SECRET]")
        self.assertEqual(sanitized["api_key"], "[REDACTED_SECRET]")
        self.assertEqual(sanitized["nested"]["bearer_token"], "[REDACTED_SECRET]")
        self.assertEqual(sanitized["safe_metric"], 95.5)
        self.assertEqual(sanitized["nested"]["destination_ip"], "185.220.101.5")

    # -------------------------------------------------------------------------
    # 7. Regression Test: SOAR Lifecycle & Premature RESOLVED Fix
    # -------------------------------------------------------------------------

    @patch("app.services.osint_collector.dispatch_playbook_to_matched_tenants")
    @patch("app.services.osint_collector.generate_soar_playbook")
    def test_soar_delivery_received_does_not_mark_threat_match_resolved(
        self,
        mock_generate_playbook,
        mock_dispatch
    ):
        """
        Regression test: SOAR webhook delivery returning RECEIVED must NEVER
        mark ThreatMatch.status as RESOLVED. Vulnerability remediation status
        must remain OPEN pending verified software remediation.
        """
        mock_generate_playbook.return_value = {
            "platform_target": "Nginx",
            "remediation_script": "iptables -A INPUT -p tcp --dport 80 -j DROP",
            "is_automated_applicable": True
        }
        # Simulate webhook receiver returning RECEIVED
        mock_dispatch.return_value = [
            {"tenant_id": str(self.tenant.id), "status": "RECEIVED", "response_code": 200}
        ]

        report = models.ThreatReport(
            title="Critical Fastify RCE Vulnerability",
            summary="Remote code execution in FastAPI and Docker environments.",
            severity="critical",
            cve_id="CVE-2026-9999",
            source_url="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-9999",
            stix_bundle={"type": "bundle", "id": "bundle--cve-2026-9999", "objects": []}
        )
        self.db.add(report)
        self.db.commit()
        self.db.refresh(report)

        # Trigger correlation and mitigation
        process_threat_tenant_correlations(self.db, report)

        # Verify ThreatMatch created
        match = self.db.query(models.ThreatMatch).filter(
            models.ThreatMatch.tenant_id == self.tenant.id,
            models.ThreatMatch.threat_report_id == report.id
        ).first()

        self.assertIsNotNone(match, "ThreatMatch should be created for affected tenant")
        # CRITICAL ASSERTION: Status MUST remain OPEN, not RESOLVED!
        self.assertEqual(
            match.status,
            "OPEN",
            f"Expected ThreatMatch.status to be 'OPEN', but was '{match.status}'. Webhook RECEIVED must not resolve vulnerability."
        )
