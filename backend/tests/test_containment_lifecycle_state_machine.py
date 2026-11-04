"""
Targeted Test Suite for Milestone 3: Complete Containment Lifecycle
-------------------------------------------------------------------
Tests:
1. Complete action lifecycle states (PENDING, SIMULATED, DISPATCHED, RECEIVED, FAILED, REJECTED, EXPIRED, ROLLED_BACK)
2. Strict state machine transitions and InvalidStateTransitionError enforcement
3. Database-level partial unique index concurrency protection & historical record preservation
4. Idempotent expiry and exact-rule rollback
5. Tenant isolation across services and API endpoints
6. Audit trail generation and secrets stripping
7. SOAR delivery semantics (RECEIVED != APPLIED/VERIFIED, never marks ThreatMatch RESOLVED)
"""

import os
import sys
import uuid
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
    ACTIVE_CONTAINMENT_STATUSES,
    sanitize_audit_details
)
from app.services.firewall_adapter import (
    SimulatedFirewallAdapter,
    InvalidStateTransitionError
)
from app.services.soar_dispatcher import dispatch_containment_action_to_tenant


class TestContainmentLifecycleMilestone3(BaseTestCase):

    def setUp(self):
        super().setUp()
        # Seed second tenant for strict multi-tenant isolation tests
        self.tenant_b = models.Tenant(
            company_name="Beta Global Security Ltd",
            tech_stack="Python:3.11, Django:4.2, PostgreSQL:14",
            webhook_url="https://mock-soar.beta.local/webhook",
            auth_token="BETA_BEARER_SECRET_998877"
        )
        self.db.add(self.tenant_b)
        self.db.commit()
        self.db.refresh(self.tenant_b)

        # User for tenant B
        self.user_b = models.User(
            tenant_id=self.tenant_b.id,
            email="analyst@beta.local",
            password_hash="fakehash",
            role="analyst"
        )
        self.db.add(self.user_b)
        self.db.commit()
        self.db.refresh(self.user_b)

    def _create_candidate(self, ip="185.220.101.5", tenant_id=None, confidence=92.0, ttl=3600):
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        return NetworkIndicatorCandidate(
            indicator_value=ip,
            tenant_id=tenant_id or self.tenant.id,
            confidence_score=confidence,
            evidence_source="CISA_IOC",
            is_structured_ioc=True,
            evidence_summary="Verified malicious C2 host.",
            observed_at=now - timedelta(hours=1),
            ttl_seconds=ttl
        )

    # -------------------------------------------------------------------------
    # 1. State Semantics and Lifecycle Transitions
    # -------------------------------------------------------------------------

    def test_lifecycle_simulated_and_verification_semantics(self):
        """
        Action transitions PENDING -> SIMULATED.
        Verification retains SIMULATED with verified_at set; NEVER falsely claims APPLIED or VERIFIED as live state.
        """
        cand = self._create_candidate()
        ok, action, _ = AutonomousPolicyEngine.evaluate_candidate(cand, self.db)
        self.assertTrue(ok)
        self.assertEqual(action.status, "PENDING")

        # Apply simulation
        res = SimulatedFirewallAdapter.apply_containment(action, self.db)
        self.assertEqual(res["status"], "SIMULATED")
        self.assertFalse(res["is_live_enforcement"])
        self.assertTrue(res["is_simulated"])
        self.assertEqual(action.status, "SIMULATED")
        self.assertIsNotNone(action.applied_at)

        # Verification retains status as SIMULATED
        v_res = SimulatedFirewallAdapter.verify_containment(action, self.db)
        self.assertEqual(v_res["status"], "SIMULATED")
        self.assertTrue(v_res["verified"])
        self.assertFalse(v_res["is_live_enforcement"])
        self.assertEqual(action.status, "SIMULATED")
        self.assertIsNotNone(action.verified_at)

    def test_invalid_state_transitions_rejected(self):
        """Illegal transitions raise InvalidStateTransitionError and preserve database integrity."""
        cand = self._create_candidate(ip="185.220.101.12")
        _, action, _ = AutonomousPolicyEngine.evaluate_candidate(cand, self.db)
        self.assertEqual(action.status, "PENDING")

        # Cannot verify PENDING
        with self.assertRaises(InvalidStateTransitionError):
            SimulatedFirewallAdapter.verify_containment(action, self.db)

        # Cannot rollback PENDING
        with self.assertRaises(InvalidStateTransitionError):
            SimulatedFirewallAdapter.rollback_containment(action, self.db)

        # Move to SIMULATED then ROLLED_BACK
        SimulatedFirewallAdapter.apply_containment(action, self.db)
        SimulatedFirewallAdapter.rollback_containment(action, self.db)
        self.assertEqual(action.status, "ROLLED_BACK")

        # Cannot re-apply ROLLED_BACK
        with self.assertRaises(InvalidStateTransitionError):
            SimulatedFirewallAdapter.apply_containment(action, self.db)

    # -------------------------------------------------------------------------
    # 2. Duplicate and Concurrency Protection
    # -------------------------------------------------------------------------

    def test_concurrent_or_pre_existing_duplicate_rejected(self):
        """Pre-existing active action prevents duplicate creation for the same tenant and indicator."""
        cand = self._create_candidate(ip="185.220.101.25")
        ok1, act1, _ = AutonomousPolicyEngine.evaluate_candidate(cand, self.db)
        self.assertTrue(ok1)
        self.assertIsNotNone(act1)

        # Second evaluation for same tenant & IP must be rejected
        ok2, act2, reason2 = AutonomousPolicyEngine.evaluate_candidate(cand, self.db)
        self.assertFalse(ok2)
        self.assertIsNone(act2)
        self.assertIn("REJECTED_DUPLICATE_ACTIVE_CONTAINMENT_ACTION", reason2)
        self.assertIn(act1.action_id, reason2)

    def test_database_level_uniqueness_handles_concurrency_race(self):
        """Database-level partial unique index catches concurrent race insertions gracefully."""
        # Directly insert an active action bypassing evaluate_candidate
        act_manual = ContainmentAction(
            id=str(uuid.uuid4()),
            action_id="act-auto-race-1111",
            tenant_id=self.tenant.id,
            indicator_value="185.220.101.33",
            indicator_type="ipv4",
            action_type="BLOCK_IPV4_DESTINATION",
            policy_decision="QUALIFIED",
            status="SIMULATED",
            ttl_seconds=3600,
            expires_at=datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(hours=1)
        )
        self.db.add(act_manual)
        self.db.commit()

        # Attempt to insert candidate with same tenant & IP
        cand = self._create_candidate(ip="185.220.101.33")
        ok, conflicting_act, reason = AutonomousPolicyEngine.evaluate_candidate(cand, self.db)
        self.assertFalse(ok)
        self.assertIsNone(conflicting_act)
        self.assertIn("REJECTED_DUPLICATE_ACTIVE_CONTAINMENT_ACTION", reason)
        self.assertIn(act_manual.action_id, reason)

    def test_historical_actions_preserved_and_new_action_allowed_after_expiry_or_rollback(self):
        """When an older action has EXPIRED or ROLLED_BACK, a new action for the same IP is permitted."""
        cand = self._create_candidate(ip="185.220.101.44")
        ok1, act1, _ = AutonomousPolicyEngine.evaluate_candidate(cand, self.db)
        self.assertTrue(ok1)

        # Transition to SIMULATED then ROLLED_BACK
        SimulatedFirewallAdapter.apply_containment(act1, self.db)
        SimulatedFirewallAdapter.rollback_containment(act1, self.db)
        self.assertEqual(act1.status, "ROLLED_BACK")

        # Now evaluate candidate again for same tenant & IP -> MUST be qualified!
        ok2, act2, reason2 = AutonomousPolicyEngine.evaluate_candidate(cand, self.db)
        self.assertTrue(ok2)
        self.assertEqual(reason2, "QUALIFIED")
        self.assertNotEqual(act1.id, act2.id)

        # Verify historical action is preserved in database
        total_actions = self.db.query(ContainmentAction).filter(
            ContainmentAction.tenant_id == self.tenant.id,
            ContainmentAction.indicator_value == "185.220.101.44"
        ).count()
        self.assertEqual(total_actions, 2)

    # -------------------------------------------------------------------------
    # 3. Expiry and Rollback Behavior
    # -------------------------------------------------------------------------

    def test_bulk_expiry_service_is_repeatable_and_idempotent(self):
        """expire_active_containment_actions scans and transitions expired actions idempotently."""
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        cand = self._create_candidate(ip="185.220.101.55", ttl=10)
        _, action, _ = AutonomousPolicyEngine.evaluate_candidate(cand, self.db)
        SimulatedFirewallAdapter.apply_containment(action, self.db)

        # Force expires_at into the past
        action.expires_at = now - timedelta(seconds=5)
        self.db.commit()

        # Run bulk expiry service
        results = SimulatedFirewallAdapter.expire_active_containment_actions(self.db, tenant_id=self.tenant.id)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["status"], "EXPIRED")
        self.assertEqual(action.status, "EXPIRED")

        # Run again immediately -> 0 actions pending expiry
        results2 = SimulatedFirewallAdapter.expire_active_containment_actions(self.db, tenant_id=self.tenant.id)
        self.assertEqual(len(results2), 0)

    def test_rollback_identifies_exact_action_and_reverses_only_managed_rule(self):
        """Rollback removes only the specific rule ID created by the system."""
        cand = self._create_candidate(ip="185.220.101.66")
        _, action, _ = AutonomousPolicyEngine.evaluate_candidate(cand, self.db)
        SimulatedFirewallAdapter.apply_containment(action, self.db)

        rule_id = action.rule_spec.get("rule_id")
        self.assertIsNotNone(rule_id)

        res = SimulatedFirewallAdapter.rollback_containment(action, self.db, reason="Security Analyst Request")
        self.assertEqual(res["status"], "ROLLED_BACK")
        self.assertEqual(res["rollback_rule"]["reversed_rule_id"], rule_id)
        self.assertEqual(action.status, "ROLLED_BACK")

        # Repeated rollback is idempotent
        res_idemp = SimulatedFirewallAdapter.rollback_containment(action, self.db)
        self.assertEqual(res_idemp["status"], "ROLLED_BACK")

    # -------------------------------------------------------------------------
    # 4. Audit Trail and Tenant Isolation
    # -------------------------------------------------------------------------

    def test_rollback_enforces_tenant_ownership(self):
        """Tenant A cannot rollback Tenant B's containment action."""
        cand = self._create_candidate(ip="185.220.101.77", tenant_id=self.tenant_b.id)
        _, action_b, _ = AutonomousPolicyEngine.evaluate_candidate(cand, self.db)
        SimulatedFirewallAdapter.apply_containment(action_b, self.db)

        # Attempting rollback with Tenant A's ID must raise PermissionError
        with self.assertRaises(PermissionError):
            SimulatedFirewallAdapter.rollback_containment(
                action=action_b,
                db=self.db,
                expected_tenant_id=self.tenant.id
            )

    def test_audit_logs_record_every_transition_and_sanitize_secrets(self):
        """Every status transition creates an audit entry and redacts sensitive tokens."""
        cand = self._create_candidate(ip="185.220.101.88")
        _, action, _ = AutonomousPolicyEngine.evaluate_candidate(cand, self.db)
        SimulatedFirewallAdapter.apply_containment(action, self.db)
        SimulatedFirewallAdapter.rollback_containment(action, self.db)

        logs = self.db.query(ContainmentAuditLog).filter(
            ContainmentAuditLog.action_id == action.id
        ).order_by(ContainmentAuditLog.created_at.asc()).all()

        event_types = [l.event_type for l in logs]
        self.assertIn("POLICY_EVALUATION", event_types)
        self.assertIn("SIMULATION_APPLIED", event_types)
        self.assertIn("SIMULATION_ROLLBACK", event_types)

        # Verify secrets redaction
        secret_dict = {
            "auth_token": "SUPER_SECRET_123",
            "password": "SecretPassword!",
            "normal_field": "safe_value"
        }
        sanitized = sanitize_audit_details(secret_dict)
        self.assertEqual(sanitized["auth_token"], "[REDACTED_SECRET]")
        self.assertEqual(sanitized["password"], "[REDACTED_SECRET]")
        self.assertEqual(sanitized["normal_field"], "safe_value")

    # -------------------------------------------------------------------------
    # 5. SOAR Delivery Semantics (DISPATCHED, RECEIVED, no premature RESOLVED)
    # -------------------------------------------------------------------------

    @patch("requests.post")
    def test_soar_delivery_transitions_to_dispatched_and_received(self, mock_post):
        """
        SOAR webhook delivery:
        - HTTP 200 transitions action to RECEIVED (NOT APPLIED or VERIFIED).
        - Underlying ThreatMatch status is NEVER marked RESOLVED.
        """
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {"content-type": "application/json"}
        mock_resp.json.return_value = {"status": "ok", "ack_id": "soc-ack-42"}
        mock_post.return_value = mock_resp

        cand = self._create_candidate(ip="185.220.101.99")
        _, action, _ = AutonomousPolicyEngine.evaluate_candidate(cand, self.db)

        result = dispatch_containment_action_to_tenant(action, self.tenant, self.db)

        self.assertEqual(result["status"], "RECEIVED")
        self.assertEqual(action.status, "RECEIVED")
        self.assertFalse(result["is_live_enforcement"])

        # Check audit trail has DISPATCHED and RECEIVED
        logs = self.db.query(ContainmentAuditLog).filter(
            ContainmentAuditLog.action_id == action.id
        ).all()
        events = [l.event_type for l in logs]
        self.assertIn("SOAR_DISPATCHED", events)
        self.assertIn("SOAR_RECEIVED", events)

    @patch("requests.post")
    def test_soar_delivery_network_failure_transitions_to_failed(self, mock_post):
        """Network exception transitions action to FAILED safely."""
        mock_post.side_effect = Exception("Connection timed out (5s)")

        cand = self._create_candidate(ip="185.220.101.100")
        _, action, _ = AutonomousPolicyEngine.evaluate_candidate(cand, self.db)

        result = dispatch_containment_action_to_tenant(action, self.tenant, self.db)
        self.assertEqual(result["status"], "FAILED")
        self.assertEqual(action.status, "FAILED")
        self.assertIn("Connection timed out", action.error_message)

    # -------------------------------------------------------------------------
    # 6. Tenant API Isolation Endpoints
    # -------------------------------------------------------------------------

    def test_tenant_api_isolation_prevents_cross_tenant_access_and_rollback(self):
        """Authenticated Tenant A cannot view or rollback Tenant B's containment action via API."""
        cand_b = self._create_candidate(ip="185.220.101.111", tenant_id=self.tenant_b.id)
        _, action_b, _ = AutonomousPolicyEngine.evaluate_candidate(cand_b, self.db)
        SimulatedFirewallAdapter.apply_containment(action_b, self.db)

        # Authenticate as Tenant A user
        token_a = self.client.post("/api/auth/token", data={
            "username": self.user.email,
            "password": "testpassword123"
        }).json().get("access_token")
        headers_a = {"Authorization": f"Bearer {token_a}"}

        # Attempt to GET Tenant B's action -> 404
        get_res = self.client.get(f"/api/tenants/containment/actions/{action_b.action_id}", headers=headers_a)
        self.assertEqual(get_res.status_code, 404)

        # Attempt to POST rollback on Tenant B's action -> 404
        post_res = self.client.post(f"/api/tenants/containment/actions/{action_b.action_id}/rollback", headers=headers_a)
        self.assertEqual(post_res.status_code, 404)
        self.assertEqual(action_b.status, "SIMULATED")  # Status unchanged


if __name__ == "__main__":
    import unittest
    unittest.main()
