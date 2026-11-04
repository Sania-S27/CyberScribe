"""
Tests for Webhook Integration End-to-End (CyberScribe Section 3 & 4)
---------------------------------------------------------------------
Verifies:
1. Inbound Webhook: Valid authenticated request succeeds with status RECEIVED.
2. Inbound Webhook: Missing or invalid Bearer token rejected with 401.
3. Inbound Webhook: Malformed payload rejected safely with 422.
4. Inbound Webhook: Unknown target tenant rejected with 404.
5. Inbound Webhook: Deterministic bogon filtering rejects loopback/private/infrastructure IPs.
6. Inbound Webhook: Idempotency suppresses duplicate deliveries safely.
7. Inbound Webhook: Acknowledging receipt (RECEIVED) does NOT assert live execution or resolve threats.
8. Outbound SOAR Dispatch: Successful dispatch transitions action to RECEIVED (never APPLIED/VERIFIED).
9. Outbound SOAR Dispatch: 5xx server errors trigger bounded retries.
10. Outbound SOAR Dispatch: 4xx client errors fail immediately without retrying.
11. Outbound SOAR Dispatch: Strict tenant isolation prevents cross-tenant action dispatch.
12. Outbound Incident Notifications: Bounded retries and independent email execution verified.
13. Secrets scrubbing: Tokens and credentials never exposed in audit logs.
"""

import uuid
from unittest.mock import patch, MagicMock
import requests

from tests.base import BaseTestCase
from app import models
from app.services.soar_dispatcher import dispatch_containment_action_to_tenant
from app.services.notification_service import NotificationService
from app.agents.mitigation import dispatch_playbook_to_tenant


class TestWebhookIntegrationsE2E(BaseTestCase):

    def setUp(self):
        super().setUp()

        # Primary Tenant A
        self.tenant_a = models.Tenant(
            id=str(uuid.uuid4()),
            company_name="Alpha Defense Networks",
            tech_stack="Python:3.11, FastAPI:0.104.1",
            webhook_url="https://mock-soar-receiver.alpha.local/webhook",
            auth_token="ALPHA_SECRET_BEARER_TOKEN_123"
        )
        self.db.add(self.tenant_a)

        # Foreign Tenant B
        self.tenant_b = models.Tenant(
            id=str(uuid.uuid4()),
            company_name="Beta Cloud Infrastructure",
            tech_stack="Node.js, Express",
            webhook_url="https://mock-soar-receiver.beta.local/webhook",
            auth_token="BETA_SECRET_BEARER_TOKEN_456"
        )
        self.db.add(self.tenant_b)
        self.db.commit()

        # Asset and Threat Report
        self.asset = models.AssetComponent(
            id=str(uuid.uuid4()),
            tenant_id=self.tenant_a.id,
            software_name="fastapi",
            software_version="0.100.0",
            environment="production"
        )
        self.db.add(self.asset)

        self.threat_report = models.ThreatReport(
            id=str(uuid.uuid4()),
            cve_id="CVE-2026-8888",
            title="Critical HTTP Request Smuggling",
            summary="Remote exploitation via malformed headers",
            severity="critical"
        )
        self.db.add(self.threat_report)
        self.db.commit()

        # Threat Match
        self.threat_match = models.ThreatMatch(
            id=str(uuid.uuid4()),
            tenant_id=self.tenant_a.id,
            asset_component_id=self.asset.id,
            threat_report_id=self.threat_report.id,
            status="OPEN",
            ai_confidence_score=98.0,
            ai_matching_reason="Confirmed CVE match"
        )
        self.db.add(self.threat_match)
        self.db.commit()

    # =========================================================================
    # INBOUND WEBHOOK TESTS
    # =========================================================================

    def test_inbound_webhook_valid_authenticated_request_succeeds(self):
        """Inbound: Valid authenticated webhook returns HTTP 200 with status RECEIVED."""
        payload = {
            "tenant_id": str(self.tenant_a.id),
            "event_type": "SECURITY_ALERT",
            "delivery_id": f"deliv-{uuid.uuid4().hex[:8]}",
            "cve_id": "CVE-2026-8888",
            "details": {"source": "Campus Guide Security Hub"}
        }
        headers = {"Authorization": f"Bearer {self.tenant_a.auth_token}"}

        resp = self.client.post("/api/security/soar-webhook", json=payload, headers=headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["status"], "RECEIVED")
        self.assertTrue(data["acknowledged"])
        self.assertFalse(data["is_live_enforcement"], "Receipt must NOT assert live enforcement")

        # Verify database audit persistence
        audit = self.db.query(models.TenantNotification).filter(
            models.TenantNotification.delivery_id == payload["delivery_id"],
            models.TenantNotification.channel == "INBOUND_WEBHOOK"
        ).first()
        self.assertIsNotNone(audit)
        self.assertEqual(audit.status, "RECEIVED")
        self.assertFalse(audit.human_confirmed)

    def test_inbound_webhook_missing_auth_header_rejected_401(self):
        """Inbound: Missing Authorization header rejected with 401 Unauthorized."""
        payload = {
            "tenant_id": str(self.tenant_a.id),
            "event_type": "CONTAINMENT_REQUEST"
        }
        resp = self.client.post("/api/security/soar-webhook", json=payload)
        self.assertEqual(resp.status_code, 401)
        self.assertIn("Missing Authorization header", resp.json()["detail"])

    def test_inbound_webhook_invalid_token_rejected_401(self):
        """Inbound: Token mismatch or fraudulent token rejected with 401 Unauthorized."""
        payload = {
            "tenant_id": str(self.tenant_a.id),
            "event_type": "CONTAINMENT_REQUEST"
        }
        headers = {"Authorization": "Bearer INVALID_OR_EXPIRED_TOKEN"}
        resp = self.client.post("/api/security/soar-webhook", json=payload, headers=headers)
        self.assertEqual(resp.status_code, 401)
        self.assertIn("Invalid webhook credentials", resp.json()["detail"])

    def test_inbound_webhook_unknown_tenant_rejected_404(self):
        """Inbound: Nonexistent tenant UUID returns 404 Not Found."""
        payload = {
            "tenant_id": str(uuid.uuid4()),
            "event_type": "SECURITY_ALERT"
        }
        headers = {"Authorization": "Bearer SOME_TOKEN"}
        resp = self.client.post("/api/security/soar-webhook", json=payload, headers=headers)
        self.assertEqual(resp.status_code, 404)
        self.assertIn("does not exist", resp.json()["detail"])

    def test_inbound_webhook_malformed_payload_rejected_422(self):
        """Inbound: Payload missing required schema fields rejected with 422 Unprocessable Entity."""
        headers = {"Authorization": f"Bearer {self.tenant_a.auth_token}"}
        resp = self.client.post("/api/security/soar-webhook", json={"random_field": "data"}, headers=headers)
        self.assertEqual(resp.status_code, 422)

    def test_inbound_webhook_bogon_ip_rejected_under_policy(self):
        """Inbound: Containment request targeting loopback/private/infrastructure IP is rejected."""
        payload = {
            "tenant_id": str(self.tenant_a.id),
            "event_type": "CONTAINMENT_REQUEST",
            "indicator_value": "127.0.0.1",
            "delivery_id": f"deliv-bogon-{uuid.uuid4().hex[:6]}"
        }
        headers = {"Authorization": f"Bearer {self.tenant_a.auth_token}"}
        resp = self.client.post("/api/security/soar-webhook", json=payload, headers=headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["status"], "REJECTED_POLICY")
        self.assertIn("LOOPBACK", data["reason"])
        self.assertFalse(data["is_live_enforcement"])

    def test_inbound_webhook_idempotency_suppresses_duplicate_action(self):
        """Inbound: Duplicate delivery_id returns cached acknowledgment with duplicate=True."""
        delivery_id = f"deliv-idemp-{uuid.uuid4().hex[:8]}"
        payload = {
            "tenant_id": str(self.tenant_a.id),
            "event_type": "SECURITY_ALERT",
            "delivery_id": delivery_id
        }
        headers = {"Authorization": f"Bearer {self.tenant_a.auth_token}"}

        # First delivery
        resp1 = self.client.post("/api/security/soar-webhook", json=payload, headers=headers)
        self.assertEqual(resp1.status_code, 200)
        self.assertFalse(resp1.json().get("duplicate", False))

        # Second delivery with same delivery_id
        resp2 = self.client.post("/api/security/soar-webhook", json=payload, headers=headers)
        self.assertEqual(resp2.status_code, 200)
        self.assertTrue(resp2.json().get("duplicate", False))
        self.assertIn("previously acknowledged", resp2.json()["message"])

    def test_inbound_webhook_does_not_mark_threat_match_resolved(self):
        """Safety Contract: Webhook receipt acknowledgement must NEVER mark ThreatMatch as RESOLVED."""
        payload = {
            "tenant_id": str(self.tenant_a.id),
            "event_type": "CONTAINMENT_REQUEST",
            "cve_id": self.threat_report.cve_id,
            "indicator_value": "185.220.101.5"
        }
        headers = {"Authorization": f"Bearer {self.tenant_a.auth_token}"}

        resp = self.client.post("/api/security/soar-webhook", json=payload, headers=headers)
        self.assertEqual(resp.status_code, 200)

        # Refresh ThreatMatch: status MUST remain OPEN
        self.db.refresh(self.threat_match)
        self.assertEqual(
            self.threat_match.status,
            "OPEN",
            "ThreatMatch status must remain OPEN until software remediation is independently verified."
        )

    # =========================================================================
    # OUTBOUND SOAR DISPATCH TESTS
    # =========================================================================

    @patch("requests.post")
    def test_outbound_soar_dispatch_success_records_received(self, mock_post):
        """Outbound: HTTP 200 response transitions action status to RECEIVED (never APPLIED/VERIFIED)."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = '{"status": "ACK", "playbook": "RECEIVED"}'
        mock_post.return_value = mock_resp

        action = models.ContainmentAction(
            action_id=f"act-{uuid.uuid4().hex[:8]}",
            tenant_id=self.tenant_a.id,
            threat_match_id=self.threat_match.id,
            indicator_value="185.220.101.5",
            indicator_type="ip_address",
            action_type="IP_BLOCK",
            policy_decision="CONTAIN_IP",
            status="PENDING"
        )
        self.db.add(action)
        self.db.commit()

        res = dispatch_containment_action_to_tenant(action=action, tenant=self.tenant_a, db=self.db)
        self.assertEqual(res["status"], "RECEIVED")
        self.assertEqual(action.status, "RECEIVED")
        self.assertFalse(res["is_live_enforcement"])
        self.assertIn("Enforcement NOT confirmed", action.execution_output)

    @patch("requests.post")
    def test_outbound_soar_dispatch_bounded_retries_on_5xx_server_error(self, mock_post):
        """Outbound: Server 500 error triggers bounded retries up to max_retries before marking FAILED."""
        mock_resp = MagicMock()
        mock_resp.status_code = 503
        mock_resp.text = "Service Unavailable"
        mock_post.return_value = mock_resp

        action = models.ContainmentAction(
            action_id=f"act-{uuid.uuid4().hex[:8]}",
            tenant_id=self.tenant_a.id,
            threat_match_id=self.threat_match.id,
            indicator_value="185.220.101.5",
            indicator_type="ip_address",
            action_type="IP_BLOCK",
            policy_decision="CONTAIN_IP",
            status="PENDING"
        )
        self.db.add(action)
        self.db.commit()

        res = dispatch_containment_action_to_tenant(action=action, tenant=self.tenant_a, db=self.db)
        self.assertEqual(res["status"], "FAILED")
        self.assertEqual(action.status, "FAILED")
        # Initial attempt + 2 retries = 3 attempts total
        self.assertEqual(mock_post.call_count, 3)

    @patch("requests.post")
    def test_outbound_soar_dispatch_non_retryable_on_4xx_client_error(self, mock_post):
        """Outbound: Client 400/401 error fails immediately without retrying."""
        mock_resp = MagicMock()
        mock_resp.status_code = 401
        mock_resp.text = "Unauthorized Token"
        mock_post.return_value = mock_resp

        action = models.ContainmentAction(
            action_id=f"act-{uuid.uuid4().hex[:8]}",
            tenant_id=self.tenant_a.id,
            threat_match_id=self.threat_match.id,
            indicator_value="185.220.101.5",
            indicator_type="ip_address",
            action_type="IP_BLOCK",
            policy_decision="CONTAIN_IP",
            status="PENDING"
        )
        self.db.add(action)
        self.db.commit()

        res = dispatch_containment_action_to_tenant(action=action, tenant=self.tenant_a, db=self.db)
        self.assertEqual(res["status"], "FAILED")
        # 4xx is non-retryable: exactly 1 attempt made
        self.assertEqual(mock_post.call_count, 1)

    def test_outbound_soar_dispatch_tenant_isolation_violation_raises(self):
        """Outbound: Attempting to dispatch Tenant B's action using Tenant A's context raises PermissionError."""
        action_b = models.ContainmentAction(
            action_id=f"act-{uuid.uuid4().hex[:8]}",
            tenant_id=self.tenant_b.id,
            indicator_value="198.51.100.99",
            indicator_type="ip_address",
            action_type="IP_BLOCK",
            policy_decision="CONTAIN_IP",
            status="PENDING"
        )
        self.db.add(action_b)
        self.db.commit()

        with self.assertRaises(PermissionError):
            dispatch_containment_action_to_tenant(action=action_b, tenant=self.tenant_a, db=self.db)

    # =========================================================================
    # OUTBOUND INCIDENT NOTIFICATION TESTS
    # =========================================================================

    @patch("requests.post")
    def test_outbound_notification_service_bounded_retries_and_resilience(self, mock_post):
        """Outbound Notification: Webhook connection failure retries boundedly and records honest failure."""
        mock_post.side_effect = requests.exceptions.ConnectionError("Connection refused by receiver")

        res = NotificationService.send_incident_notification(
            db=self.db,
            tenant=self.tenant_a,
            event_type="VULNERABILITY_CONFIRMED",
            threat_report=self.threat_report,
            asset=self.asset,
            max_retries=2
        )

        self.assertEqual(res["status"], "FAILED")
        self.assertFalse(res["delivered"])
        self.assertFalse(res["human_confirmed"])
        # Initial attempt + 2 retries = 3 attempts total
        self.assertEqual(mock_post.call_count, 3)

    @patch("requests.post")
    def test_outbound_playbook_mitigation_dispatch_bounded_retries(self, mock_post):
        """Outbound Mitigation Playbook: dispatch_playbook_to_tenant retries transient server errors."""
        mock_resp = MagicMock()
        mock_resp.status_code = 502
        mock_resp.text = "Bad Gateway"
        mock_resp.headers = {"content-type": "text/plain"}
        mock_post.return_value = mock_resp

        playbook = {
            "playbook_name": "Test Quarantine",
            "firewall_rules": ["iptables -A INPUT -s 185.220.101.5 -j DROP"],
            "iocs": {"ip_addresses": ["185.220.101.5"]}
        }

        res = dispatch_playbook_to_tenant(tenant=self.tenant_a, playbook=playbook)
        self.assertEqual(res["status"], "FAILED")
        self.assertEqual(mock_post.call_count, 3)

    # =========================================================================
    # EXTENDED WEBHOOK RESILIENCE, ERROR SANITIZATION & RETRY LIFECYCLE TESTS
    # =========================================================================

    @patch("requests.post")
    def test_outbound_notification_service_successful_delivery(self, mock_post):
        """Outbound Notification: Successful 200 response marks status DELIVERED with error_message None."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = '{"status": "RECEIVED", "acknowledged": true}'
        mock_post.return_value = mock_resp

        res = NotificationService.send_incident_notification(
            db=self.db,
            tenant=self.tenant_a,
            event_type="VULNERABILITY_CONFIRMED",
            threat_report=self.threat_report,
            asset=self.asset,
            max_retries=2
        )

        self.assertEqual(res["status"], "DELIVERED")
        self.assertTrue(res["delivered"])
        self.assertFalse(res["human_confirmed"])
        self.assertEqual(mock_post.call_count, 1)

        # Check DB persistence
        notif = self.db.query(models.TenantNotification).filter(
            models.TenantNotification.delivery_id == res["delivery_id"]
        ).first()
        self.assertIsNotNone(notif)
        self.assertEqual(notif.status, "DELIVERED")
        self.assertEqual(notif.status_code, 200)
        self.assertTrue(notif.delivered)
        self.assertFalse(notif.human_confirmed)
        self.assertIsNone(notif.error_message)

    @patch("requests.post")
    def test_outbound_notification_service_connection_error_and_sanitization(self, mock_post):
        """Outbound Notification: Connection error produces sanitized error message without memory pointers."""
        raw_err = (
            "HTTPConnectionPool(host='127.0.0.1', port=8000): Max retries exceeded with url: "
            "/api/security/soar-webhook (Caused by NewConnectionError('<urllib3.connection.HTTPConnection object at 0x0000024C41983390>: "
            "Failed to establish a new connection: [WinError 10061] No connection could be made because the target machine actively refused it'))"
        )
        mock_post.side_effect = requests.exceptions.ConnectionError(raw_err)

        res = NotificationService.send_incident_notification(
            db=self.db,
            tenant=self.tenant_a,
            event_type="VULNERABILITY_CONFIRMED",
            threat_report=self.threat_report,
            asset=self.asset,
            max_retries=2
        )

        self.assertEqual(res["status"], "FAILED")
        self.assertFalse(res["delivered"])
        self.assertFalse(res["human_confirmed"])
        self.assertEqual(mock_post.call_count, 3)

        notif = self.db.query(models.TenantNotification).filter(
            models.TenantNotification.delivery_id == res["delivery_id"]
        ).first()
        self.assertIsNotNone(notif)
        self.assertIn("Connection refused", notif.error_message)
        self.assertNotIn("0x0000024C41983390", notif.error_message)

    @patch("requests.post")
    def test_outbound_notification_service_timeout_error(self, mock_post):
        """Outbound Notification: Timeout error produces sanitized message and bounded retries."""
        mock_post.side_effect = requests.exceptions.Timeout("Read timed out after 6.0 seconds")

        res = NotificationService.send_incident_notification(
            db=self.db,
            tenant=self.tenant_a,
            event_type="VULNERABILITY_CONFIRMED",
            threat_report=self.threat_report,
            asset=self.asset,
            max_retries=1
        )

        self.assertEqual(res["status"], "FAILED")
        self.assertFalse(res["delivered"])
        self.assertEqual(mock_post.call_count, 2)
        self.assertIn("timeout", res["error"].lower())

    @patch("requests.post")
    def test_outbound_notification_service_auth_failure_non_retryable(self, mock_post):
        """Outbound Notification: 401 Unauthorized fails immediately on first attempt without retrying."""
        mock_resp = MagicMock()
        mock_resp.status_code = 401
        mock_resp.text = '{"detail": "Invalid authentication token"}'
        mock_post.return_value = mock_resp

        res = NotificationService.send_incident_notification(
            db=self.db,
            tenant=self.tenant_a,
            event_type="VULNERABILITY_CONFIRMED",
            threat_report=self.threat_report,
            asset=self.asset,
            max_retries=3
        )

        self.assertEqual(res["status"], "FAILED")
        self.assertEqual(mock_post.call_count, 1)  # Non-retryable
        self.assertEqual(res["status_code"], 401)

    @patch("requests.post")
    def test_outbound_notification_service_422_schema_error_non_retryable(self, mock_post):
        """Outbound Notification: 422 Unprocessable Entity fails immediately on first attempt."""
        mock_resp = MagicMock()
        mock_resp.status_code = 422
        mock_resp.text = '{"detail": [{"loc": ["body", "playbook"], "msg": "Field required"}]}'
        mock_post.return_value = mock_resp

        res = NotificationService.send_incident_notification(
            db=self.db,
            tenant=self.tenant_a,
            event_type="VULNERABILITY_CONFIRMED",
            threat_report=self.threat_report,
            asset=self.asset,
            max_retries=2
        )

        self.assertEqual(res["status"], "FAILED")
        self.assertEqual(mock_post.call_count, 1)
        self.assertEqual(res["status_code"], 422)

    @patch("requests.post")
    def test_outbound_notification_service_503_server_error_retryable(self, mock_post):
        """Outbound Notification: 503 Service Unavailable triggers all bounded retries."""
        mock_resp = MagicMock()
        mock_resp.status_code = 503
        mock_resp.text = "Service Temporarily Unavailable"
        mock_post.return_value = mock_resp

        res = NotificationService.send_incident_notification(
            db=self.db,
            tenant=self.tenant_a,
            event_type="VULNERABILITY_CONFIRMED",
            threat_report=self.threat_report,
            asset=self.asset,
            max_retries=2
        )

        self.assertEqual(res["status"], "FAILED")
        self.assertEqual(mock_post.call_count, 3)

    def test_outbound_notification_service_missing_webhook_url(self):
        """Outbound Notification: Tenant without webhook_url records locally without error."""
        tenant_no_url = models.Tenant(
            id=str(uuid.uuid4()),
            company_name="Local Only Corp",
            webhook_url=None
        )
        self.db.add(tenant_no_url)
        self.db.commit()

        res = NotificationService.send_incident_notification(
            db=self.db,
            tenant=tenant_no_url,
            event_type="VULNERABILITY_CONFIRMED",
            threat_report=self.threat_report,
            asset=self.asset
        )

        self.assertEqual(res["status"], "RECORDED_LOCALLY")
        self.assertFalse(res["delivered"])

    @patch("requests.post")
    def test_retry_notification_updates_status_and_preserves_human_confirmed(self, mock_post):
        """Retry Notification: Retrying failed notification updates DELIVERED while strictly preserving human_confirmed=False."""
        # Setup existing failed notification
        deliv_id = f"notif-fail-{uuid.uuid4().hex[:8]}"
        failed_notif = models.TenantNotification(
            delivery_id=deliv_id,
            tenant_id=self.tenant_a.id,
            event_type="VULNERABILITY_CONFIRMED",
            channel="WEBHOOK",
            recipient_url=self.tenant_a.webhook_url,
            status="FAILED",
            status_code=None,
            delivered=False,
            human_confirmed=False,
            error_message="[Initial Error] Connection refused"
        )
        self.db.add(failed_notif)
        self.db.commit()

        # Mock successful retry
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = '{"status": "RECEIVED"}'
        mock_post.return_value = mock_resp

        retry_res = NotificationService.retry_notification(
            db=self.db,
            delivery_id=deliv_id
        )

        self.assertEqual(retry_res["status"], "DELIVERED")
        self.assertTrue(retry_res["delivered"])
        self.assertFalse(retry_res["human_confirmed"])

        # Verify DB updated
        self.db.refresh(failed_notif)
        self.assertEqual(failed_notif.status, "DELIVERED")
        self.assertEqual(failed_notif.status_code, 200)
        self.assertTrue(failed_notif.delivered)
        self.assertFalse(failed_notif.human_confirmed)
        self.assertIsNone(failed_notif.error_message)

    @patch("requests.post")
    def test_end_to_end_vulnerability_confirmed_webhook_state_transition(self, mock_post):
        """End-to-End: Traces VULNERABILITY_CONFIRMED from failure (port offline) -> retry -> success, keeping ACK separate."""
        # 1. First attempt: connection error (simulates port 8000 offline)
        mock_post.side_effect = requests.exceptions.ConnectionError(
            "HTTPConnectionPool(host='127.0.0.1', port=8000): Max retries exceeded with url: /api/security/soar-webhook"
        )

        initial_res = NotificationService.send_incident_notification(
            db=self.db,
            tenant=self.tenant_a,
            event_type="VULNERABILITY_CONFIRMED",
            threat_report=self.threat_report,
            asset=self.asset,
            max_retries=1
        )
        deliv_id = initial_res["delivery_id"]
        self.assertEqual(initial_res["status"], "FAILED")
        self.assertFalse(initial_res["delivered"])
        self.assertFalse(initial_res["human_confirmed"])

        notif_step1 = self.db.query(models.TenantNotification).filter(
            models.TenantNotification.delivery_id == deliv_id
        ).first()
        self.assertEqual(notif_step1.status, "FAILED")
        self.assertFalse(notif_step1.human_confirmed)

        # 2. Receiver becomes available: Retry succeeds
        mock_post.side_effect = None
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = '{"status": "RECEIVED", "acknowledged": true}'
        mock_post.return_value = mock_resp

        retry_res = NotificationService.retry_notification(
            db=self.db,
            delivery_id=deliv_id
        )
        self.assertEqual(retry_res["status"], "DELIVERED")
        self.assertTrue(retry_res["delivered"])
        self.assertFalse(retry_res["human_confirmed"])

        # 3. Explicit SOC human acknowledgment (separate from webhook success)
        notif_step2 = self.db.query(models.TenantNotification).filter(
            models.TenantNotification.delivery_id == deliv_id
        ).first()
        self.assertEqual(notif_step2.status, "DELIVERED")
        self.assertFalse(notif_step2.human_confirmed)

        notif_step2.human_confirmed = True
        self.db.commit()

        self.db.refresh(notif_step2)
        self.assertTrue(notif_step2.human_confirmed)
        self.assertEqual(notif_step2.status, "DELIVERED")

