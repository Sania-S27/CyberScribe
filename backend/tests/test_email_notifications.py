"""
Unit & Integration Tests for CyberScribe Email Notification Service
-------------------------------------------------------------------
Verifies:
1. Strict tenant isolation during recipient resolution.
2. Safe simulation mode when SMTP is unconfigured.
3. Authenticated SMTP dispatch with TLS and MIME payload construction.
4. Error sanitization on SMTP authentication failure (no credential leakage).
5. Timeout handling and bounded retries.
6. Duplicate email suppression.
7. HTML escaping across all 9 security lifecycle events.
8. Independent channel dispatch (webhook failure does not suppress email).
9. Rate-limited test email authorization.
"""

import uuid
import socket
import smtplib
from unittest.mock import patch, MagicMock

from tests.base import BaseTestCase
from app import models
from app.services.email_notification_service import (
    EmailNotificationService,
    is_smtp_configured,
    get_smtp_config,
    sanitize_error_message
)
from app.services.notification_service import NotificationService
from app.services.autonomous_response_orchestrator import AutonomousResponseOrchestrator
from app.services.patch_adapter import PatchManagementAdapter


class TestEmailNotificationService(BaseTestCase):

    def setUp(self):
        super().setUp()

        # Tenant A (Primary)
        self.tenant_a = models.Tenant(
            id=str(uuid.uuid4()),
            company_name="Acme CyberCorp",
            tech_stack="FastAPI, React",
            webhook_url="http://127.0.0.1:8000/webhook"
        )
        self.db.add(self.tenant_a)

        # Tenant B (Foreign)
        self.tenant_b = models.Tenant(
            id=str(uuid.uuid4()),
            company_name="Rival Security Ltd",
            tech_stack="Django"
        )
        self.db.add(self.tenant_b)
        self.db.commit()

        # Users for Tenant A
        self.user_a1 = models.User(
            id=str(uuid.uuid4()),
            tenant_id=self.tenant_a.id,
            email="soc_analyst@acmecorp.com",
            password_hash="hash1",
            role="analyst"
        )
        self.user_a2 = models.User(
            id=str(uuid.uuid4()),
            tenant_id=self.tenant_a.id,
            email="ciso@acmecorp.com",
            password_hash="hash2",
            role="admin"
        )
        self.db.add_all([self.user_a1, self.user_a2])

        # User for Tenant B
        self.user_b1 = models.User(
            id=str(uuid.uuid4()),
            tenant_id=self.tenant_b.id,
            email="spy@rivalsec.com",
            password_hash="hash3",
            role="admin"
        )
        self.db.add(self.user_b1)

        # Asset and Threat Report
        self.asset = models.AssetComponent(
            id=str(uuid.uuid4()),
            tenant_id=self.tenant_a.id,
            software_name="fastapi",
            software_version="0.100.0",
            environment="production"
        )
        self.db.add(self.asset)

        self.report = models.ThreatReport(
            id=str(uuid.uuid4()),
            cve_id="CVE-2026-99999",
            title="FastAPI Input Validation Vulnerability",
            summary="FastAPI versions before 0.104.1 are vulnerable to denial of service. Fixed in 0.104.1.",
            severity="high"
        )
        self.db.add(self.report)
        self.db.commit()

    def test_recipient_resolution_enforces_strict_tenant_isolation(self):
        """TENANT ISOLATION: Resolving recipients for Tenant A must NEVER include Tenant B users."""
        recipients_a = EmailNotificationService.resolve_tenant_recipients(
            db=self.db,
            tenant_id=self.tenant_a.id
        )

        self.assertIn("soc_analyst@acmecorp.com", recipients_a)
        self.assertIn("ciso@acmecorp.com", recipients_a)
        self.assertNotIn("spy@rivalsec.com", recipients_a)
        self.assertEqual(len(recipients_a), 2)

        # Verify Tenant B resolution
        recipients_b = EmailNotificationService.resolve_tenant_recipients(
            db=self.db,
            tenant_id=self.tenant_b.id
        )
        self.assertIn("spy@rivalsec.com", recipients_b)
        self.assertNotIn("soc_analyst@acmecorp.com", recipients_b)
        self.assertEqual(len(recipients_b), 1)

    @patch("app.services.email_notification_service.is_smtp_configured", return_value=False)
    def test_simulation_mode_when_smtp_unconfigured(self, mock_is_configured):
        """Verifies safe simulation mode staging when SMTP is not configured."""
        res = EmailNotificationService.send_email_notification(
            db=self.db,
            tenant=self.tenant_a,
            event_type="VULNERABILITY_CONFIRMED",
            threat_report=self.report,
            asset=self.asset,
            fixed_version="0.104.1"
        )

        self.assertEqual(res["status"], "SIMULATED")
        self.assertTrue(res["is_simulated"])
        self.assertFalse(res["delivered"])
        self.assertFalse(res["human_confirmed"])
        self.assertIn("simulation mode", res["message"])

        # Database audit verification
        saved = self.db.query(models.TenantNotification).filter(
            models.TenantNotification.delivery_id == res["delivery_id"],
            models.TenantNotification.channel == "EMAIL"
        ).first()
        self.assertIsNotNone(saved)
        self.assertEqual(saved.status, "SIMULATED")
        self.assertFalse(saved.delivered)
        self.assertFalse(saved.human_confirmed)

    @patch("smtplib.SMTP")
    @patch("app.services.email_notification_service.is_smtp_configured", return_value=True)
    @patch("app.services.email_notification_service.get_smtp_config")
    def test_live_smtp_success_records_sent_to_smtp(self, mock_cfg, mock_is_configured, mock_smtp_class):
        """Verifies successful SMTP dispatch transitions to SENT_TO_SMTP without faking human confirmation."""
        mock_cfg.return_value = {
            "host": "smtp.acmesec.com",
            "port": 587,
            "username": "smtp_user",
            "password": "secret_password",
            "from_email": "alerts@acmesec.com",
            "use_tls": True,
            "frontend_url": "http://localhost:5173"
        }

        mock_server = MagicMock()
        mock_smtp_class.return_value = mock_server

        res = EmailNotificationService.send_email_notification(
            db=self.db,
            tenant=self.tenant_a,
            event_type="FIX_AVAILABLE",
            threat_report=self.report,
            asset=self.asset,
            fixed_version="0.104.1"
        )

        self.assertEqual(res["status"], "SENT_TO_SMTP")
        self.assertTrue(res["delivered"])
        self.assertFalse(res["human_confirmed"], "SMTP acceptance is NOT human receipt")

        # Check SMTP server calls
        mock_smtp_class.assert_called_with("smtp.acmesec.com", 587, timeout=8.0)
        mock_server.starttls.assert_called_once()
        mock_server.login.assert_called_with("smtp_user", "secret_password")
        mock_server.sendmail.assert_called_once()
        mock_server.quit.assert_called_once()

        # Database verification
        saved = self.db.query(models.TenantNotification).filter(
            models.TenantNotification.delivery_id == res["delivery_id"]
        ).first()
        self.assertIsNotNone(saved)
        self.assertEqual(saved.status, "SENT_TO_SMTP")
        self.assertEqual(saved.channel, "EMAIL")
        self.assertTrue(saved.delivered)
        self.assertFalse(saved.human_confirmed)

    @patch("smtplib.SMTP")
    @patch("app.services.email_notification_service.is_smtp_configured", return_value=True)
    @patch("app.services.email_notification_service.get_smtp_config")
    def test_smtp_authentication_failure_sanitizes_error(self, mock_cfg, mock_is_configured, mock_smtp_class):
        """Verifies SMTP auth failure is recorded as FAILED and credentials are never logged."""
        mock_cfg.return_value = {
            "host": "smtp.acmesec.com",
            "port": 587,
            "username": "smtp_user",
            "password": "super_secret_password_123",
            "from_email": "alerts@acmesec.com",
            "use_tls": True,
            "frontend_url": "http://localhost:5173"
        }

        mock_server = MagicMock()
        mock_server.login.side_effect = smtplib.SMTPAuthenticationError(535, b"Invalid credentials")
        mock_smtp_class.return_value = mock_server

        res = EmailNotificationService.send_email_notification(
            db=self.db,
            tenant=self.tenant_a,
            event_type="PATCH_APPROVAL_REQUIRED",
            threat_report=self.report,
            asset=self.asset,
            fixed_version="0.104.1",
            max_retries=0
        )

        self.assertEqual(res["status"], "FAILED")
        self.assertFalse(res["delivered"])
        self.assertNotIn("super_secret_password_123", res.get("error", ""))

        # Database record
        saved = self.db.query(models.TenantNotification).filter(
            models.TenantNotification.delivery_id == res["delivery_id"]
        ).first()
        self.assertIsNotNone(saved)
        self.assertEqual(saved.status, "FAILED")
        self.assertNotIn("super_secret_password_123", saved.error_message or "")

    @patch("smtplib.SMTP")
    @patch("app.services.email_notification_service.is_smtp_configured", return_value=True)
    @patch("app.services.email_notification_service.get_smtp_config")
    def test_smtp_timeout_and_bounded_retries(self, mock_cfg, mock_is_configured, mock_smtp_class):
        """Verifies bounded retry logic: attempts max_retries + 1 before marking FAILED."""
        mock_cfg.return_value = {
            "provider": "smtp",
            "host": "smtp.acmesec.com",
            "port": 587,
            "username": "smtp_user",
            "password": "secret_password",
            "from_email": "alerts@acmesec.com",
            "use_tls": True,
            "frontend_url": "http://localhost:5173",
            "api_key": ""
        }
        mock_smtp_class.side_effect = socket.timeout("Connection timed out")

        res = EmailNotificationService.send_email_notification(
            db=self.db,
            tenant=self.tenant_a,
            event_type="PATCH_STARTED",
            threat_report=self.report,
            asset=self.asset,
            provider="smtp",
            max_retries=2
        )

        self.assertEqual(res["status"], "FAILED")
        self.assertFalse(res["delivered"])
        self.assertEqual(mock_smtp_class.call_count, 3)  # Initial + 2 retries

    def test_duplicate_suppression_prevents_duplicate_sends(self):
        """Verifies duplicate dispatches with the same delivery_id are suppressed."""
        fixed_delivery_id = "email-dup-test-12345"

        # Staged initial record in DB
        initial_notif = models.TenantNotification(
            id=str(uuid.uuid4()),
            delivery_id=fixed_delivery_id,
            tenant_id=self.tenant_a.id,
            channel="EMAIL",
            event_type="PATCH_SUCCEEDED",
            status="SENT_TO_SMTP",
            delivered=True,
            human_confirmed=False
        )
        self.db.add(initial_notif)
        self.db.commit()

        # Second dispatch attempt with same delivery_id
        res = EmailNotificationService.send_email_notification(
            db=self.db,
            tenant=self.tenant_a,
            event_type="PATCH_SUCCEEDED",
            threat_report=self.report,
            asset=self.asset,
            delivery_id=fixed_delivery_id
        )

        self.assertEqual(res["status"], "SENT_TO_SMTP")
        self.assertIn("Duplicate suppressed", res["message"])

    def test_all_9_events_render_and_escape_untrusted_html(self):
        """Verifies HTML template generation and XSS escaping across all 9 event types."""
        events = [
            "VULNERABILITY_CONFIRMED",
            "CONTAINMENT_APPLIED",
            "FIX_AVAILABLE",
            "PATCH_APPROVAL_REQUIRED",
            "PATCH_STARTED",
            "PATCH_SUCCEEDED",
            "PATCH_FAILED",
            "REMEDIATION_VERIFIED",
            "CONTAINMENT_RELEASED"
        ]

        malicious_input = "<script>alert('xss')</script>"

        for evt in events:
            subject, text, html_out = EmailNotificationService.build_email_content(
                tenant=self.tenant_a,
                event_type=evt,
                threat_report=self.report,
                asset=self.asset,
                fixed_version=malicious_input,
                additional_evidence=malicious_input
            )

            # Assert unescaped script tag is NEVER present
            self.assertNotIn("<script>", html_out)
            self.assertNotIn("alert('xss')", html_out)
            self.assertIn("&lt;script&gt;", html_out)
            self.assertIn(evt, subject)
            self.assertIn(evt, text)

    @patch("requests.post")
    @patch("app.services.email_notification_service.EmailNotificationService.send_email_notification")
    def test_independent_channel_dispatch(self, mock_email_send, mock_webhook_post):
        """INDEPENDENT CHANNELS: Webhook network failure must NOT suppress email delivery."""
        mock_webhook_post.side_effect = Exception("Webhook connection refused")
        mock_email_send.return_value = {
            "status": "SENT_TO_SMTP",
            "delivered": True,
            "channel": "EMAIL"
        }

        res = NotificationService.send_incident_notification(
            db=self.db,
            tenant=self.tenant_a,
            event_type="CONTAINMENT_APPLIED",
            threat_report=self.report,
            asset=self.asset
        )

        # Webhook failed
        self.assertEqual(res["status"], "FAILED")
        self.assertFalse(res["delivered"])

        # Email was still independently invoked and succeeded
        mock_email_send.assert_called_once()
        self.assertIn("email", res)
        self.assertEqual(res["email"]["status"], "SENT_TO_SMTP")
        self.assertTrue(res["email"]["delivered"])

    @patch("app.services.email_notification_service.is_smtp_configured", return_value=False)
    def test_rate_limited_test_email(self, mock_is_configured):
        """Verifies rate-limiting on test email endpoint."""
        # 3 calls within window should succeed
        for _ in range(3):
            res = EmailNotificationService.send_test_email(
                db=self.db,
                tenant=self.tenant_a,
                requesting_user=self.user_a1
            )
            self.assertEqual(res["status"], "SIMULATED")

        # 4th call within 60s window must raise ValueError (rate limit exceeded)
        with self.assertRaises(ValueError) as ctx:
            EmailNotificationService.send_test_email(
                db=self.db,
                tenant=self.tenant_a,
                requesting_user=self.user_a1
            )
        self.assertIn("rate limit reached", str(ctx.exception).lower())

    @patch.dict("os.environ", {
        "EMAIL_PROVIDER": "brevo",
        "EMAIL_ENABLED": "true",
        "SMTP_HOST": "smtp-relay.brevo.com",
        "SMTP_PORT": "587",
        "SMTP_USERNAME": "test_brevo_user",
        "SMTP_PASSWORD": "test_brevo_password",
        "SMTP_FROM_EMAIL": "alerts@cyberscribe.security",
        "SMTP_FROM_NAME": "CyberScribe Security",
        "SMTP_USE_TLS": "true"
    })
    def test_brevo_config_and_display_name_formatting(self):
        """Verifies Brevo settings are correctly loaded and From header includes display name."""
        cfg = get_smtp_config()
        self.assertEqual(cfg["provider"], "brevo")
        self.assertTrue(cfg["email_enabled"])
        self.assertEqual(cfg["host"], "smtp-relay.brevo.com")
        self.assertEqual(cfg["port"], 587)
        self.assertEqual(cfg["from_email"], "alerts@cyberscribe.security")
        self.assertEqual(cfg["from_name"], "CyberScribe Security")
        self.assertTrue(cfg["use_tls"])
        self.assertTrue(is_smtp_configured())

    @patch.dict("os.environ", {
        "EMAIL_PROVIDER": "brevo",
        "EMAIL_ENABLED": "false",
        "SMTP_HOST": "smtp-relay.brevo.com"
    })
    def test_real_email_disabled_by_default_without_explicit_enablement(self):
        """Verifies real email remains disabled in safe SIMULATED mode if EMAIL_ENABLED=false."""
        self.assertFalse(is_smtp_configured())

        res = EmailNotificationService.send_email_notification(
            db=self.db,
            tenant=self.tenant_a,
            event_type="VULNERABILITY_CONFIRMED",
            threat_report=self.report,
            asset=self.asset
        )
        self.assertEqual(res["status"], "SIMULATED")
        self.assertFalse(res["delivered"])
        self.assertTrue(res["is_simulated"])

    @patch("smtplib.SMTP")
    @patch("app.services.email_notification_service.is_smtp_configured", return_value=True)
    @patch("app.services.email_notification_service.get_smtp_config")
    def test_admin_test_email_endpoint_super_admin_success(self, mock_cfg, mock_is_configured, mock_smtp_class):
        """ADMIN RBAC: Super admin can dispatch test email via admin endpoint with mock SMTP."""
        mock_cfg.return_value = {
            "provider": "smtp",
            "host": "smtp.acmesec.com",
            "port": 587,
            "username": "smtp_user",
            "password": "secret_password",
            "from_email": "alerts@acmesec.com",
            "from_name": "CyberScribe Security",
            "use_tls": True,
            "frontend_url": "http://localhost:5173",
            "api_key": ""
        }
        mock_server = MagicMock()
        mock_smtp_class.return_value = mock_server

        resp = self.client.post(
            "/admin/notifications/test-email",
            json={"target_email": "ciso-admin@enterprise.org"},
            headers=self.admin_headers
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["status"], "SENT_TO_SMTP")
        self.assertTrue(data["delivered"])
        self.assertIn("ciso-admin@enterprise.org", data["recipients"])

    @patch("requests.post")
    @patch("app.services.email_notification_service.is_smtp_configured", return_value=True)
    @patch("app.services.email_notification_service.get_smtp_config")
    def test_admin_test_email_endpoint_brevo_api_success(self, mock_cfg, mock_is_configured, mock_post):
        """ADMIN RBAC: Super admin can dispatch test email via admin endpoint using Brevo HTTPS API."""
        mock_cfg.return_value = {
            "provider": "brevo",
            "api_key": "xkeysib-mock-api-key-test-admin",
            "api_url": "https://api.brevo.com/v3/smtp/email",
            "from_email": "alerts@cyberscribe.security",
            "from_name": "CyberScribe Security",
            "frontend_url": "http://localhost:5173"
        }
        mock_resp = MagicMock()
        mock_resp.status_code = 201
        mock_resp.content = b'{"messageId": "<test-msg-id-admin@brevo>"}'
        mock_resp.json.return_value = {"messageId": "<test-msg-id-admin@brevo>"}
        mock_post.return_value = mock_resp

        resp = self.client.post(
            "/admin/notifications/test-email",
            json={"target_email": "ciso-admin@enterprise.org"},
            headers=self.admin_headers
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["status"], "SENT_TO_SMTP")
        self.assertTrue(data["delivered"])
        self.assertEqual(data["provider"], "brevo")
        self.assertEqual(data["message_id"], "<test-msg-id-admin@brevo>")
        self.assertIn("ciso-admin@enterprise.org", data["recipients"])

    def test_admin_test_email_endpoint_forbidden_for_tenant_user(self):
        """ADMIN RBAC: Tenant user attempting to call admin test-email endpoint gets 403 Forbidden."""
        resp = self.client.post(
            "/admin/notifications/test-email",
            json={"target_email": "attacker@evil.com"},
            headers=self.user_headers
        )
        self.assertEqual(resp.status_code, 403)
        self.assertIn("Admin access required", resp.json()["detail"])

    # =========================================================================
    # Brevo Transactional Email REST API (HTTPS) Tests
    # =========================================================================

    @patch("requests.post")
    @patch.dict("os.environ", {
        "EMAIL_PROVIDER": "brevo",
        "EMAIL_ENABLED": "true",
        "BREVO_API_KEY": "xkeysib-mock-api-key-test-1234567890",
        "BREVO_API_URL": "https://api.brevo.com/v3/smtp/email",
        "SMTP_FROM_EMAIL": "alerts@cyberscribe.security",
        "SMTP_FROM_NAME": "CyberScribe Security"
    })
    def test_brevo_api_success_records_sent_to_smtp(self, mock_requests_post):
        """BREVO API: Verifies successful HTTPS POST to /v3/smtp/email records SENT_TO_SMTP without faking human confirmation."""
        mock_resp = MagicMock()
        mock_resp.status_code = 201
        mock_resp.content = b'{"messageId": "<brevo-test-msgid-999@smtp-relay.mailin.fr>"}'
        mock_resp.json.return_value = {"messageId": "<brevo-test-msgid-999@smtp-relay.mailin.fr>"}
        mock_requests_post.return_value = mock_resp

        res = EmailNotificationService.send_email_notification(
            db=self.db,
            tenant=self.tenant_a,
            event_type="FIX_AVAILABLE",
            threat_report=self.report,
            asset=self.asset,
            fixed_version="0.104.1"
        )

        self.assertEqual(res["status"], "SENT_TO_SMTP")
        self.assertTrue(res["delivered"])
        self.assertFalse(res["human_confirmed"], "Brevo API acceptance is NOT verified human receipt")
        self.assertEqual(res["provider"], "brevo")
        self.assertEqual(res["message_id"], "<brevo-test-msgid-999@smtp-relay.mailin.fr>")

        # Verify HTTPS POST call
        mock_requests_post.assert_called_once()
        call_args, call_kwargs = mock_requests_post.call_args
        self.assertEqual(call_args[0], "https://api.brevo.com/v3/smtp/email")
        self.assertEqual(call_kwargs["headers"]["api-key"], "xkeysib-mock-api-key-test-1234567890")
        self.assertEqual(call_kwargs["headers"]["content-type"], "application/json")

        payload = call_kwargs["json"]
        self.assertEqual(payload["sender"]["email"], "alerts@cyberscribe.security")
        self.assertEqual(payload["sender"]["name"], "CyberScribe Security")
        self.assertEqual(len(payload["to"]), 2)
        to_emails = [t["email"] for t in payload["to"]]
        self.assertIn("soc_analyst@acmecorp.com", to_emails)
        self.assertIn("ciso@acmecorp.com", to_emails)
        self.assertIn("FIX_AVAILABLE", payload["subject"])
        self.assertIn("<!DOCTYPE html>", payload["htmlContent"])
        self.assertIn("0.104.1", payload["textContent"])

        # Database audit verification
        saved = self.db.query(models.TenantNotification).filter(
            models.TenantNotification.delivery_id == res["delivery_id"]
        ).first()
        self.assertIsNotNone(saved)
        self.assertEqual(saved.status, "SENT_TO_SMTP")
        self.assertEqual(saved.channel, "EMAIL")
        self.assertTrue(saved.delivered)
        self.assertFalse(saved.human_confirmed)

    @patch("requests.post")
    @patch.dict("os.environ", {
        "EMAIL_PROVIDER": "brevo",
        "EMAIL_ENABLED": "true",
        "BREVO_API_KEY": "xkeysib-super-secret-key-that-must-not-leak",
        "BREVO_API_URL": "https://api.brevo.com/v3/smtp/email"
    })
    def test_brevo_api_authentication_failure_sanitizes_error(self, mock_requests_post):
        """BREVO API: Verifies HTTP 401 is recorded as FAILED and API key is scrubbed from logs and DB."""
        mock_resp = MagicMock()
        mock_resp.status_code = 401
        mock_resp.text = '{"code": "unauthorized", "message": "Key not found for key xkeysib-super-secret-key-that-must-not-leak"}'
        mock_requests_post.return_value = mock_resp

        res = EmailNotificationService.send_email_notification(
            db=self.db,
            tenant=self.tenant_a,
            event_type="PATCH_APPROVAL_REQUIRED",
            threat_report=self.report,
            asset=self.asset,
            fixed_version="0.104.1",
            max_retries=2
        )

        self.assertEqual(res["status"], "FAILED")
        self.assertFalse(res["delivered"])
        self.assertNotIn("xkeysib-super-secret-key-that-must-not-leak", res.get("error", ""))
        self.assertIn("[API_KEY_REDACTED]", res.get("error", ""))
        # 401 is non-retryable: exactly 1 request made
        self.assertEqual(mock_requests_post.call_count, 1)

        # Database record check
        saved = self.db.query(models.TenantNotification).filter(
            models.TenantNotification.delivery_id == res["delivery_id"]
        ).first()
        self.assertIsNotNone(saved)
        self.assertEqual(saved.status, "FAILED")
        self.assertNotIn("xkeysib-super-secret-key-that-must-not-leak", saved.error_message or "")

    @patch("requests.post")
    @patch.dict("os.environ", {
        "EMAIL_PROVIDER": "brevo",
        "EMAIL_ENABLED": "true",
        "BREVO_API_KEY": "xkeysib-valid-key",
        "BREVO_API_URL": "https://api.brevo.com/v3/smtp/email"
    })
    def test_brevo_api_invalid_sender_error(self, mock_requests_post):
        """BREVO API: Verifies HTTP 400 sender verification error is captured honestly without retrying."""
        mock_resp = MagicMock()
        mock_resp.status_code = 400
        mock_resp.text = '{"code": "invalid_parameter", "message": "Sender email is not valid or not verified in Brevo account"}'
        mock_requests_post.return_value = mock_resp

        res = EmailNotificationService.send_email_notification(
            db=self.db,
            tenant=self.tenant_a,
            event_type="VULNERABILITY_CONFIRMED",
            threat_report=self.report,
            asset=self.asset
        )

        self.assertEqual(res["status"], "FAILED")
        self.assertFalse(res["delivered"])
        self.assertIn("Sender email is not valid", res.get("error", ""))
        # 400 is non-retryable
        self.assertEqual(mock_requests_post.call_count, 1)

    @patch("requests.post")
    @patch.dict("os.environ", {
        "EMAIL_PROVIDER": "brevo",
        "EMAIL_ENABLED": "true",
        "BREVO_API_KEY": "xkeysib-valid-key",
        "BREVO_API_URL": "https://api.brevo.com/v3/smtp/email"
    })
    def test_brevo_api_rate_limit_and_quota_error(self, mock_requests_post):
        """BREVO API: Verifies HTTP 429 rate limit is captured and handled safely."""
        mock_resp = MagicMock()
        mock_resp.status_code = 429
        mock_resp.text = '{"code": "rate_limit_exceeded", "message": "Too many requests"}'
        mock_requests_post.return_value = mock_resp

        res = EmailNotificationService.send_email_notification(
            db=self.db,
            tenant=self.tenant_a,
            event_type="PATCH_STARTED",
            threat_report=self.report,
            asset=self.asset,
            max_retries=1
        )

        self.assertEqual(res["status"], "FAILED")
        self.assertFalse(res["delivered"])
        self.assertIn("429", res.get("error", ""))

    @patch("requests.post")
    @patch.dict("os.environ", {
        "EMAIL_PROVIDER": "brevo",
        "EMAIL_ENABLED": "true",
        "BREVO_API_KEY": "xkeysib-valid-key",
        "BREVO_API_URL": "https://api.brevo.com/v3/smtp/email"
    })
    def test_brevo_api_timeout_and_retries(self, mock_requests_post):
        """BREVO API: Verifies network timeouts trigger bounded retries before failing."""
        import requests
        mock_requests_post.side_effect = requests.exceptions.Timeout("HTTPS connection timed out")

        res = EmailNotificationService.send_email_notification(
            db=self.db,
            tenant=self.tenant_a,
            event_type="CONTAINMENT_APPLIED",
            threat_report=self.report,
            asset=self.asset,
            max_retries=2
        )

        self.assertEqual(res["status"], "FAILED")
        self.assertFalse(res["delivered"])
        self.assertEqual(mock_requests_post.call_count, 3)  # Initial + 2 retries
        self.assertIn("timed out", res.get("error", "").lower())

    @patch("requests.post")
    @patch.dict("os.environ", {
        "EMAIL_PROVIDER": "brevo",
        "EMAIL_ENABLED": "true",
        "BREVO_API_KEY": "xkeysib-valid-key",
        "BREVO_API_URL": "https://api.brevo.com/v3/smtp/email"
    })
    def test_brevo_api_network_connection_failure(self, mock_requests_post):
        """BREVO API: Verifies DNS/connection failure records honest failure without crashing."""
        import requests
        mock_requests_post.side_effect = requests.exceptions.ConnectionError("Failed to resolve api.brevo.com")

        res = EmailNotificationService.send_email_notification(
            db=self.db,
            tenant=self.tenant_a,
            event_type="CONTAINMENT_RELEASED",
            threat_report=self.report,
            asset=self.asset,
            max_retries=0
        )

        self.assertEqual(res["status"], "FAILED")
        self.assertFalse(res["delivered"])
        self.assertIn("Failed to resolve", res.get("error", ""))

    # =========================================================================
    # Fully Automatic Application Workflow Integration Tests
    # =========================================================================

    @patch("requests.post")
    @patch.dict("os.environ", {
        "EMAIL_PROVIDER": "brevo",
        "EMAIL_ENABLED": "true",
        "BREVO_API_KEY": "xkeysib-auto-workflow-test-key",
        "BREVO_API_URL": "https://api.brevo.com/v3/smtp/email"
    })
    def test_automatic_email_dispatch_on_sbom_correlation_and_incident_creation(self, mock_requests_post):
        """AUTOMATIC WORKFLOW: Threat ingestion & SBOM correlation automatically dispatches Brevo email without manual test endpoint."""
        mock_resp = MagicMock()
        mock_resp.status_code = 201
        mock_resp.content = b'{"messageId": "<brevo-auto-incident-msg-001>"}'
        mock_resp.json.return_value = {"messageId": "<brevo-auto-incident-msg-001>"}
        mock_requests_post.return_value = mock_resp

        # Trigger real application workflow: OSINT/SBOM correlation
        res = AutonomousResponseOrchestrator.correlate_sbom_and_create_incident(
            db=self.db,
            tenant_id=self.tenant_a.id,
            threat_report_id=self.report.id,
            is_simulated=True
        )

        self.assertEqual(res["status"], "INCIDENT_CREATED")
        self.assertTrue(mock_requests_post.called, "Brevo HTTPS API should be called automatically upon SBOM correlation")

        # Verify Brevo API payload structure
        found_vuln_email = False
        for call_item in mock_requests_post.call_args_list:
            kwargs = call_item[1]
            if "json" in kwargs and kwargs["json"].get("headers", {}).get("X-CyberScribe-Event") == "VULNERABILITY_CONFIRMED":
                found_vuln_email = True
                payload = kwargs["json"]
                # Strict tenant recipient isolation
                recipient_emails = [t["email"] for t in payload["to"]]
                self.assertIn(self.user_a1.email, recipient_emails)
                self.assertIn(self.user_a2.email, recipient_emails)
                self.assertNotIn(self.user_b1.email, recipient_emails)
                # Subject & Content
                self.assertIn("VULNERABILITY_CONFIRMED", payload["subject"])
                self.assertIn("fastapi", payload["textContent"].lower())

        self.assertTrue(found_vuln_email, "Expected automatic VULNERABILITY_CONFIRMED notification to be sent to Brevo API")

        # Verify audit persistence in DB
        saved = self.db.query(models.TenantNotification).filter(
            models.TenantNotification.tenant_id == self.tenant_a.id,
            models.TenantNotification.channel == "EMAIL",
            models.TenantNotification.event_type == "VULNERABILITY_CONFIRMED"
        ).first()
        self.assertIsNotNone(saved)
        self.assertEqual(saved.status, "SENT_TO_SMTP")
        self.assertTrue(saved.delivered)
        self.assertFalse(saved.human_confirmed, "Upstream API acceptance must not fake human confirmation")

    @patch("requests.post")
    @patch.dict("os.environ", {
        "EMAIL_PROVIDER": "brevo",
        "EMAIL_ENABLED": "true",
        "BREVO_API_KEY": "xkeysib-auto-workflow-test-key",
        "BREVO_API_URL": "https://api.brevo.com/v3/smtp/email"
    })
    def test_automatic_email_dispatch_on_patch_execution_and_release(self, mock_requests_post):
        """AUTOMATIC WORKFLOW: Autonomous patch execution automatically dispatches PATCH_STARTED, SUCCEEDED, and VERIFIED."""
        mock_resp = MagicMock()
        mock_resp.status_code = 201
        mock_resp.content = b'{"messageId": "<brevo-patch-exec-msg-002>"}'
        mock_resp.json.return_value = {"messageId": "<brevo-patch-exec-msg-002>"}
        mock_requests_post.return_value = mock_resp

        # Create active threat match and proposal for Tenant A
        match = models.ThreatMatch(
            id=str(uuid.uuid4()),
            tenant_id=self.tenant_a.id,
            asset_component_id=self.asset.id,
            threat_report_id=self.report.id,
            status="OPEN",
            ai_confidence_score=95.0,
            ai_matching_reason="Authoritative CVE match"
        )
        self.db.add(match)
        self.db.commit()

        proposal = PatchManagementAdapter.create_proposal(
            db=self.db,
            tenant_id=self.tenant_a.id,
            threat_match_id=match.id,
            asset_component_id=self.asset.id,
            package_name="fastapi",
            target_version="0.104.1",
            package_manager="pip"
        )
        PatchManagementAdapter.approve_proposal(
            db=self.db,
            proposal_id=proposal.proposal_id,
            approver="SOC_LEAD",
            tenant_id=self.tenant_a.id
        )

        # Trigger workflow: execute_patch_and_release
        res = AutonomousResponseOrchestrator.execute_patch_and_release(
            db=self.db,
            proposal_id=proposal.proposal_id,
            tenant_id=self.tenant_a.id,
            is_simulated=True
        )

        self.assertEqual(res["status"], "SIMULATED_PATCH_SUCCEEDED")
        self.assertTrue(mock_requests_post.called)

        # Confirm events dispatched through Brevo API
        dispatched_events = []
        for call_item in mock_requests_post.call_args_list:
            kwargs = call_item[1]
            if "json" in kwargs:
                evt = kwargs["json"].get("headers", {}).get("X-CyberScribe-Event")
                if evt:
                    dispatched_events.append(evt)

        self.assertIn("PATCH_STARTED", dispatched_events)
        self.assertIn("PATCH_SUCCEEDED", dispatched_events)
        self.assertIn("REMEDIATION_VERIFIED", dispatched_events)

    @patch("requests.post")
    @patch.dict("os.environ", {
        "EMAIL_PROVIDER": "brevo",
        "EMAIL_ENABLED": "true",
        "BREVO_API_KEY": "xkeysib-auto-workflow-test-key",
        "BREVO_API_URL": "https://api.brevo.com/v3/smtp/email"
    })
    def test_automatic_email_dispatch_on_manual_remediation(self, mock_requests_post):
        """AUTOMATIC WORKFLOW: Manual remediation reporting verifies constraints and notifies tenant automatically."""
        mock_resp = MagicMock()
        mock_resp.status_code = 201
        mock_resp.content = b'{"messageId": "<brevo-manual-rem-msg-003>"}'
        mock_resp.json.return_value = {"messageId": "<brevo-manual-rem-msg-003>"}
        mock_requests_post.return_value = mock_resp

        # Create active threat match
        match = models.ThreatMatch(
            id=str(uuid.uuid4()),
            tenant_id=self.tenant_a.id,
            asset_component_id=self.asset.id,
            threat_report_id=self.report.id,
            status="OPEN",
            ai_confidence_score=95.0,
            ai_matching_reason="Confirmed CVE match"
        )
        self.db.add(match)
        self.db.commit()

        # Trigger workflow: manual remediation reported by user
        res = AutonomousResponseOrchestrator.process_manual_remediation(
            db=self.db,
            threat_match_id=match.id,
            tenant_id=self.tenant_a.id,
            new_version="0.104.1",
            notes="Upgraded manually via virtualenv."
        )

        self.assertEqual(res["status"], "RESOLVED_AND_RELEASED")
        self.assertTrue(mock_requests_post.called)

        # Check REMEDIATION_VERIFIED was dispatched
        dispatched_events = [
            c[1]["json"]["headers"]["X-CyberScribe-Event"]
            for c in mock_requests_post.call_args_list
            if "json" in c[1] and isinstance(c[1]["json"], dict) and "headers" in c[1]["json"]
        ]
        self.assertIn("REMEDIATION_VERIFIED", dispatched_events)

    @patch("requests.post")
    @patch.dict("os.environ", {
        "EMAIL_PROVIDER": "brevo",
        "EMAIL_ENABLED": "true",
        "BREVO_API_KEY": "xkeysib-auto-workflow-test-key",
        "BREVO_API_URL": "https://api.brevo.com/v3/smtp/email"
    })
    def test_automatic_workflow_deduplication_storm_suppression(self, mock_requests_post):
        """DEDUPLICATION: Repeated feed sweeps within window do NOT produce duplicate outbound emails."""
        mock_resp = MagicMock()
        mock_resp.status_code = 201
        mock_resp.content = b'{"messageId": "<brevo-storm-msg>"}'
        mock_resp.json.return_value = {"messageId": "<brevo-storm-msg>"}
        mock_requests_post.return_value = mock_resp

        # Sweep 1: Initial correlation
        AutonomousResponseOrchestrator.correlate_sbom_and_create_incident(
            db=self.db,
            tenant_id=self.tenant_a.id,
            threat_report_id=self.report.id,
            is_simulated=True
        )
        initial_brevo_calls = [
            c for c in mock_requests_post.call_args_list
            if c[0] and "brevo" in str(c[0][0])
        ]
        self.assertGreater(len(initial_brevo_calls), 0)

        # Sweep 2: Immediate re-trigger with identical incident
        AutonomousResponseOrchestrator.correlate_sbom_and_create_incident(
            db=self.db,
            tenant_id=self.tenant_a.id,
            threat_report_id=self.report.id,
            is_simulated=True
        )
        second_brevo_calls = [
            c for c in mock_requests_post.call_args_list
            if c[0] and "brevo" in str(c[0][0])
        ]

        # Brevo email calls must not duplicate for the exact same event within the storm suppression window
        self.assertEqual(len(initial_brevo_calls), len(second_brevo_calls), "Duplicate storm suppression should prevent re-dispatching outbound email")

    @patch("requests.post")
    @patch.dict("os.environ", {
        "EMAIL_PROVIDER": "brevo",
        "EMAIL_ENABLED": "true",
        "BREVO_API_KEY": "xkeysib-auto-workflow-test-key",
        "BREVO_API_URL": "https://api.brevo.com/v3/smtp/email"
    })
    def test_automatic_workflow_tenant_isolation_boundary(self, mock_requests_post):
        """TENANT ISOLATION: Incident for Tenant B automatically dispatches email ONLY to Tenant B users."""
        mock_resp = MagicMock()
        mock_resp.status_code = 201
        mock_resp.content = b'{"messageId": "<brevo-isolation-msg>"}'
        mock_resp.json.return_value = {"messageId": "<brevo-isolation-msg>"}
        mock_requests_post.return_value = mock_resp

        # Asset and threat for Tenant B
        asset_b = models.AssetComponent(
            id=str(uuid.uuid4()),
            tenant_id=self.tenant_b.id,
            software_name="django",
            software_version="4.0.0",
            environment="production"
        )
        report_b = models.ThreatReport(
            id=str(uuid.uuid4()),
            cve_id="CVE-2026-88888",
            title="Django Query Injection Vulnerability",
            severity="critical"
        )
        self.db.add_all([asset_b, report_b])
        self.db.commit()

        # Trigger workflow for Tenant B
        AutonomousResponseOrchestrator.correlate_sbom_and_create_incident(
            db=self.db,
            tenant_id=self.tenant_b.id,
            threat_report_id=report_b.id,
            is_simulated=True
        )

        self.assertTrue(mock_requests_post.called)
        # Inspect recipients of all calls
        for call_item in mock_requests_post.call_args_list:
            payload = call_item[1]["json"]
            recipient_emails = [t["email"] for t in payload["to"]]
            self.assertIn("spy@rivalsec.com", recipient_emails)
            self.assertNotIn("soc_analyst@acmecorp.com", recipient_emails)
            self.assertNotIn("ciso@acmecorp.com", recipient_emails)


