"""
Tests for Centralized Security Email Notification Policy (CyberScribe Section 2 & 4)
------------------------------------------------------------------------------------
Verifies:
1. Rule A: SBOM match (VULNERABILITY_CONFIRMED) by itself never triggers a containment-success
   or remediation-success email. Findings remain recorded as PENDING.
2. Rule B: Critical/High threat with verified containment triggers containment-success email.
   Simulated, queued, or unverified containment does NOT trigger success email.
3. Rule C: Critical/High threat with verified remediation triggers remediation-success email.
   Simulated or unverified remediation does NOT trigger success email.
4. Rule D: Critical/High threat awaiting action triggers urgent action-required alert (labeled pending).
5. Severity Gating: Medium and Low threats are suppressed from security success notifications.
6. Rule E: Failed action (PATCH_FAILED) triggers failure alert with actual outcome; never disguised as success.
7. Duplicate lifecycle events do not produce duplicate notifications.
8. Strict tenant isolation: recipients and advisories cannot cross tenant boundaries.
9. Provider timeout / HTTP error is handled safely without modifying security action outcomes.
10. Mocked Brevo REST API: zero real outbound network emails sent during tests.
"""

import uuid
from unittest.mock import patch, MagicMock

from tests.base import BaseTestCase
from app import models
from app.services.email_notification_service import (
    EmailNotificationService,
    NotificationEligibilityPolicy,
    get_smtp_config
)


class TestEmailNotificationPolicy(BaseTestCase):

    def setUp(self):
        super().setUp()

        # Tenant A (Primary)
        self.tenant_a = models.Tenant(
            id=str(uuid.uuid4()),
            company_name="Acme Defence Labs",
            tech_stack="FastAPI, React, Docker",
            webhook_url="http://127.0.0.1:8000/webhook",
            auth_token="ACME_BEARER_TOKEN_999"
        )
        self.db.add(self.tenant_a)

        # Tenant B (Foreign)
        self.tenant_b = models.Tenant(
            id=str(uuid.uuid4()),
            company_name="Foreign Corp",
            tech_stack="NodeJS"
        )
        self.db.add(self.tenant_b)
        self.db.commit()

        # Users for Tenant A
        self.user_a1 = models.User(
            id=str(uuid.uuid4()),
            tenant_id=self.tenant_a.id,
            email="secops@acmedefence.com",
            password_hash="hash1",
            role="analyst"
        )
        self.db.add(self.user_a1)

        # User for Tenant B
        self.user_b1 = models.User(
            id=str(uuid.uuid4()),
            tenant_id=self.tenant_b.id,
            email="intruder@foreigncorp.com",
            password_hash="hash2",
            role="admin"
        )
        self.db.add(self.user_b1)

        # Asset Component
        self.asset = models.AssetComponent(
            id=str(uuid.uuid4()),
            tenant_id=self.tenant_a.id,
            software_name="openssl",
            software_version="3.0.1",
            environment="production"
        )
        self.db.add(self.asset)

        # Critical Threat
        self.critical_threat = models.ThreatReport(
            id=str(uuid.uuid4()),
            cve_id="CVE-2026-1111",
            title="Critical OpenSSL Buffer Overflow RCE",
            summary="Remote code execution in OpenSSL 3.0.1",
            severity="critical"
        )
        # High Threat
        self.high_threat = models.ThreatReport(
            id=str(uuid.uuid4()),
            cve_id="CVE-2026-2222",
            title="High Severity Denial of Service",
            summary="Resource exhaustion vulnerability",
            severity="high"
        )
        # Medium Threat
        self.medium_threat = models.ThreatReport(
            id=str(uuid.uuid4()),
            cve_id="CVE-2026-3333",
            title="Medium Severity Information Leak",
            summary="Minor memory disclosure",
            severity="medium"
        )
        # Low Threat
        self.low_threat = models.ThreatReport(
            id=str(uuid.uuid4()),
            cve_id="CVE-2026-4444",
            title="Low Severity Debug Banner",
            summary="Verbose debug banner disclosure",
            severity="low"
        )
        self.db.add_all([self.critical_threat, self.high_threat, self.medium_threat, self.low_threat])
        self.db.commit()

    # -------------------------------------------------------------------------
    # 1. Rule A: SBOM Match Is Never A Containment or Remediation Success Email
    # -------------------------------------------------------------------------
    def test_sbom_match_never_triggers_success_email(self):
        """Rule A: An SBOM match (VULNERABILITY_CONFIRMED) must NEVER be formatted as containment or patch success."""
        subject, text, html_content = EmailNotificationService.build_email_content(
            tenant=self.tenant_a,
            event_type="VULNERABILITY_CONFIRMED",
            threat_report=self.critical_threat,
            asset=self.asset
        )

        self.assertIn("PENDING ACTION REQUIRED", subject)
        self.assertNotIn("Containment Success", subject)
        self.assertNotIn("Remediation Success", subject)
        self.assertIn("does NOT constitute a containment or remediation action", text)
        self.assertIn("does NOT constitute a containment or remediation action", html_content)

    # -------------------------------------------------------------------------
    # 2. Rule B: Containment Success Email
    # -------------------------------------------------------------------------
    @patch("requests.post")
    @patch.dict("os.environ", {
        "EMAIL_PROVIDER": "brevo",
        "EMAIL_ENABLED": "true",
        "BREVO_API_KEY": "xkeysib-mock-key-policy-test",
        "BREVO_API_URL": "https://api.brevo.com/v3/smtp/email"
    })
    def test_critical_threat_verified_containment_sends_containment_success_email(self, mock_post):
        """Rule B: Critical threat with verified live containment triggers containment-success email."""
        mock_resp = MagicMock()
        mock_resp.status_code = 201
        mock_resp.content = b'{"messageId": "<brevo-containment-msg-101>"}'
        mock_resp.json.return_value = {"messageId": "<brevo-containment-msg-101>"}
        mock_post.return_value = mock_resp

        res = EmailNotificationService.send_email_notification(
            db=self.db,
            tenant=self.tenant_a,
            event_type="CONTAINMENT_APPLIED",
            threat_report=self.critical_threat,
            asset=self.asset,
            containment_action_id="act-fw-9988",
            is_simulated=False,
            action_status="VERIFIED"
        )

        self.assertEqual(res["status"], "SENT_TO_SMTP")
        self.assertTrue(res["delivered"])
        mock_post.assert_called_once()
        call_payload = mock_post.call_args[1]["json"]
        self.assertIn("Containment Success (VERIFIED)", call_payload["subject"])
        self.assertIn("act-fw-9988", call_payload["textContent"])

    def test_simulated_containment_suppresses_success_email(self):
        """Rule B: Simulated containment action must NOT send containment-success email."""
        res = EmailNotificationService.send_email_notification(
            db=self.db,
            tenant=self.tenant_a,
            event_type="CONTAINMENT_APPLIED",
            threat_report=self.critical_threat,
            asset=self.asset,
            containment_action_id="act-fw-sim",
            is_simulated=True,
            action_status="SIMULATED"
        )

        self.assertEqual(res["status"], "SUPPRESSED_POLICY")
        self.assertFalse(res["delivered"])
        self.assertIn("simulated", res["reason"].lower())

    def test_unverified_containment_status_suppresses_success_email(self):
        """Rule B: Containment with status QUEUED or PENDING must NOT send success email."""
        for unverified_status in ["QUEUED", "PENDING", "RECOMMENDED", "DISPATCHED"]:
            res = EmailNotificationService.send_email_notification(
                db=self.db,
                tenant=self.tenant_a,
                event_type="CONTAINMENT_APPLIED",
                threat_report=self.high_threat,
                asset=self.asset,
                is_simulated=False,
                action_status=unverified_status
            )
            self.assertEqual(res["status"], "SUPPRESSED_POLICY")
            self.assertFalse(res["delivered"])
            self.assertIn(unverified_status, res["reason"])

    # -------------------------------------------------------------------------
    # 3. Rule C: Remediation / Patch Success Email
    # -------------------------------------------------------------------------
    @patch("requests.post")
    @patch.dict("os.environ", {
        "EMAIL_PROVIDER": "brevo",
        "EMAIL_ENABLED": "true",
        "BREVO_API_KEY": "xkeysib-mock-key-policy-test",
        "BREVO_API_URL": "https://api.brevo.com/v3/smtp/email"
    })
    def test_high_threat_verified_remediation_sends_remediation_success_email(self, mock_post):
        """Rule C: High threat with verified remediation triggers remediation-success email."""
        mock_resp = MagicMock()
        mock_resp.status_code = 201
        mock_resp.content = b'{"messageId": "<brevo-remediation-msg-102>"}'
        mock_resp.json.return_value = {"messageId": "<brevo-remediation-msg-102>"}
        mock_post.return_value = mock_resp

        res = EmailNotificationService.send_email_notification(
            db=self.db,
            tenant=self.tenant_a,
            event_type="REMEDIATION_VERIFIED",
            threat_report=self.high_threat,
            asset=self.asset,
            fixed_version="3.0.2",
            is_simulated=False,
            action_status="VERIFIED"
        )

        self.assertEqual(res["status"], "SENT_TO_SMTP")
        self.assertTrue(res["delivered"])
        mock_post.assert_called_once()
        call_payload = mock_post.call_args[1]["json"]
        self.assertIn("Remediation Success (VERIFIED)", call_payload["subject"])
        self.assertIn("3.0.2", call_payload["textContent"])

    def test_simulated_remediation_suppresses_success_email(self):
        """Rule C: Simulated remediation must NOT send remediation-success email."""
        res = EmailNotificationService.send_email_notification(
            db=self.db,
            tenant=self.tenant_a,
            event_type="REMEDIATION_VERIFIED",
            threat_report=self.critical_threat,
            asset=self.asset,
            fixed_version="3.0.2",
            is_simulated=True,
            action_status="SIMULATED"
        )

        self.assertEqual(res["status"], "SUPPRESSED_POLICY")
        self.assertFalse(res["delivered"])
        self.assertIn("simulated", res["reason"].lower())

    # -------------------------------------------------------------------------
    # 4. Rule D: Critical/High Threats Awaiting Action
    # -------------------------------------------------------------------------
    @patch("requests.post")
    @patch.dict("os.environ", {
        "EMAIL_PROVIDER": "brevo",
        "EMAIL_ENABLED": "true",
        "BREVO_API_KEY": "xkeysib-mock-key-policy-test",
        "BREVO_API_URL": "https://api.brevo.com/v3/smtp/email"
    })
    def test_critical_threat_awaiting_approval_sends_action_required_alert(self, mock_post):
        """Rule D: Validated Critical/High threat awaiting SOC authorization sends action-required alert."""
        mock_resp = MagicMock()
        mock_resp.status_code = 201
        mock_resp.content = b'{"messageId": "<brevo-action-req-msg-103>"}'
        mock_resp.json.return_value = {"messageId": "<brevo-action-req-msg-103>"}
        mock_post.return_value = mock_resp

        res = EmailNotificationService.send_email_notification(
            db=self.db,
            tenant=self.tenant_a,
            event_type="PATCH_APPROVAL_REQUIRED",
            threat_report=self.critical_threat,
            asset=self.asset,
            fixed_version="3.0.2"
        )

        self.assertEqual(res["status"], "SENT_TO_SMTP")
        self.assertTrue(res["delivered"])
        call_payload = mock_post.call_args[1]["json"]
        self.assertIn("Action Required - PENDING", call_payload["subject"])
        self.assertNotIn("Success", call_payload["subject"])

    # -------------------------------------------------------------------------
    # 5. Severity Gating: Medium and Low Threats Suppressed
    # -------------------------------------------------------------------------
    def test_medium_and_low_threats_suppressed_from_success_notifications(self):
        """Severity Gate: Medium and Low severity threats do not trigger notifications under this policy."""
        for low_med_threat in [self.medium_threat, self.low_threat]:
            res = EmailNotificationService.send_email_notification(
                db=self.db,
                tenant=self.tenant_a,
                event_type="CONTAINMENT_APPLIED",
                threat_report=low_med_threat,
                asset=self.asset,
                is_simulated=False,
                action_status="VERIFIED"
            )
            self.assertEqual(res["status"], "SUPPRESSED_POLICY")
            self.assertFalse(res["delivered"])
            self.assertIn("below notification threshold", res["reason"])

    # -------------------------------------------------------------------------
    # 6. Rule E: Failed Actions Send Clearly Labeled Failure Alert
    # -------------------------------------------------------------------------
    @patch("requests.post")
    @patch.dict("os.environ", {
        "EMAIL_PROVIDER": "brevo",
        "EMAIL_ENABLED": "true",
        "BREVO_API_KEY": "xkeysib-mock-key-policy-test",
        "BREVO_API_URL": "https://api.brevo.com/v3/smtp/email"
    })
    def test_failed_patch_sends_action_failed_alert_never_success(self, mock_post):
        """Rule E: Failed actions send action-failed alert; never silently convert failure to success."""
        mock_resp = MagicMock()
        mock_resp.status_code = 201
        mock_resp.content = b'{"messageId": "<brevo-failure-msg-104>"}'
        mock_resp.json.return_value = {"messageId": "<brevo-failure-msg-104>"}
        mock_post.return_value = mock_resp

        res = EmailNotificationService.send_email_notification(
            db=self.db,
            tenant=self.tenant_a,
            event_type="PATCH_FAILED",
            threat_report=self.critical_threat,
            asset=self.asset,
            fixed_version="3.0.2",
            additional_evidence="Subprocess exited with return code 1: package collision"
        )

        self.assertEqual(res["status"], "SENT_TO_SMTP")
        self.assertTrue(res["delivered"])
        call_payload = mock_post.call_args[1]["json"]
        self.assertIn("Action Failed", call_payload["subject"])
        self.assertNotIn("Success", call_payload["subject"])
        self.assertIn("package collision", call_payload["textContent"])

    # -------------------------------------------------------------------------
    # 7. Duplicate Event Idempotency Suppression
    # -------------------------------------------------------------------------
    @patch("requests.post")
    @patch.dict("os.environ", {
        "EMAIL_PROVIDER": "brevo",
        "EMAIL_ENABLED": "true",
        "BREVO_API_KEY": "xkeysib-mock-key-policy-test",
        "BREVO_API_URL": "https://api.brevo.com/v3/smtp/email"
    })
    def test_duplicate_events_do_not_produce_duplicate_emails(self, mock_post):
        """Idempotency: Re-dispatching same delivery_id or rapid duplicate event is suppressed."""
        mock_resp = MagicMock()
        mock_resp.status_code = 201
        mock_resp.content = b'{"messageId": "<brevo-idempotent-msg-105>"}'
        mock_resp.json.return_value = {"messageId": "<brevo-idempotent-msg-105>"}
        mock_post.return_value = mock_resp

        delivery_id = f"email-dedup-{uuid.uuid4().hex[:8]}"

        # First dispatch succeeds
        res1 = EmailNotificationService.send_email_notification(
            db=self.db,
            tenant=self.tenant_a,
            event_type="PATCH_APPROVAL_REQUIRED",
            threat_report=self.critical_threat,
            asset=self.asset,
            delivery_id=delivery_id
        )
        self.assertEqual(res1["status"], "SENT_TO_SMTP")
        self.assertEqual(mock_post.call_count, 1)

        # Second dispatch with identical delivery_id is suppressed
        res2 = EmailNotificationService.send_email_notification(
            db=self.db,
            tenant=self.tenant_a,
            event_type="PATCH_APPROVAL_REQUIRED",
            threat_report=self.critical_threat,
            asset=self.asset,
            delivery_id=delivery_id
        )
        self.assertIn("Duplicate suppressed", res2["message"])
        self.assertEqual(mock_post.call_count, 1)  # No second HTTP call

    # -------------------------------------------------------------------------
    # 8. Strict Multi-Tenant Isolation
    # -------------------------------------------------------------------------
    @patch("requests.post")
    @patch.dict("os.environ", {
        "EMAIL_PROVIDER": "brevo",
        "EMAIL_ENABLED": "true",
        "BREVO_API_KEY": "xkeysib-mock-key-policy-test",
        "BREVO_API_URL": "https://api.brevo.com/v3/smtp/email"
    })
    def test_cross_tenant_recipients_and_data_strictly_isolated(self, mock_post):
        """Tenant Isolation: Recipients of Tenant B are never emailed or leaked during Tenant A alerts."""
        mock_resp = MagicMock()
        mock_resp.status_code = 201
        mock_resp.content = b'{"messageId": "<brevo-iso-msg-106>"}'
        mock_resp.json.return_value = {"messageId": "<brevo-iso-msg-106>"}
        mock_post.return_value = mock_resp

        EmailNotificationService.send_email_notification(
            db=self.db,
            tenant=self.tenant_a,
            event_type="PATCH_APPROVAL_REQUIRED",
            threat_report=self.critical_threat,
            asset=self.asset
        )

        call_payload = mock_post.call_args[1]["json"]
        to_addresses = [t["email"] for t in call_payload["to"]]
        self.assertIn("secops@acmedefence.com", to_addresses)
        self.assertNotIn("intruder@foreigncorp.com", to_addresses)

    # -------------------------------------------------------------------------
    # 9. Provider Timeout Handled Safely Without Changing Security Action
    # -------------------------------------------------------------------------
    @patch("requests.post")
    @patch.dict("os.environ", {
        "EMAIL_PROVIDER": "brevo",
        "EMAIL_ENABLED": "true",
        "BREVO_API_KEY": "xkeysib-mock-key-policy-test",
        "BREVO_API_URL": "https://api.brevo.com/v3/smtp/email"
    })
    def test_provider_timeout_does_not_crash_or_alter_security_operations(self, mock_post):
        """Resilience: Email network timeout records honest failure and does not crash caller."""
        import requests
        mock_post.side_effect = requests.exceptions.Timeout("Brevo HTTPS API timed out")

        res = EmailNotificationService.send_email_notification(
            db=self.db,
            tenant=self.tenant_a,
            event_type="PATCH_APPROVAL_REQUIRED",
            threat_report=self.critical_threat,
            asset=self.asset,
            max_retries=1
        )

        self.assertEqual(res["status"], "FAILED")
        self.assertFalse(res["delivered"])
        self.assertIn("timed out", res.get("error", "").lower())
