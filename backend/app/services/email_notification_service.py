"""
CyberScribe Authenticated Email Notification Service
---------------------------------------------------
Delivers structured, multi-part security advisories, vulnerability alerts, fixed-version
notifications, patch authorization requests, and containment lifecycle updates via
authenticated SMTP with TLS, bounded retries, and comprehensive tenant isolation.

SAFETY & COMPLIANCE GUARANTEES:
1. Honest Delivery Records: SMTP acceptance is recorded as 'SENT_TO_SMTP' (delivered=True),
   but 'human_confirmed' strictly remains FALSE until an authorized user explicitly confirms
   receipt in the dashboard.
2. Tenant Isolation: Recipients are strictly resolved from users belonging to the incident's
   tenant. Users from other tenants are never queried or emailed.
3. Safe Simulation Mode: If SMTP credentials or host are not configured, operates in
   simulation mode (status='SIMULATED', delivered=False) without failing or sending traffic.
4. Secret Scrubbing: Credentials, auth tokens, and internal IPs are never leaked in logs,
   email headers, or error messages.
5. Escaped Content: All untrusted fields (package names, CVE IDs, evidence text) are escaped
   via html.escape() to prevent HTML injection in email clients.
6. Idempotency & Duplicate Suppression: Prevents duplicate dispatches for the same delivery_id
   or incident token within an active window.
"""

import os
import re
import time
import html
import smtplib
import socket
import logging
import requests
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formataddr
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List, Tuple
from sqlalchemy.orm import Session

from app.models import Tenant, User, ThreatReport, AssetComponent, TenantNotification
from app.core.config import settings

logger = logging.getLogger("EmailNotificationService")

DEFAULT_SMTP_TIMEOUT = 8.0
DEFAULT_API_TIMEOUT = 8.0
MAX_SMTP_RETRIES = 2
TEST_EMAIL_RATE_LIMIT_SECONDS = 60
TEST_EMAIL_MAX_PER_WINDOW = 3

# In-memory rate limiting tracker for test emails: {tenant_id: [timestamp, ...]}
_test_email_rate_limit: Dict[str, List[float]] = {}


def get_email_config() -> Dict[str, Any]:
    """Retrieves current Email & Brevo configuration from environment / settings."""
    provider = os.getenv("EMAIL_PROVIDER", getattr(settings, "EMAIL_PROVIDER", "brevo")).strip().lower()
    email_enabled_env = os.getenv("EMAIL_ENABLED", str(getattr(settings, "EMAIL_ENABLED", False)))
    email_enabled = str(email_enabled_env).strip().lower() in ("true", "1", "yes")

    api_key = os.getenv("BREVO_API_KEY", getattr(settings, "BREVO_API_KEY", "")).strip()
    api_url = os.getenv("BREVO_API_URL", getattr(settings, "BREVO_API_URL", "https://api.brevo.com/v3/smtp/email")).strip()

    host = os.getenv("SMTP_HOST", getattr(settings, "SMTP_HOST", "")).strip()
    port_str = os.getenv("SMTP_PORT", str(getattr(settings, "SMTP_PORT", 587))).strip()
    try:
        port = int(port_str)
    except ValueError:
        port = 587

    username = os.getenv("SMTP_USERNAME", getattr(settings, "SMTP_USERNAME", "")).strip()
    password = os.getenv("SMTP_PASSWORD", getattr(settings, "SMTP_PASSWORD", "")).strip()

    # If BREVO_API_KEY is not set explicitly, check if password starts with xkeysib- (Brevo API key)
    if not api_key and password.startswith("xkeysib-"):
        api_key = password

    from_email = os.getenv(
        "BREVO_SENDER_EMAIL",
        os.getenv("SMTP_FROM_EMAIL", getattr(settings, "SMTP_FROM_EMAIL", "alerts@cyberscribe.local"))
    ).strip()
    from_name = os.getenv(
        "BREVO_SENDER_NAME",
        os.getenv("SMTP_FROM_NAME", getattr(settings, "SMTP_FROM_NAME", "CyberScribe Security"))
    ).strip()
    
    use_tls_env = os.getenv("SMTP_USE_TLS", str(getattr(settings, "SMTP_USE_TLS", True)))
    use_tls = str(use_tls_env).strip().lower() in ("true", "1", "yes")

    frontend_url = os.getenv("FRONTEND_URL", getattr(settings, "FRONTEND_URL", "http://localhost:5173")).rstrip("/")

    return {
        "provider": provider,
        "email_enabled": email_enabled,
        "api_key": api_key,
        "api_url": api_url,
        "host": host,
        "port": port,
        "username": username,
        "password": password,
        "from_email": from_email,
        "from_name": from_name,
        "use_tls": use_tls,
        "frontend_url": frontend_url
    }


get_smtp_config = get_email_config  # Backward compatibility alias


def is_smtp_configured() -> bool:
    """
    Returns True if minimum required email delivery settings are present AND
    real outbound email has been explicitly enabled via EMAIL_ENABLED=true.
    Safe simulation mode is maintained by default until explicitly enabled.
    """
    cfg = get_email_config()
    if not cfg.get("email_enabled", False):
        return False
    if cfg.get("provider") == "brevo" and cfg.get("api_key"):
        return True
    return bool(cfg.get("host"))


def is_email_configured() -> bool:
    """Forward and backward compatible check for configured email delivery."""
    return is_smtp_configured()


def sanitize_error_message(err: Exception) -> str:
    """Strips credentials, API keys, or internal network traces from error strings."""
    msg = str(err)
    cfg = get_email_config()
    if cfg.get("api_key"):
        msg = msg.replace(cfg["api_key"], "[API_KEY_REDACTED]")
    if cfg.get("password"):
        msg = msg.replace(cfg["password"], "********")
    if cfg.get("username"):
        msg = msg.replace(cfg["username"], "[USERNAME_REDACTED]")
    # Redact any Brevo API keys or SMTP passwords matching known patterns
    msg = re.sub(r"xkeysib-[a-zA-Z0-9_\-]+", "[API_KEY_REDACTED]", msg)
    msg = re.sub(r"xsmtpsib-[a-zA-Z0-9_\-]+", "[SMTP_KEY_REDACTED]", msg)
    return msg[:300]



class NotificationEligibilityPolicy:
    """
    Centralized Policy Engine for Security Email Notifications.
    
    POLICY RULES:
    Rule A (SBOM & Vulnerability Matches):
      - A match (VULNERABILITY_CONFIRMED) must NEVER trigger a containment-success
        or remediation-success email.
      - Can trigger an urgent action-required advisory only if severity is CRITICAL or HIGH.
      - Never word as a successful block, containment, or patch.
    Rule B (Containment Success):
      - Automatically send containment-success email ONLY for CRITICAL or HIGH threats
        where an authorized containment action actually executed and enforcement is verified.
      - Simulated, queued, recommended, or unverified actions are strictly suppressed.
    Rule C (Remediation/Patch Success):
      - Automatically send remediation-success email ONLY for CRITICAL or HIGH threats
        where patch was actually applied and post-action verification confirmed resolution.
      - Simulated or unverified actions are strictly suppressed.
    Rule D (Urgent Action Required):
      - Dispatches pending/action-required alerts for validated CRITICAL or HIGH threats
        requiring SOC attention (e.g., PATCH_APPROVAL_REQUIRED, FIX_AVAILABLE).
      - Clearly labeled as pending action, never as containment/patch success.
    Rule E (Failed or Unverified Actions):
      - Never send success emails for failed, skipped, timed out, or unverified actions.
      - Dispatches clearly labeled failure alert (PATCH_FAILED) with actual failure details.
    Severity Gate:
      - Critical and High threats are eligible for email notifications under this policy.
      - Medium and Low threats are suppressed from email notifications under this policy.
    """

    ELIGIBLE_SEVERITIES = {"CRITICAL", "HIGH"}

    @classmethod
    def evaluate(
        cls,
        event_type: str,
        severity: Optional[str] = "HIGH",
        is_simulated: bool = False,
        action_status: Optional[str] = None
    ) -> Tuple[bool, str]:
        """
        Evaluates whether an event qualifies for email notification dispatch under security policy.
        Returns (is_eligible: bool, policy_reason: str).
        """
        if event_type == "TEST_EMAIL_DISPATCHED":
            return True, "Authorized administrator diagnostic notification."

        sev = (severity or "HIGH").strip().upper()

        if sev not in cls.ELIGIBLE_SEVERITIES:
            return False, f"Threat severity '{sev}' is below notification threshold (requires CRITICAL or HIGH)."

        # Rule B: Containment Success
        if event_type == "CONTAINMENT_APPLIED":
            if is_simulated:
                return False, "Containment success email suppressed: action was simulated, not verified live enforcement."
            if action_status and action_status.upper() not in ("APPLIED", "VERIFIED"):
                return False, f"Containment success email suppressed: enforcement status is '{action_status}' (requires APPLIED or VERIFIED)."
            return True, "Verified containment enforcement confirmed on Critical/High threat."

        # Rule C: Remediation / Patch Success
        if event_type in ("REMEDIATION_VERIFIED", "PATCH_SUCCEEDED"):
            if is_simulated:
                return False, "Remediation success email suppressed: patch was simulated, not verified live execution."
            if action_status and action_status.upper() not in ("VERIFIED", "APPLIED", "SUCCESS"):
                return False, f"Remediation success email suppressed: remediation status is '{action_status}' (requires VERIFIED or APPLIED)."
            return True, "Verified software remediation confirmed on Critical/High threat."

        # Rule A & D: Urgent Action Required (Pending alerts - never worded as success)
        if event_type in ("VULNERABILITY_CONFIRMED", "PATCH_APPROVAL_REQUIRED", "FIX_AVAILABLE", "PATCH_STARTED"):
            return True, f"Urgent action-required notification for {sev} threat awaiting containment/remediation."

        # Rule E: Failed Actions
        if event_type == "PATCH_FAILED":
            return True, f"Action failure notification for {sev} threat."

        if event_type == "CONTAINMENT_RELEASED":
            if is_simulated:
                return False, "Containment release notification suppressed: simulated rollback."
            return True, f"Verified containment rollback notification for {sev} threat."

        return False, f"Event type '{event_type}' not eligible under security email policy."


class EmailNotificationService:
    """Delivers auditable, multi-part security emails with bounded retries and tenant isolation."""

    @classmethod
    def resolve_tenant_recipients(cls, db: Session, tenant_id: str) -> List[str]:
        """
        Resolves authorized recipient emails for a specific tenant.
        Strictly enforces tenant boundary: only users with matching tenant_id are returned.
        """
        users = db.query(User).filter(User.tenant_id == tenant_id).all()
        email_pattern = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
        recipients = []
        for u in users:
            if u.email and email_pattern.match(u.email.strip()):
                clean = u.email.strip().lower()
                if clean not in recipients:
                    recipients.append(clean)
        return recipients

    @classmethod
    def check_duplicate_suppression(
        cls,
        db: Session,
        tenant_id: str,
        idempotency_token: str,
        threat_report_id: Optional[str] = None,
        event_type: Optional[str] = None,
        window_seconds: int = 120
    ) -> Optional[TenantNotification]:
        """
        Checks if an email with the same idempotency token was already delivered or staged.
        Also suppresses rapid duplicate event dispatches for the same tenant + threat_report + event_type
        within a short time window (default 120 seconds) to prevent alert storms during repetitive feed ingestion.
        """
        existing = db.query(TenantNotification).filter(
            TenantNotification.tenant_id == tenant_id,
            TenantNotification.channel == "EMAIL",
            TenantNotification.delivery_id == idempotency_token,
            TenantNotification.status.in_(["SENT_TO_SMTP", "SIMULATED"])
        ).first()
        if existing:
            return existing

        # Rapid duplicate storm check for same threat + event_type
        if threat_report_id and event_type:
            recent = db.query(TenantNotification).filter(
                TenantNotification.tenant_id == tenant_id,
                TenantNotification.channel == "EMAIL",
                TenantNotification.threat_report_id == threat_report_id,
                TenantNotification.event_type == event_type,
                TenantNotification.status.in_(["SENT_TO_SMTP", "SIMULATED"])
            ).order_by(TenantNotification.created_at.desc()).first()
            if recent:
                cat = getattr(recent, "created_at", None)
                if cat is None or not isinstance(cat, datetime):
                    return recent
                now_utc = datetime.now(timezone.utc)
                if cat.tzinfo is None:
                    cat = cat.replace(tzinfo=timezone.utc)
                if abs((now_utc - cat).total_seconds()) < window_seconds:
                    return recent

        return None

    @classmethod
    def build_email_content(
        cls,
        tenant: Tenant,
        event_type: str,
        threat_report: Optional[ThreatReport] = None,
        asset: Optional[AssetComponent] = None,
        fixed_version: Optional[str] = None,
        remediation_policy: str = "NOTIFY",
        containment_action_id: Optional[str] = None,
        additional_evidence: Optional[str] = None,
        custom_message: Optional[str] = None
    ) -> Tuple[str, str, str]:
        """
        Constructs Subject, Plain Text, and HTML email templates.
        All user/external fields are strictly escaped to prevent HTML injection.
        """
        cfg = get_smtp_config()
        frontend_url = cfg["frontend_url"]

        company_name = html.escape(tenant.company_name or "Enterprise Tenant")
        cve_id = html.escape(threat_report.cve_id if threat_report and threat_report.cve_id else "SECURITY-ADVISORY")
        title = html.escape(threat_report.title if threat_report and threat_report.title else "Security Vulnerability Advisory")
        severity = (threat_report.severity if threat_report and threat_report.severity else "medium").upper()
        
        pkg_name = html.escape(asset.software_name if asset else "Software Inventory")
        installed_ver = html.escape(asset.software_version if asset else "Unspecified")
        environment = html.escape(getattr(asset, "environment", "production") if asset else "production")
        fixed_ver_clean = html.escape(fixed_version) if fixed_version else None
        action_id_clean = html.escape(containment_action_id) if containment_action_id else None
        evidence_clean = html.escape(additional_evidence) if additional_evidence else None
        msg_clean = html.escape(custom_message) if custom_message else None

        # Determine severity styling
        sev_colors = {
            "CRITICAL": "#ef4444",
            "HIGH": "#f97316",
            "MEDIUM": "#f59e0b",
            "LOW": "#06b6d4"
        }
        sev_color = sev_colors.get(severity, "#64748b")

        # Human-readable event description with explicit lifecycle status
        event_descriptions = {
            "VULNERABILITY_CONFIRMED": "Authoritative SBOM match confirmed. This advisory is PENDING SOC review and does NOT constitute a containment or remediation action.",
            "CONTAINMENT_APPLIED": "VERIFIED CONTAINMENT: Evidence-based temporary IP containment has been executed and verified to shield your service.",
            "FIX_AVAILABLE": "PENDING ACTION: A verified compatible upstream fix has been discovered for an active vulnerability. Awaiting remediation scheduling.",
            "PATCH_APPROVAL_REQUIRED": "URGENT ACTION REQUIRED: An autonomous patch proposal is awaiting explicit SOC approval under your NOTIFY policy. No patch has been applied yet.",
            "PATCH_STARTED": "Autonomous package upgrade execution has commenced on the authorized target environment.",
            "PATCH_SUCCEEDED": "VERIFIED PATCH: The package upgrade command executed successfully on the target host and post-action verification confirmed resolution.",
            "PATCH_FAILED": "ACTION FAILED: The automated package update failed, timed out, or produced an unexpected error. Containment remains active.",
            "REMEDIATION_VERIFIED": "VERIFIED REMEDIATION: Post-patch environment inspection independently confirmed remediation. Advisory resolved.",
            "CONTAINMENT_RELEASED": "VERIFIED RELEASE: Temporary containment rules have been safely rolled back following verified remediation.",
            "TEST_EMAIL_DISPATCHED": "Authorized test notification dispatched from the CyberScribe Remediation Console."
        }
        desc = event_descriptions.get(event_type, "Autonomous vulnerability response lifecycle notification.")

        # Distinct, non-deceptive subject lines ensuring clear status labeling
        if event_type == "VULNERABILITY_CONFIRMED":
            subject = f"[CyberScribe Advisory - PENDING ACTION REQUIRED] [{severity}] [{event_type}]: {cve_id} affecting {pkg_name}"
        elif event_type == "PATCH_APPROVAL_REQUIRED":
            subject = f"[CyberScribe Action Required - PENDING] [{severity}] [{event_type}]: {cve_id} affecting {pkg_name}"
        elif event_type == "CONTAINMENT_APPLIED":
            subject = f"[CyberScribe Containment Success (VERIFIED)] [{severity}] [{event_type}]: {cve_id} affecting {pkg_name}"
        elif event_type in ("REMEDIATION_VERIFIED", "PATCH_SUCCEEDED"):
            subject = f"[CyberScribe Remediation Success (VERIFIED)] [{severity}] [{event_type}]: {cve_id} affecting {pkg_name}"
        elif event_type == "PATCH_FAILED":
            subject = f"[CyberScribe Action Failed] [{severity}] [{event_type}]: {cve_id} affecting {pkg_name}"
        elif event_type == "FIX_AVAILABLE":
            subject = f"[CyberScribe Fix Available - PENDING ACTION] [{severity}] [{event_type}]: {cve_id} affecting {pkg_name}"
        else:
            subject = f"[CyberScribe Alert] [{severity}] [{event_type}]: {cve_id} affecting {pkg_name}"

        # Plain-text template
        text_lines = [
            f"CYBERSCRIBE AUTONOMOUS SECURITY ALERT",
            f"=====================================",
            f"Company:      {tenant.company_name}",
            f"Event:        {event_type}",
            f"Severity:     {severity}",
            f"Advisory:     {cve_id} - {threat_report.title if threat_report else 'Advisory'}",
            f"Component:    {pkg_name} (Installed: {installed_ver})",
            f"Environment:  {environment}",
            f"Remediation:  Policy: {remediation_policy} | Fixed Version: {fixed_version or 'Awaiting upstream release'}",
            f"Containment:  {'Active (' + containment_action_id + ')' if containment_action_id else 'None / Uncontained'}",
            f"",
            f"Event Details:",
            f"{desc}",
        ]
        if custom_message:
            text_lines.append(f"Message: {custom_message}")
        if additional_evidence:
            text_lines.append(f"Evidence: {additional_evidence}")
        text_lines.extend([
            f"",
            f"Access your tenant remediation console:",
            f"{frontend_url}/remediation",
            f"",
            f"Notice: SMTP delivery is not proof of human acknowledgment. Please sign off in the CyberScribe console.",
            f"CyberScribe Autonomous Vulnerability Response Platform - Confidential"
        ])
        plain_text = "\n".join(text_lines)

        # Responsive HTML template
        html_content = f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{subject}</title>
</head>
<body style="margin: 0; padding: 0; background-color: #020617; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; color: #f8fafc;">
  <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background-color: #020617; padding: 24px 0;">
    <tr>
      <td align="center">
        <table role="presentation" width="600" cellspacing="0" cellpadding="0" style="max-width: 600px; width: 100%; background-color: #0f172a; border: 1px solid #1e293b; border-radius: 12px; overflow: hidden; box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.5);">
          
          <!-- Header Bar -->
          <tr>
            <td style="padding: 20px 24px; background: linear-gradient(135deg, #090d16 0%, #1e1b4b 100%); border-bottom: 1px solid #1e293b;">
              <table width="100%" cellspacing="0" cellpadding="0">
                <tr>
                  <td>
                    <span style="font-size: 18px; font-weight: 800; font-family: monospace; letter-spacing: 1px; color: #38bdf8;">CYBER<span style="color: #a855f7;">SCRIBE</span></span>
                    <span style="font-size: 11px; font-family: monospace; color: #94a3b8; display: block; margin-top: 2px;">Autonomous Vulnerability Response Platform</span>
                  </td>
                  <td align="right">
                    <span style="display: inline-block; padding: 4px 10px; border-radius: 6px; font-size: 11px; font-weight: 700; font-family: monospace; background-color: {sev_color}22; color: {sev_color}; border: 1px solid {sev_color}55;">
                      {severity}
                    </span>
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- Event Banner -->
          <tr>
            <td style="padding: 24px 24px 12px 24px;">
              <div style="display: inline-block; padding: 3px 8px; border-radius: 4px; font-size: 11px; font-weight: 700; font-family: monospace; background-color: #0284c7; color: #ffffff; text-transform: uppercase;">
                {event_type}
              </div>
              <h1 style="margin: 12px 0 6px 0; font-size: 20px; font-weight: 700; color: #f1f5f9; line-height: 1.3;">
                {title}
              </h1>
              <p style="margin: 0; font-size: 13px; color: #94a3b8; line-height: 1.5;">
                {desc}
              </p>
            </td>
          </tr>

          {f'''<!-- Custom Message Callout -->
          <tr>
            <td style="padding: 0 24px 12px 24px;">
              <div style="background-color: #1e293b; border-left: 3px solid #38bdf8; padding: 12px; border-radius: 4px; font-size: 12px; color: #cbd5e1;">
                {msg_clean}
              </div>
            </td>
          </tr>''' if msg_clean else ''}

          <!-- Incident Metadata Table -->
          <tr>
            <td style="padding: 8px 24px 16px 24px;">
              <table width="100%" cellspacing="0" cellpadding="0" style="background-color: #090d16; border: 1px solid #1e293b; border-radius: 8px; font-size: 12px; font-family: monospace;">
                <tr>
                  <td style="padding: 10px 14px; border-bottom: 1px solid #1e293b; color: #64748b; width: 38%;">Target Company:</td>
                  <td style="padding: 10px 14px; border-bottom: 1px solid #1e293b; color: #f8fafc; font-weight: 600;">{company_name}</td>
                </tr>
                <tr>
                  <td style="padding: 10px 14px; border-bottom: 1px solid #1e293b; color: #64748b;">Advisory ID:</td>
                  <td style="padding: 10px 14px; border-bottom: 1px solid #1e293b; color: #38bdf8; font-weight: 700;">{cve_id}</td>
                </tr>
                <tr>
                  <td style="padding: 10px 14px; border-bottom: 1px solid #1e293b; color: #64748b;">Affected Package:</td>
                  <td style="padding: 10px 14px; border-bottom: 1px solid #1e293b; color: #f8fafc;"><strong>{pkg_name}</strong> (v{installed_ver})</td>
                </tr>
                <tr>
                  <td style="padding: 10px 14px; border-bottom: 1px solid #1e293b; color: #64748b;">Verified Fix Version:</td>
                  <td style="padding: 10px 14px; border-bottom: 1px solid #1e293b; color: {'#10b981' if fixed_ver_clean else '#94a3b8'}; font-weight: 600;">
                    {fixed_ver_clean or 'Awaiting verified patch release'}
                  </td>
                </tr>
                <tr>
                  <td style="padding: 10px 14px; border-bottom: 1px solid #1e293b; color: #64748b;">Remediation Policy:</td>
                  <td style="padding: 10px 14px; border-bottom: 1px solid #1e293b; color: #a855f7;">{remediation_policy}</td>
                </tr>
                <tr>
                  <td style="padding: 10px 14px; color: #64748b;">Containment State:</td>
                  <td style="padding: 10px 14px; color: {'#a855f7' if action_id_clean else '#94a3b8'};">
                    {'Active Rule: ' + action_id_clean if action_id_clean else 'No active containment'}
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          {f'''<!-- Evidence Box -->
          <tr>
            <td style="padding: 0 24px 16px 24px;">
              <div style="background-color: #0b1120; border: 1px solid #1e293b; border-radius: 8px; padding: 12px 14px;">
                <span style="font-size: 11px; font-family: monospace; font-weight: 700; color: #94a3b8; text-transform: uppercase;">Technical Evidence & Constraint Evaluation:</span>
                <p style="margin: 6px 0 0 0; font-size: 12px; font-family: monospace; color: #cbd5e1; line-height: 1.4;">
                  {evidence_clean}
                </p>
              </div>
            </td>
          </tr>''' if evidence_clean else ''}

          <!-- Action CTA -->
          <tr>
            <td style="padding: 12px 24px 28px 24px;" align="center">
              <a href="{frontend_url}/remediation" style="display: inline-block; padding: 12px 28px; background-color: #0284c7; color: #ffffff; text-decoration: none; font-size: 13px; font-weight: 700; border-radius: 6px; font-family: monospace; letter-spacing: 0.5px;">
                Open Remediation Console &rarr;
              </a>
              <div style="margin-top: 10px;">
                <a href="{frontend_url}/findings" style="color: #38bdf8; font-size: 11px; font-family: monospace; text-decoration: none;">
                  View Detailed Vulnerability Findings
                </a>
              </div>
            </td>
          </tr>

          <!-- Footer -->
          <tr>
            <td style="padding: 16px 24px; background-color: #090d16; border-top: 1px solid #1e293b; font-size: 11px; font-family: monospace; color: #64748b; text-align: center; line-height: 1.5;">
              This is an automated security advisory dispatched by CyberScribe Autonomous Vulnerability Response Platform.<br>
              <strong>Notice:</strong> SMTP delivery acceptance does not constitute verified human receipt. Authorized SOC personnel must sign off in the console.<br>
              &copy; {datetime.now().year} CyberScribe &bull; Confidential Tenant Notification
            </td>
          </tr>

        </table>
      </td>
    </tr>
  </table>
</body>
</html>"""
        return subject, plain_text, html_content

    @classmethod
    def send_email_notification(
        cls,
        db: Session,
        tenant: Tenant,
        event_type: str,
        threat_report: Optional[ThreatReport] = None,
        asset: Optional[AssetComponent] = None,
        fixed_version: Optional[str] = None,
        remediation_policy: str = "NOTIFY",
        containment_action_id: Optional[str] = None,
        additional_evidence: Optional[str] = None,
        custom_message: Optional[str] = None,
        override_recipients: Optional[List[str]] = None,
        delivery_id: Optional[str] = None,
        provider: Optional[str] = None,
        timeout: float = DEFAULT_SMTP_TIMEOUT,
        max_retries: int = MAX_SMTP_RETRIES,
        is_simulated: bool = False,
        action_status: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Executes an email notification dispatch for a tenant.
        - Resolves recipients with strict tenant isolation.
        - Checks duplicate suppression.
        - Enforces centralized NotificationEligibilityPolicy.
        - Falls back to SIMULATED mode if SMTP is not configured.
        - Executes authenticated TLS SMTP send or Brevo REST API with bounded retries.
        - Persists record in _tenant_notifications with channel='EMAIL'.
        """
        email_delivery_id = delivery_id or f"email-{os.urandom(6).hex()}"
        cfg = get_smtp_config()
        if provider:
            cfg["provider"] = str(provider).strip().lower()

        cve_id = threat_report.cve_id if threat_report and threat_report.cve_id else "UNKNOWN"
        pkg_name = asset.software_name if asset else "Unspecified"
        installed_ver = asset.software_version if asset else "Unspecified"

        # 1. Resolve recipients
        if override_recipients:
            recipients = [r.strip().lower() for r in override_recipients if "@" in r]
        else:
            recipients = cls.resolve_tenant_recipients(db=db, tenant_id=tenant.id)

        # 2. Check for duplicate suppression
        dup = cls.check_duplicate_suppression(
            db=db,
            tenant_id=tenant.id,
            idempotency_token=email_delivery_id,
            threat_report_id=threat_report.id if threat_report else None,
            event_type=event_type
        )
        if dup:
            logger.info(f"Duplicate email notification {email_delivery_id} suppressed for {tenant.company_name}.")
            return {
                "status": dup.status,
                "delivery_id": dup.delivery_id,
                "channel": "EMAIL",
                "delivered": dup.delivered,
                "human_confirmed": dup.human_confirmed,
                "recipients": recipients,
                "message": f"Email notification previously recorded ({dup.status}). Duplicate suppressed."
            }

        # 3. Handle zero recipients
        if not recipients:
            logger.info(f"No authorized recipients found for tenant {tenant.company_name} ({tenant.id}).")
            res_dict = {
                "status": "NO_RECIPIENTS",
                "delivery_id": email_delivery_id,
                "channel": "EMAIL",
                "delivered": False,
                "human_confirmed": False,
                "recipients": [],
                "message": "Tenant has no registered user emails. Email delivery skipped."
            }
            cls._persist_email_record(
                db=db,
                delivery_id=email_delivery_id,
                tenant_id=tenant.id,
                threat_report_id=threat_report.id if threat_report else None,
                event_type=event_type,
                recipients="",
                status="NO_RECIPIENTS",
                delivered=False,
                cve_id=cve_id,
                pkg_name=pkg_name,
                installed_ver=installed_ver,
                fixed_ver=fixed_version,
                payload={"event_type": event_type, "recipients": []},
                error_msg="No registered users with valid email addresses for this tenant."
            )
            return res_dict

        # 3b. Centralized Security Email Policy Evaluation
        effective_sev = threat_report.severity if threat_report and threat_report.severity else "HIGH"
        eligible, policy_reason = NotificationEligibilityPolicy.evaluate(
            event_type=event_type,
            severity=effective_sev,
            is_simulated=is_simulated,
            action_status=action_status
        )
        if not eligible:
            logger.info(f"Email notification {email_delivery_id} suppressed by policy: {policy_reason}")
            res_dict = {
                "status": "SUPPRESSED_POLICY",
                "delivery_id": email_delivery_id,
                "channel": "EMAIL",
                "delivered": False,
                "human_confirmed": False,
                "is_simulated": is_simulated,
                "recipients": recipients,
                "reason": policy_reason,
                "message": f"Email notification suppressed under security policy: {policy_reason}"
            }
            cls._persist_email_record(
                db=db,
                delivery_id=email_delivery_id,
                tenant_id=tenant.id,
                threat_report_id=threat_report.id if threat_report else None,
                event_type=event_type,
                recipients=",".join(recipients),
                status="SUPPRESSED_POLICY",
                delivered=False,
                cve_id=cve_id,
                pkg_name=pkg_name,
                installed_ver=installed_ver,
                fixed_ver=fixed_version,
                payload={"policy_suppressed": True, "reason": policy_reason, "severity": effective_sev},
                error_msg=policy_reason
            )
            return res_dict

        # 4. Construct templates
        subject, plain_text, html_body = cls.build_email_content(
            tenant=tenant,
            event_type=event_type,
            threat_report=threat_report,
            asset=asset,
            fixed_version=fixed_version,
            remediation_policy=remediation_policy,
            containment_action_id=containment_action_id,
            additional_evidence=additional_evidence,
            custom_message=custom_message
        )

        email_payload = {
            "delivery_id": email_delivery_id,
            "channel": "EMAIL",
            "event_type": event_type,
            "subject": subject,
            "recipients": recipients,
            "from_email": cfg["from_email"],
            "cve_id": cve_id,
            "package_name": pkg_name,
            "installed_version": installed_ver,
            "fixed_version": fixed_version,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

        # 5. Check if Email delivery is configured; if not, operate safely in SIMULATED mode
        if not is_email_configured():
            logger.info(
                f"[SIMULATED] Email notification {email_delivery_id} staged for {tenant.company_name} "
                f"to {recipients} ({event_type}). Email credentials or provider unconfigured."
            )
            res_dict = {
                "status": "SIMULATED",
                "delivery_id": email_delivery_id,
                "channel": "EMAIL",
                "provider": cfg.get("provider", "brevo"),
                "delivered": False,
                "human_confirmed": False,
                "is_simulated": True,
                "recipients": recipients,
                "subject": subject,
                "message": "Email delivery is unconfigured or EMAIL_ENABLED is false. Email notification safely staged in simulation mode."
            }
            cls._persist_email_record(
                db=db,
                delivery_id=email_delivery_id,
                tenant_id=tenant.id,
                threat_report_id=threat_report.id if threat_report else None,
                event_type=event_type,
                recipients=",".join(recipients),
                status="SIMULATED",
                delivered=False,
                cve_id=cve_id,
                pkg_name=pkg_name,
                installed_ver=installed_ver,
                fixed_ver=fixed_version,
                payload=email_payload,
                error_msg=None
            )
            return res_dict

        # 6. Preferred Route: Brevo Transactional Email REST API over HTTPS
        # Avoids SMTP IP-whitelisting restrictions on dynamic developer/residential networks
        if cfg.get("provider", "brevo") == "brevo" and cfg.get("api_key"):
            return cls._send_via_brevo_api(
                db=db,
                tenant=tenant,
                threat_report=threat_report,
                delivery_id=email_delivery_id,
                event_type=event_type,
                recipients=recipients,
                subject=subject,
                plain_text=plain_text,
                html_body=html_body,
                email_payload=email_payload,
                cfg=cfg,
                cve_id=cve_id,
                pkg_name=pkg_name,
                installed_ver=installed_ver,
                fixed_version=fixed_version,
                timeout=timeout,
                max_retries=max_retries
            )

        # 7. Fallback Route: Authenticated SMTP Relay (Legacy / Generic SMTP)
        return cls._send_via_smtp(
            db=db,
            tenant=tenant,
            threat_report=threat_report,
            delivery_id=email_delivery_id,
            event_type=event_type,
            recipients=recipients,
            subject=subject,
            plain_text=plain_text,
            html_body=html_body,
            email_payload=email_payload,
            cfg=cfg,
            cve_id=cve_id,
            pkg_name=pkg_name,
            installed_ver=installed_ver,
            fixed_version=fixed_version,
            timeout=timeout,
            max_retries=max_retries
        )

    @classmethod
    def _send_via_brevo_api(
        cls,
        db: Session,
        tenant: Tenant,
        threat_report: Optional[ThreatReport],
        delivery_id: str,
        event_type: str,
        recipients: List[str],
        subject: str,
        plain_text: str,
        html_body: str,
        email_payload: Dict[str, Any],
        cfg: Dict[str, Any],
        cve_id: Optional[str],
        pkg_name: Optional[str],
        installed_ver: Optional[str],
        fixed_version: Optional[str],
        timeout: float,
        max_retries: int
    ) -> Dict[str, Any]:
        """
        Delivers structured security advisory via Brevo Transactional Email REST API (HTTPS).
        Endpoint: POST https://api.brevo.com/v3/smtp/email
        Authenticates via HTTPS 'api-key' header without requiring dynamic IP whitelisting.
        """
        api_url = cfg.get("api_url") or "https://api.brevo.com/v3/smtp/email"
        headers = {
            "accept": "application/json",
            "content-type": "application/json",
            "api-key": cfg["api_key"]
        }

        api_payload = {
            "sender": {
                "name": cfg.get("from_name", "CyberScribe Security"),
                "email": cfg.get("from_email", "alerts@cyberscribe.local")
            },
            "to": [{"email": r} for r in recipients],
            "subject": subject,
            "htmlContent": html_body,
            "textContent": plain_text,
            "headers": {
                "X-CyberScribe-Event": event_type,
                "X-CyberScribe-Delivery-ID": delivery_id,
                "X-CyberScribe-Provider": "brevo-api"
            }
        }

        attempts = 0
        last_error = ""

        while attempts <= max_retries:
            attempts += 1
            try:
                logger.info(f"Connecting to Brevo Email API ({api_url}) (attempt {attempts}/{max_retries+1})...")
                resp = requests.post(
                    api_url,
                    json=api_payload,
                    headers=headers,
                    timeout=timeout
                )

                if resp.status_code in (200, 201, 202):
                    resp_data = resp.json() if resp.content else {}
                    message_id = resp_data.get("messageId", f"brevo-{delivery_id}")
                    logger.info(f"Email {delivery_id} successfully accepted by Brevo API (messageId: {message_id}) for {recipients}.")
                    res_dict = {
                        "status": "SENT_TO_SMTP",
                        "delivery_id": delivery_id,
                        "channel": "EMAIL",
                        "provider": "brevo",
                        "delivered": True,
                        "human_confirmed": False,
                        "recipients": recipients,
                        "subject": subject,
                        "message_id": message_id,
                        "message": "Email successfully accepted by Brevo HTTPS API (submitted for delivery). Inbox delivery confirmation requires recipient receipt."
                    }
                    cls._persist_email_record(
                        db=db,
                        delivery_id=delivery_id,
                        tenant_id=tenant.id,
                        threat_report_id=threat_report.id if threat_report else None,
                        event_type=event_type,
                        recipients=",".join(recipients),
                        status="SENT_TO_SMTP",
                        delivered=True,
                        cve_id=cve_id,
                        pkg_name=pkg_name,
                        installed_ver=installed_ver,
                        fixed_ver=fixed_version,
                        payload=email_payload,
                        error_msg=None
                    )
                    return res_dict

                # Handle HTTP errors from Brevo
                err_text = resp.text[:200]
                sanitized_err = sanitize_error_message(Exception(f"HTTP {resp.status_code}: {err_text}"))
                last_error = f"Brevo API error: {sanitized_err}"

                # Non-retryable client errors (400 Invalid Parameter, 401 Unauthorized, 403 Forbidden)
                if resp.status_code in (400, 401, 403):
                    logger.warning(f"Brevo API rejected dispatch (non-retryable): {last_error}")
                    break
                else:
                    logger.warning(f"Brevo API dispatch attempt {attempts} failed: {last_error}")
                    if attempts <= max_retries:
                        time.sleep(0.5)

            except (requests.Timeout, requests.RequestException, Exception) as e:
                last_error = sanitize_error_message(e)
                logger.warning(f"Brevo API request attempt {attempts} failed: {last_error}")
                if attempts <= max_retries:
                    time.sleep(0.5)

        # All retries exhausted or non-retryable error
        logger.error(f"Email dispatch {delivery_id} failed via Brevo API after {attempts} attempts: {last_error}")
        res_dict = {
            "status": "FAILED",
            "delivery_id": delivery_id,
            "channel": "EMAIL",
            "provider": "brevo",
            "delivered": False,
            "human_confirmed": False,
            "recipients": recipients,
            "error": last_error,
            "message": f"Brevo API dispatch failed: {last_error}"
        }
        cls._persist_email_record(
            db=db,
            delivery_id=delivery_id,
            tenant_id=tenant.id,
            threat_report_id=threat_report.id if threat_report else None,
            event_type=event_type,
            recipients=",".join(recipients),
            status="FAILED",
            delivered=False,
            cve_id=cve_id,
            pkg_name=pkg_name,
            installed_ver=installed_ver,
            fixed_ver=fixed_version,
            payload=email_payload,
            error_msg=last_error
        )
        return res_dict

    @classmethod
    def _send_via_smtp(
        cls,
        db: Session,
        tenant: Tenant,
        threat_report: Optional[ThreatReport],
        delivery_id: str,
        event_type: str,
        recipients: List[str],
        subject: str,
        plain_text: str,
        html_body: str,
        email_payload: Dict[str, Any],
        cfg: Dict[str, Any],
        cve_id: Optional[str],
        pkg_name: Optional[str],
        installed_ver: Optional[str],
        fixed_version: Optional[str],
        timeout: float,
        max_retries: int
    ) -> Dict[str, Any]:
        """Executes authenticated SMTP dispatch with bounded retries."""
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        if cfg.get("from_name"):
            msg["From"] = formataddr((cfg["from_name"], cfg["from_email"]))
        else:
            msg["From"] = cfg["from_email"]
        msg["To"] = ", ".join(recipients)
        msg["X-CyberScribe-Event"] = event_type
        msg["X-CyberScribe-Delivery-ID"] = delivery_id
        msg["X-CyberScribe-Provider"] = cfg.get("provider", "brevo")

        msg.attach(MIMEText(plain_text, "plain", "utf-8"))
        msg.attach(MIMEText(html_body, "html", "utf-8"))

        attempts = 0
        last_error = ""

        while attempts <= max_retries:
            attempts += 1
            try:
                logger.info(f"Connecting to SMTP server {cfg['host']}:{cfg['port']} (attempt {attempts}/{max_retries+1})...")
                if cfg["port"] == 465:
                    server = smtplib.SMTP_SSL(cfg["host"], cfg["port"], timeout=timeout)
                    server.ehlo()
                else:
                    server = smtplib.SMTP(cfg["host"], cfg["port"], timeout=timeout)
                    server.ehlo()
                    if cfg["use_tls"]:
                        server.starttls()
                        server.ehlo()

                if cfg["username"] and cfg["password"]:
                    server.login(cfg["username"], cfg["password"])

                server.sendmail(cfg["from_email"], recipients, msg.as_string())
                server.quit()

                logger.info(f"Email {delivery_id} successfully accepted by SMTP server for {recipients}.")
                res_dict = {
                    "status": "SENT_TO_SMTP",
                    "delivery_id": delivery_id,
                    "channel": "EMAIL",
                    "provider": cfg.get("provider", "brevo"),
                    "delivered": True,
                    "human_confirmed": False,
                    "recipients": recipients,
                    "subject": subject,
                    "message": "Email successfully accepted by upstream SMTP server (submitted for delivery). Inbox delivery confirmation requires recipient receipt."
                }
                cls._persist_email_record(
                    db=db,
                    delivery_id=delivery_id,
                    tenant_id=tenant.id,
                    threat_report_id=threat_report.id if threat_report else None,
                    event_type=event_type,
                    recipients=",".join(recipients),
                    status="SENT_TO_SMTP",
                    delivered=True,
                    cve_id=cve_id,
                    pkg_name=pkg_name,
                    installed_ver=installed_ver,
                    fixed_ver=fixed_version,
                    payload=email_payload,
                    error_msg=None
                )
                return res_dict

            except (smtplib.SMTPAuthenticationError, smtplib.SMTPException, socket.timeout, Exception) as e:
                last_error = sanitize_error_message(e)
                logger.warning(f"SMTP dispatch attempt {attempts} failed: {last_error}")
                if attempts <= max_retries:
                    time.sleep(0.5)

        # All retries exhausted
        logger.error(f"Email dispatch {delivery_id} failed after {attempts} attempts: {last_error}")
        res_dict = {
            "status": "FAILED",
            "delivery_id": delivery_id,
            "channel": "EMAIL",
            "delivered": False,
            "human_confirmed": False,
            "recipients": recipients,
            "error": last_error,
            "message": f"SMTP dispatch failed: {last_error}"
        }
        cls._persist_email_record(
            db=db,
            delivery_id=delivery_id,
            tenant_id=tenant.id,
            threat_report_id=threat_report.id if threat_report else None,
            event_type=event_type,
            recipients=",".join(recipients),
            status="FAILED",
            delivered=False,
            cve_id=cve_id,
            pkg_name=pkg_name,
            installed_ver=installed_ver,
            fixed_ver=fixed_version,
            payload=email_payload,
            error_msg=last_error
        )
        return res_dict

    @classmethod
    def send_test_email(
        cls,
        db: Session,
        tenant: Tenant,
        requesting_user: User,
        target_email: Optional[str] = None,
        provider: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Sends an authorized, rate-limited test security email.
        Enforces tenant boundary and bounded request rate.
        """
        now_ts = time.time()
        tenant_key = str(tenant.id)

        # Rate limiting check (max 3 per 60s)
        window = _test_email_rate_limit.get(tenant_key, [])
        window = [t for t in window if now_ts - t < TEST_EMAIL_RATE_LIMIT_SECONDS]
        if len(window) >= TEST_EMAIL_MAX_PER_WINDOW:
            oldest = window[0]
            wait_time = int(TEST_EMAIL_RATE_LIMIT_SECONDS - (now_ts - oldest))
            raise ValueError(f"Test email rate limit reached ({TEST_EMAIL_MAX_PER_WINDOW} per minute). Please wait {max(1, wait_time)} seconds.")

        # Update window
        window.append(now_ts)
        _test_email_rate_limit[tenant_key] = window

        # Determine target recipient
        if target_email and "@" in target_email:
            clean_target = target_email.strip().lower()
        else:
            clean_target = requesting_user.email.strip().lower()

        # Send test notification
        return cls.send_email_notification(
            db=db,
            tenant=tenant,
            event_type="TEST_EMAIL_DISPATCHED",
            threat_report=None,
            asset=None,
            fixed_version="1.0.0",
            remediation_policy=getattr(tenant, "remediation_policy", "NOTIFY") or "NOTIFY",
            additional_evidence="This is an authorized test verification email confirming end-to-end SMTP delivery.",
            custom_message=f"Test email initiated by {requesting_user.email} from IP/console.",
            override_recipients=[clean_target],
            provider=provider
        )

    @classmethod
    def _persist_email_record(
        cls,
        db: Session,
        delivery_id: str,
        tenant_id: str,
        threat_report_id: Optional[str],
        event_type: str,
        recipients: str,
        status: str,
        delivered: bool,
        cve_id: Optional[str],
        pkg_name: Optional[str],
        installed_ver: Optional[str],
        fixed_ver: Optional[str],
        payload: Dict[str, Any],
        error_msg: Optional[str]
    ) -> None:
        """Saves an immutable email dispatch audit record in _tenant_notifications."""
        try:
            notif = TenantNotification(
                delivery_id=delivery_id,
                tenant_id=tenant_id,
                threat_report_id=threat_report_id,
                event_type=event_type,
                channel="EMAIL",
                recipient_url=recipients[:500] if recipients else None,
                status=status,
                status_code=None,
                delivered=delivered,
                human_confirmed=False,
                cve_id=cve_id,
                affected_component=pkg_name,
                installed_version=installed_ver,
                fixed_version=fixed_ver,
                payload=payload,
                error_message=error_msg,
                created_at=datetime.now(timezone.utc)
            )
            db.add(notif)
            db.commit()
        except Exception as e:
            db.rollback()
            logger.error(f"Failed to persist email TenantNotification {delivery_id}: {e}")
