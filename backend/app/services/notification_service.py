"""
CyberScribe Company Notification Service
----------------------------------------
Delivers structured security advisories, vulnerability alerts, fixed-version notifications,
and containment lifecycle updates to company users and SOAR webhook endpoints.

GUARANTEES:
1. Honest Delivery Records: Never fakes successful delivery. Verifies HTTP status codes and timeouts.
2. Webhook ACK Safeguard: HTTP 200/ACCEPTED delivery is recorded as DELIVERED, but human_confirmed
   remains FALSE until an authorized company user explicitly acknowledges the notification.
3. Secret Safety: Strips API keys, passwords, and tokens before audit logging.
4. Structured Event Taxonomy:
   - VULNERABILITY_CONFIRMED: Dispatched on confirmed SBOM match.
   - CONTAINMENT_APPLIED: Dispatched when containment rule is established.
   - FIX_AVAILABLE: Dispatched under NOTIFY policy when verified fix is discovered.
   - PATCH_APPROVAL_REQUIRED: Dispatched when patch proposal awaits human authorization.
   - PATCH_STARTED: Dispatched when automated or manual patching begins.
   - PATCH_SUCCEEDED: Dispatched when patch installation command completes successfully.
   - PATCH_FAILED: Dispatched when package update fails, times out, or produces errors.
   - REMEDIATION_VERIFIED: Dispatched when post-patch version evaluates to NOT_AFFECTED.
   - CONTAINMENT_RELEASED: Dispatched when verified patch allows safe rule rollback.
"""

import uuid
import logging
import time
import re
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List
import requests
from sqlalchemy.orm import Session

from app.models import Tenant, ThreatMatch, ThreatReport, AssetComponent, TenantNotification

logger = logging.getLogger("NotificationService")
DEFAULT_TIMEOUT_SECONDS = 6.0


class NotificationService:
    """Dispatches and persists auditable security alerts and notifications to company endpoints."""

    @classmethod
    def _sanitize_error_message(cls, err: Any, target_url: Optional[str] = None) -> str:
        """Sanitizes connection and HTTP error messages, removing secrets, tokens, and internal memory addresses."""
        if not err:
            return ""
        err_str = str(err)
        
        # Scrub Bearer tokens, secrets, or API keys
        err_str = re.sub(r"Bearer\s+[A-Za-z0-9_\-\.]+", "Bearer [REDACTED]", err_str, flags=re.IGNORECASE)
        err_str = re.sub(r"(token|secret|key|password)=['\"][^'\"]+['\"]", r"\1='[REDACTED]'", err_str, flags=re.IGNORECASE)
        
        # Friendly format for connection refusal
        if "Failed to establish a new connection" in err_str or "actively refused" in err_str or "Connection refused" in err_str:
            host_match = re.search(r"host='([^']+)', port=(\d+)", err_str)
            if host_match:
                return f"Connection refused: Webhook receiver at {host_match.group(1)}:{host_match.group(2)} is offline or actively refusing connections."
            return "Connection refused: Webhook receiver endpoint is offline or unreachable."
            
        # Friendly format for timeouts
        if "timed out" in err_str.lower() or "timeout" in err_str.lower():
            return "Request timeout: Webhook receiver did not respond within configured timeout limit."
            
        # Friendly format for DNS resolution errors
        if "NameResolutionError" in err_str or "Failed to resolve" in err_str or "getaddrinfo failed" in err_str:
            return "DNS resolution error: Unable to resolve hostname for webhook endpoint."
            
        # Friendly format for TLS / SSL certificate validation failures
        if "SSLError" in err_str or "certificate verify failed" in err_str:
            return "TLS/SSL validation failure: Receiver certificate verification failed."
            
        # Strip internal object pointers (e.g. <urllib3.connection.HTTPConnection object at 0x...>)
        clean = re.sub(r"<[^>]+object at 0x[0-9a-fA-F]+>", "[Connection Object]", err_str)
        return clean[:250].strip()

    @classmethod
    def send_incident_notification(
        cls,
        db: Session,
        tenant: Tenant,
        event_type: str,
        threat_report: ThreatReport,
        asset: Optional[AssetComponent] = None,
        fixed_version: Optional[str] = None,
        remediation_policy: str = "NOTIFY",
        containment_action_id: Optional[str] = None,
        additional_evidence: Optional[str] = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        is_simulated: bool = False,
        action_status: Optional[str] = None,
        max_retries: int = 2
    ) -> Dict[str, Any]:
        """
        Builds, persists, and delivers an auditable notification to the tenant's configured endpoint.
        Enforces bounded retries, webhook ACK semantics, and independent email delivery.
        """
        delivery_id = f"notif-{uuid.uuid4().hex[:12]}"
        now = datetime.now(timezone.utc).isoformat()

        cve_id = threat_report.cve_id if threat_report else "UNKNOWN"
        pkg_name = asset.software_name if asset else "Unspecified"
        installed_ver = asset.software_version if asset else "Unspecified"

        # Build clean payload
        playbook_obj = {
            "playbook_name": f"Security Advisory {cve_id} ({event_type})",
            "recommended_action": f"Upgrade {pkg_name} to {fixed_version} and verify." if fixed_version else "Awaiting verified upstream patch release.",
            "firewall_rules": [f"Containment Action: {containment_action_id}"] if containment_action_id else [],
            "iocs": {"cve_id": [cve_id]} if cve_id else {},
            "sigma_rule": f"title: Advisory for {cve_id}\nstatus: active",
            "patch_guidance": f"Upgrade {pkg_name} to {fixed_version}." if fixed_version else "Awaiting patch."
        }

        payload = {
            "delivery_id": delivery_id,
            "event_type": event_type,
            "timestamp": now,
            "tenant_id": str(tenant.id),
            "tenant_name": tenant.company_name,
            "company_name": tenant.company_name,
            "cve_id": cve_id,
            "playbook": playbook_obj,
            "iocs": playbook_obj["iocs"],
            "threat": {
                "cve_id": cve_id,
                "title": threat_report.title if threat_report else "Threat Advisory",
                "severity": threat_report.severity if threat_report else "medium",
                "published_at": threat_report.published_at.isoformat() if threat_report and threat_report.published_at else None,
            },
            "affected_component": {
                "package_name": pkg_name,
                "installed_version": installed_ver,
                "environment": getattr(asset, "environment", "production") if asset else "production"
            },
            "remediation": {
                "policy": remediation_policy,
                "fixed_version": fixed_version,
                "is_fix_available": bool(fixed_version),
                "recommended_steps": f"Upgrade {pkg_name} to {fixed_version} and verify." if fixed_version else "Awaiting verified upstream patch release."
            },
            "containment": {
                "action_id": containment_action_id,
                "is_contained": bool(containment_action_id)
            },
            "evidence": additional_evidence or "",
            "details": {
                "cve_id": cve_id,
                "evidence": additional_evidence or "",
                "remediation_policy": remediation_policy,
                "fixed_version": fixed_version
            }
        }

        # If tenant has no webhook URL configured
        if not tenant.webhook_url:
            logger.info(f"Notification {delivery_id} recorded locally for {tenant.company_name} (no webhook configured).")
            res_dict = {
                "status": "RECORDED_LOCALLY",
                "delivery_id": delivery_id,
                "tenant_name": tenant.company_name,
                "event_type": event_type,
                "delivered": False,
                "human_confirmed": False,
                "reason": "Tenant has no configured webhook_url; recorded locally in audit ledger.",
                "payload": payload
            }
            cls._persist_record(
                db=db,
                delivery_id=delivery_id,
                tenant_id=tenant.id,
                threat_report_id=threat_report.id if threat_report else None,
                event_type=event_type,
                recipient_url=None,
                status="RECORDED_LOCALLY",
                status_code=None,
                delivered=False,
                cve_id=cve_id,
                pkg_name=pkg_name,
                installed_ver=installed_ver,
                fixed_ver=fixed_version,
                payload=payload,
                error_msg="No webhook configured; recorded locally in audit trail.",
                channel="WEBHOOK"
            )
        else:
            # Authenticated webhook dispatch with bounded retries and backoff
            token = getattr(tenant, "auth_token", None) or ""
            auth_header = token if token.startswith("Bearer ") else f"Bearer {token}" if token else ""
            headers = {
                "Content-Type": "application/json",
                "Authorization": auth_header,
                "X-CyberScribe-Event": event_type,
                "X-Delivery-ID": delivery_id
            }

            attempt = 0
            is_success = False
            last_resp = None
            last_err = ""

            while attempt <= max_retries:
                attempt += 1
                try:
                    resp = requests.post(
                        tenant.webhook_url,
                        json=payload,
                        headers=headers,
                        timeout=timeout
                    )
                    last_resp = resp
                    if resp.status_code in (200, 201, 202):
                        is_success = True
                        break
                    elif resp.status_code < 500:
                        # 4xx client errors (400, 401, 403, 404, 422) are non-retryable
                        last_err = f"HTTP {resp.status_code}: {resp.text[:200]}"
                        break
                    else:
                        # 5xx server errors retryable
                        last_err = f"HTTP {resp.status_code}: {resp.text[:200]}"
                        if attempt <= max_retries:
                            time.sleep(0.3 * attempt)
                except requests.Timeout as te:
                    last_err = f"Request timeout: Webhook receiver did not respond within {timeout}s"
                    if attempt <= max_retries:
                        time.sleep(0.3 * attempt)
                except Exception as e:
                    last_err = cls._sanitize_error_message(e, tenant.webhook_url)
                    if attempt <= max_retries:
                        time.sleep(0.3 * attempt)

            delivery_status = "DELIVERED" if is_success else "FAILED"
            status_code = last_resp.status_code if last_resp else None
            now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
            formatted_err = None if is_success else f"[{now_iso}] {last_err}"

            logger.info(f"Notification {delivery_id} to {tenant.company_name} [{event_type}]: {delivery_status} (HTTP {status_code})")
            res_dict = {
                "status": delivery_status,
                "delivery_id": delivery_id,
                "tenant_name": tenant.company_name,
                "event_type": event_type,
                "status_code": status_code,
                "delivered": is_success,
                "human_confirmed": False,
                "webhook_url": tenant.webhook_url,
                "payload": payload
            }
            if not is_success:
                res_dict["error"] = formatted_err

            cls._persist_record(
                db=db,
                delivery_id=delivery_id,
                tenant_id=tenant.id,
                threat_report_id=threat_report.id if threat_report else None,
                event_type=event_type,
                recipient_url=tenant.webhook_url,
                status=delivery_status,
                status_code=status_code,
                delivered=is_success,
                cve_id=cve_id,
                pkg_name=pkg_name,
                installed_ver=installed_ver,
                fixed_ver=fixed_version,
                payload=payload,
                error_msg=formatted_err,
                channel="WEBHOOK"
            )

        # Independent email dispatch (Requirement 8: Webhook failure must not suppress email)
        try:
            from app.services.email_notification_service import EmailNotificationService
            email_res = EmailNotificationService.send_email_notification(
                db=db,
                tenant=tenant,
                event_type=event_type,
                threat_report=threat_report,
                asset=asset,
                fixed_version=fixed_version,
                remediation_policy=remediation_policy,
                containment_action_id=containment_action_id,
                additional_evidence=additional_evidence,
                delivery_id=f"email-{delivery_id}",
                is_simulated=is_simulated,
                action_status=action_status
            )
            res_dict["email"] = email_res
        except Exception as email_err:
            logger.error(f"Independent email notification error: {email_err}")
            res_dict["email"] = {
                "status": "FAILED",
                "error": str(email_err),
                "delivered": False
            }

        return res_dict

    @classmethod
    def _persist_record(
        cls,
        db: Session,
        delivery_id: str,
        tenant_id: str,
        threat_report_id: Optional[str],
        event_type: str,
        recipient_url: Optional[str],
        status: str,
        status_code: Optional[int],
        delivered: bool,
        cve_id: Optional[str],
        pkg_name: Optional[str],
        installed_ver: Optional[str],
        fixed_ver: Optional[str],
        payload: Dict[str, Any],
        error_msg: Optional[str],
        channel: str = "WEBHOOK"
    ) -> None:
        """Persists notification record into database."""
        try:
            notif = TenantNotification(
                delivery_id=delivery_id,
                tenant_id=tenant_id,
                threat_report_id=threat_report_id,
                event_type=event_type,
                channel=channel,
                recipient_url=recipient_url,
                status=status,
                status_code=status_code,
                delivered=delivered,
                human_confirmed=False,
                cve_id=cve_id,
                affected_component=pkg_name,
                installed_version=installed_ver,
                fixed_version=fixed_ver,
                payload=payload,
                error_message=error_msg
            )
            db.add(notif)
            db.commit()
        except Exception as e:
            db.rollback()
            logger.error(f"Failed to persist TenantNotification {delivery_id}: {e}")

    @classmethod
    def retry_notification(
        cls,
        db: Session,
        delivery_id: str,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        max_retries: int = 2
    ) -> Dict[str, Any]:
        """
        Retries an existing failed notification with bounded backoff.
        Updates status, status_code, delivered, and error_message in-place.
        Preserves human_confirmed state strictly without auto-acknowledgment.
        """
        notif = db.query(TenantNotification).filter(
            TenantNotification.delivery_id == delivery_id
        ).first()

        if not notif:
            raise ValueError(f"Notification with delivery_id '{delivery_id}' not found.")

        tenant = db.query(Tenant).filter(Tenant.id == notif.tenant_id).first()
        if not tenant:
            raise ValueError(f"Tenant for notification '{delivery_id}' not found.")

        # If already delivered, return current state idempotently
        if notif.status == "DELIVERED":
            return {
                "status": "DELIVERED",
                "delivery_id": delivery_id,
                "tenant_name": tenant.company_name,
                "event_type": notif.event_type,
                "delivered": True,
                "human_confirmed": notif.human_confirmed,
                "message": f"Notification '{delivery_id}' already delivered successfully."
            }

        target_url = notif.recipient_url or tenant.webhook_url
        if not target_url:
            notif.status = "FAILED"
            now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
            notif.error_message = f"[{now_iso}] Tenant has no configured webhook_url"
            db.commit()
            return {
                "status": "FAILED",
                "delivery_id": delivery_id,
                "tenant_name": tenant.company_name,
                "event_type": notif.event_type,
                "delivered": False,
                "human_confirmed": notif.human_confirmed,
                "error": notif.error_message
            }

        # Use existing payload or construct clean fallback
        payload = notif.payload or {
            "delivery_id": notif.delivery_id,
            "event_type": notif.event_type,
            "tenant_id": str(tenant.id),
            "tenant_name": tenant.company_name,
            "cve_id": notif.cve_id,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

        token = getattr(tenant, "auth_token", None) or ""
        auth_header = token if token.startswith("Bearer ") else f"Bearer {token}" if token else ""
        headers = {
            "Content-Type": "application/json",
            "Authorization": auth_header,
            "X-CyberScribe-Event": notif.event_type,
            "X-Delivery-ID": delivery_id
        }

        attempt = 0
        is_success = False
        last_resp = None
        last_err = ""

        while attempt <= max_retries:
            attempt += 1
            try:
                resp = requests.post(
                    target_url,
                    json=payload,
                    headers=headers,
                    timeout=timeout
                )
                last_resp = resp
                if resp.status_code in (200, 201, 202):
                    is_success = True
                    break
                elif resp.status_code < 500:
                    # Non-retryable 4xx
                    last_err = f"HTTP {resp.status_code}: {resp.text[:200]}"
                    break
                else:
                    # Retryable 5xx
                    last_err = f"HTTP {resp.status_code}: {resp.text[:200]}"
                    if attempt <= max_retries:
                        time.sleep(0.3 * attempt)
            except requests.Timeout as te:
                last_err = f"Request timeout: Webhook receiver did not respond within {timeout}s"
                if attempt <= max_retries:
                    time.sleep(0.3 * attempt)
            except Exception as e:
                last_err = cls._sanitize_error_message(e, target_url)
                if attempt <= max_retries:
                    time.sleep(0.3 * attempt)

        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        notif.status = "DELIVERED" if is_success else "FAILED"
        notif.status_code = last_resp.status_code if last_resp else None
        notif.delivered = is_success
        notif.error_message = None if is_success else f"[{now_iso}] {last_err}"
        notif.recipient_url = target_url
        # Keep notif.human_confirmed untouched!
        db.commit()

        logger.info(f"Notification retry {delivery_id} to {tenant.company_name} [{notif.event_type}]: {notif.status} (HTTP {notif.status_code})")
        return {
            "status": notif.status,
            "delivery_id": delivery_id,
            "tenant_name": tenant.company_name,
            "event_type": notif.event_type,
            "status_code": notif.status_code,
            "delivered": is_success,
            "human_confirmed": notif.human_confirmed,
            "webhook_url": target_url,
            "error": notif.error_message
        }
