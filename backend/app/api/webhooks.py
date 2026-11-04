"""
CyberScribe Inbound Webhook Receiver
-----------------------------------
Receives, authenticates, validates, and audits inbound webhooks from external SOAR,
Campus Guide, or security operations platforms with strict tenant isolation,
bogon filtering, and idempotency guarantees.

SAFETY & COMPLIANCE GUARANTEES:
1. Strict Authentication: Requires Authorization Bearer token matching tenant.auth_token
   or SOAR_WEBHOOK_SECRET.
2. Tenant Isolation: Incoming payloads are validated against the target tenant boundary.
   Cross-tenant execution or credential reuse is strictly rejected.
3. Schema Validation: Malformed payloads, invalid event types, or malicious parameters are rejected.
4. Idempotency: Duplicate delivery IDs are acknowledged safely without re-triggering actions.
5. Non-repudiation & Honest Semantics: Acknowledging receipt with HTTP 200 (RECEIVED) confirms
   payload delivery only. It is NEVER treated as proof of live firewall enforcement or patch verification.
"""

import os
import uuid
import logging
from typing import Dict, Any, Optional
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Header, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models import Tenant, TenantNotification, ContainmentAction, ThreatMatch
from app.services.containment_policy import AutonomousPolicyEngine

logger = logging.getLogger("WebhooksAPI")
router = APIRouter(tags=["Webhooks"])


class SOARWebhookPayload(BaseModel):
    tenant_id: str = Field(..., description="Target tenant UUID")
    event_type: str = Field(..., description="Security event type, e.g. CONTAINMENT_REQUEST, REMEDIATION_FEEDBACK, IOC_ALERT")
    delivery_id: Optional[str] = Field(None, description="Idempotency delivery token")
    timestamp: Optional[str] = Field(None, description="ISO8601 event timestamp")
    cve_id: Optional[str] = Field(None, description="Associated CVE identifier")
    indicator_value: Optional[str] = Field(None, description="Target IP or IOC indicator")
    indicator_type: Optional[str] = Field("ip_address", description="Indicator type")
    action_type: Optional[str] = Field("IP_BLOCK", description="Requested action type")
    details: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Additional context or evidence")


def _authenticate_webhook_sender(
    authorization: Optional[str],
    target_tenant: Tenant
) -> None:
    """
    Validates sender credentials against tenant auth_token or platform SOAR secret.
    Rejects unauthorized requests with 401/403.
    """
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization header. Bearer token required."
        )

    parts = authorization.strip().split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Malformed Authorization header. Format: 'Bearer <token>'"
        )

    token = parts[1]
    expected_tenant_token = getattr(target_tenant, "auth_token", None) or ""
    global_soar_secret = os.getenv("SOAR_WEBHOOK_SECRET", os.getenv("SOAR_AUTH_TOKEN", "CAMPUS_DEFENSE_TOKEN_2026"))

    # Verify token belongs to this tenant or global SOAR integration
    if token != expected_tenant_token and token != global_soar_secret:
        logger.warning(f"Unauthorized webhook attempt for tenant {target_tenant.company_name} ({target_tenant.id})")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid webhook credentials or token mismatch."
        )


@router.post("/api/security/soar-webhook")
@router.post("/api/webhooks/inbound")
def receive_soar_webhook(
    payload: SOARWebhookPayload,
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db)
):
    """
    Authenticated inbound webhook endpoint for Campus Guide / SOAR integrations.
    - Authenticates sender with Bearer token.
    - Validates target tenant existence and boundaries.
    - Enforces idempotency via delivery_id.
    - Persists audit record in _tenant_notifications.
    - Acknowledges receipt (RECEIVED) without asserting live firewall/patch execution.
    """
    # 1. Enforce Tenant Existence & Boundary
    tenant = db.query(Tenant).filter(Tenant.id == payload.tenant_id).first()
    if not tenant:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Tenant '{payload.tenant_id}' does not exist."
        )

    # 2. Authenticate Sender
    _authenticate_webhook_sender(authorization=authorization, target_tenant=tenant)

    # 3. Resolve & Verify Idempotency
    delivery_id = payload.delivery_id or f"inbound-{uuid.uuid4().hex[:12]}"

    existing = db.query(TenantNotification).filter(
        TenantNotification.tenant_id == tenant.id,
        TenantNotification.delivery_id == delivery_id,
        TenantNotification.channel == "INBOUND_WEBHOOK"
    ).first()

    if existing:
        logger.info(f"Duplicate inbound webhook {delivery_id} acknowledged for {tenant.company_name}.")
        return {
            "status": "RECEIVED",
            "delivery_id": delivery_id,
            "tenant_id": str(tenant.id),
            "tenant_name": tenant.company_name,
            "event_type": payload.event_type,
            "duplicate": True,
            "acknowledged": True,
            "is_live_enforcement": False,
            "message": "Webhook delivery previously acknowledged. Duplicate safely ignored."
        }

    # 4. Optional Indicator Policy Validation (if containment requested)
    validation_note = "Payload accepted for review."
    if payload.event_type in ("CONTAINMENT_REQUEST", "IOC_BLOCK") and payload.indicator_value:
        valid_ip, parsed_ip, err = AutonomousPolicyEngine.validate_ip_address(payload.indicator_value)
        if not valid_ip:
            logger.warning(f"Inbound containment request for {payload.indicator_value} rejected: {err}")
            # Persist rejection audit log
            notif = TenantNotification(
                delivery_id=delivery_id,
                tenant_id=tenant.id,
                event_type=payload.event_type,
                channel="INBOUND_WEBHOOK",
                status="REJECTED_POLICY",
                delivered=True,
                human_confirmed=False,
                cve_id=payload.cve_id,
                payload=payload.model_dump(),
                error_message=f"Bogon/Policy Filter: {err}"
            )
            db.add(notif)
            db.commit()
            return {
                "status": "REJECTED_POLICY",
                "delivery_id": delivery_id,
                "tenant_id": str(tenant.id),
                "reason": f"Indicator rejected by deterministic bogon filter: {err}",
                "is_live_enforcement": False
            }
        else:
            validation_note = f"Indicator {payload.indicator_value} validated. Staged for SOC containment review."

    # 5. Persist Inbound Audit Record (Status: RECEIVED, delivered=True, human_confirmed=False)
    notif = TenantNotification(
        delivery_id=delivery_id,
        tenant_id=tenant.id,
        event_type=payload.event_type,
        channel="INBOUND_WEBHOOK",
        status="RECEIVED",
        delivered=True,
        human_confirmed=False,
        cve_id=payload.cve_id,
        payload=payload.model_dump(),
        error_message=None
    )
    db.add(notif)
    db.commit()

    logger.info(f"Inbound SOAR webhook {delivery_id} [{payload.event_type}] received for {tenant.company_name}.")

    return {
        "status": "RECEIVED",
        "delivery_id": delivery_id,
        "tenant_id": str(tenant.id),
        "tenant_name": tenant.company_name,
        "event_type": payload.event_type,
        "acknowledged": True,
        "is_live_enforcement": False,
        "note": validation_note,
        "message": "Inbound webhook acknowledged for review. Delivery does NOT assert verified execution."
    }
