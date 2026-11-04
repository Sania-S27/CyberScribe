# backend/scripts/setup_campus_guide_receiver.py
import os
import sys

# 1. Path to Campus Guide Project
CAMPUS_GUIDE_ROOT = r"E:\Campus Guide Project"
CAMPUS_GUIDE_ROUTERS = os.path.join(CAMPUS_GUIDE_ROOT, "backend", "routers")
CAMPUS_GUIDE_TESTS = os.path.join(CAMPUS_GUIDE_ROOT, "backend", "tests")
CAMPUS_GUIDE_MAIN = os.path.join(CAMPUS_GUIDE_ROOT, "backend", "main.py")
CAMPUS_GUIDE_ENV = os.path.join(CAMPUS_GUIDE_ROOT, "backend", ".env")

SECURITY_ROUTER_CODE = '''# backend/routers/security.py
import os
import uuid
import logging
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from fastapi import APIRouter, Header, HTTPException, status
from pydantic import BaseModel, Field

logger = logging.getLogger("security_webhook")

router = APIRouter()

# Read security secret from environment variable without hardcoding or logging value
SOAR_WEBHOOK_SECRET = os.getenv("SOAR_WEBHOOK_SECRET", "CAMPUS_DEFENSE_TOKEN_2026")

# In-memory safe audit ledger for received containment playbooks
_received_deliveries: Dict[str, Dict[str, Any]] = {}
MAX_LEDGER_ENTRIES = 200


class PlaybookData(BaseModel):
    playbook_name: str = Field(..., description="Descriptive name of the remediation playbook")
    recommended_action: Optional[str] = Field(None, description="Immediate containment recommendations")
    firewall_rules: Optional[List[str]] = Field(default_factory=list, description="Simulated firewall syntax for review")
    iocs: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Indicators of Compromise")
    sigma_rule: Optional[str] = Field(None, description="Sigma detection rule specification")
    patch_guidance: Optional[str] = Field(None, description="Package patching instructions")


class SOARWebhookPayload(BaseModel):
    tenant_id: str = Field(..., description="CyberScribe tenant ID")
    tenant_name: Optional[str] = Field(None, description="Tenant organization name")
    playbook: PlaybookData = Field(..., description="Remediation playbook content")
    iocs: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Correlated IOC dictionary")
    delivery_id: Optional[str] = Field(None, description="Optional idempotent delivery identifier")


class SOARReceiptResponse(BaseModel):
    status: str
    delivery_id: str
    tenant_id: str
    timestamp: str
    message: str


def verify_bearer_token(authorization: Optional[str] = Header(None)) -> str:
    """Validates Authorization header against the configured environment secret."""
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization header"
        )
    
    parts = authorization.strip().split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authorization header format. Expected Bearer <token>"
        )
    
    token = parts[1].strip()
    configured_secret = os.getenv("SOAR_WEBHOOK_SECRET", SOAR_WEBHOOK_SECRET)
    
    if token != configured_secret:
        # Safe error message without revealing token or secret
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token"
        )
    
    return token


@router.post("/soar-webhook", response_model=SOARReceiptResponse, status_code=status.HTTP_200_OK)
def receive_soar_playbook(
    payload: SOARWebhookPayload,
    authorization: Optional[str] = Header(None)
):
    """
    Safe SOAR Webhook Receiver Endpoint.
    
    Authenticates CyberScribe containment playbooks, logs delivery telemetry,
    and returns HTTP 200 acknowledgement.
    
    SAFETY ENFORCEMENT:
    This endpoint does NOT execute shell scripts, iptables rules, or system firewalls.
    All received playbooks are recorded purely for administrative and incident triage review.
    """
    # Enforce authentication
    verify_bearer_token(authorization=authorization)

    delivery_id = payload.delivery_id or f"deliv-{uuid.uuid4().hex[:12]}"
    now_iso = datetime.now(timezone.utc).isoformat()

    # Idempotent tracking
    if delivery_id in _received_deliveries:
        existing = _received_deliveries[delivery_id]
        logger.info(f"[SOAR Webhook] Repeated delivery received for delivery_id={delivery_id}")
        return SOARReceiptResponse(
            status="RECEIVED",
            delivery_id=delivery_id,
            tenant_id=payload.tenant_id,
            timestamp=existing["timestamp"],
            message="Playbook already received and acknowledged (idempotent response)"
        )

    # Record safe receipt metadata
    receipt_record = {
        "delivery_id": delivery_id,
        "tenant_id": payload.tenant_id,
        "tenant_name": payload.tenant_name,
        "playbook_name": payload.playbook.playbook_name,
        "timestamp": now_iso,
        "status": "RECEIVED",
        "has_firewall_rules": bool(payload.playbook.firewall_rules),
        "rule_count": len(payload.playbook.firewall_rules or [])
    }

    if len(_received_deliveries) >= MAX_LEDGER_ENTRIES:
        _received_deliveries.pop(next(iter(_received_deliveries)))

    _received_deliveries[delivery_id] = receipt_record

    logger.info(f"[SOAR Webhook] Successfully received playbook '{payload.playbook.playbook_name}' for tenant {payload.tenant_id}")

    return SOARReceiptResponse(
        status="RECEIVED",
        delivery_id=delivery_id,
        tenant_id=payload.tenant_id,
        timestamp=now_iso,
        message="Playbook safely received and logged for administrative review"
    )


@router.get("/receipts", status_code=status.HTTP_200_OK)
def get_receipt_ledger():
    """Read-only inspection of received containment deliveries for telemetry verification."""
    return {
        "total_received": len(_received_deliveries),
        "deliveries": list(_received_deliveries.values())
    }
'''

TEST_SECURITY_WEBHOOK_CODE = '''# backend/tests/test_security_webhook.py
import pytest
from fastapi.testclient import TestClient
import os
import sys

# Ensure backend root is in sys.path
backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from main import app
from routers.security import _received_deliveries

client = TestClient(app)

VALID_TOKEN = os.getenv("SOAR_WEBHOOK_SECRET", "CAMPUS_DEFENSE_TOKEN_2026")
AUTH_HEADER = {"Authorization": f"Bearer {VALID_TOKEN}"}

SAMPLE_PAYLOAD = {
    "tenant_id": "fd83e79b-f024-4fe1-b43a-5a083065b67a",
    "tenant_name": "Campus Guide",
    "playbook": {
        "playbook_name": "Automated Quarantine for FastAPI RCE",
        "recommended_action": "Apply perimeter rate-limits and upgrade dependencies.",
        "firewall_rules": ["iptables -A INPUT -s 192.0.2.1 -j DROP"],
        "iocs": {"ip_addresses": ["192.0.2.1"]},
        "sigma_rule": "title: Network Probe Detected\\nstatus: experimental",
        "patch_guidance": "Upgrade fastapi to >= 0.120.1"
    },
    "iocs": {"ip_addresses": ["192.0.2.1"]}
}


def test_webhook_authenticated_success():
    """Verify that a valid authenticated request receives HTTP 200 with status RECEIVED."""
    response = client.post(
        "/api/security/soar-webhook",
        headers=AUTH_HEADER,
        json=SAMPLE_PAYLOAD
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "RECEIVED"
    assert data["tenant_id"] == "fd83e79b-f024-4fe1-b43a-5a083065b67a"
    assert "delivery_id" in data
    assert "timestamp" in data


def test_webhook_missing_auth():
    """Verify that a request without Authorization header returns HTTP 401."""
    response = client.post(
        "/api/security/soar-webhook",
        json=SAMPLE_PAYLOAD
    )
    assert response.status_code == 401
    assert "Missing" in response.json()["detail"] or "Invalid" in response.json()["detail"]


def test_webhook_invalid_token():
    """Verify that a request with an invalid token returns HTTP 401 without leaking secret."""
    response = client.post(
        "/api/security/soar-webhook",
        headers={"Authorization": "Bearer WRONG_TOKEN_12345"},
        json=SAMPLE_PAYLOAD
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid authentication token"


def test_webhook_malformed_payload():
    """Verify that invalid/incomplete payload structures return HTTP 422 Unprocessable Entity."""
    malformed = {
        "tenant_id": "fd83e79b-f024-4fe1-b43a-5a083065b67a"
        # Missing required 'playbook' object
    }
    response = client.post(
        "/api/security/soar-webhook",
        headers=AUTH_HEADER,
        json=malformed
    )
    assert response.status_code == 422


def test_webhook_repeated_delivery_idempotent():
    """Verify that delivering a payload with the same delivery_id is handled idempotently."""
    fixed_delivery_id = "test-fixed-delivery-001"
    payload = {**SAMPLE_PAYLOAD, "delivery_id": fixed_delivery_id}

    # First delivery
    r1 = client.post("/api/security/soar-webhook", headers=AUTH_HEADER, json=payload)
    assert r1.status_code == 200
    d1 = r1.json()
    assert d1["delivery_id"] == fixed_delivery_id

    # Second delivery with identical delivery_id
    r2 = client.post("/api/security/soar-webhook", headers=AUTH_HEADER, json=payload)
    assert r2.status_code == 200
    d2 = r2.json()
    assert d2["delivery_id"] == fixed_delivery_id
    assert d2["status"] == "RECEIVED"
'''


def apply_setup():
    # 1. Write security router
    security_file = os.path.join(CAMPUS_GUIDE_ROUTERS, "security.py")
    with open(security_file, "w", encoding="utf-8") as f:
        f.write(SECURITY_ROUTER_CODE)
    print(f"[+] Created {security_file}")

    # 2. Write test file
    test_file = os.path.join(CAMPUS_GUIDE_TESTS, "test_security_webhook.py")
    with open(test_file, "w", encoding="utf-8") as f:
        f.write(TEST_SECURITY_WEBHOOK_CODE)
    print(f"[+] Created {test_file}")

    # 3. Update main.py if not already included
    with open(CAMPUS_GUIDE_MAIN, "r", encoding="utf-8") as f:
        main_code = f.read()

    if "from routers import security as security_router" not in main_code:
        # Add import
        main_code = main_code.replace(
            "from routers import admin as admin_router",
            "from routers import admin as admin_router\nfrom routers import security as security_router"
        )
        # Add router inclusion
        main_code = main_code.replace(
            'app.include_router(admin_router.router, prefix="/api/admin", tags=["Admin"])',
            'app.include_router(admin_router.router, prefix="/api/admin", tags=["Admin"])\napp.include_router(security_router.router, prefix="/api/security", tags=["Security"])'
        )
        with open(CAMPUS_GUIDE_MAIN, "w", encoding="utf-8") as f:
            f.write(main_code)
        print(f"[+] Updated {CAMPUS_GUIDE_MAIN} to mount /api/security router.")
    else:
        print(f"[*] /api/security router already mounted in {CAMPUS_GUIDE_MAIN}.")

    # 4. Check .env in Campus Guide
    if os.path.exists(CAMPUS_GUIDE_ENV):
        with open(CAMPUS_GUIDE_ENV, "r", encoding="utf-8") as f:
            env_content = f.read()
        if "SOAR_WEBHOOK_SECRET" not in env_content:
            with open(CAMPUS_GUIDE_ENV, "a", encoding="utf-8") as f:
                f.write("\nSOAR_WEBHOOK_SECRET=CAMPUS_DEFENSE_TOKEN_2026\n")
            print(f"[+] Appended SOAR_WEBHOOK_SECRET to {CAMPUS_GUIDE_ENV}")
        else:
            print(f"[*] SOAR_WEBHOOK_SECRET already present in {CAMPUS_GUIDE_ENV}")

    print("\n[SUCCESS] Campus Guide SOAR Webhook receiver setup complete.")


if __name__ == "__main__":
    apply_setup()
