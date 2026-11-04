"""
CyberScribe Windows Executor Daemon
------------------------------------
Standalone, narrowly privileged micro-service for Windows Defender Firewall operations.
Binds strictly to loopback (127.0.0.1:8089) and authenticates all requests via bearer token.

Enables the main CyberScribe FastAPI app to run with standard unprivileged user permissions,
delegating only narrowly scoped firewall changes to this service.
"""

import os
import sys
import logging
from typing import Dict, Any, Optional
from pydantic import BaseModel, Field
from fastapi import FastAPI, Header, HTTPException, status
import uvicorn

backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from app.services.windows_executor import cyberscribe_win_helper as helper

logger = logging.getLogger("WindowsExecutorDaemon")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")

DEFAULT_EXECUTOR_PORT = int(os.getenv("WINDOWS_EXECUTOR_PORT", "8089"))
EXECUTOR_TOKEN = os.getenv("WINDOWS_EXECUTOR_TOKEN", "cyberscribe_win_executor_secret_token_2026")

app = FastAPI(
    title="CyberScribe Windows Firewall Executor Daemon",
    description="Narrowly privileged loopback microservice for Windows Defender Firewall containment."
)


class ApplyRuleRequest(BaseModel):
    action_id: str = Field(..., min_length=3, max_length=64)
    ip_address: str = Field(...)
    port: int = Field(default=8000)
    direction: str = Field(default="in")
    allow_reserved: bool = Field(default=False)


class VerifyRuleRequest(BaseModel):
    action_id: str = Field(..., min_length=3, max_length=64)
    expected_ip: str = Field(...)
    expected_port: Optional[int] = Field(default=8000)
    direction: str = Field(default="in")


class RollbackRuleRequest(BaseModel):
    action_id: str = Field(..., min_length=3, max_length=64)


def verify_auth(x_cyberscribe_executor_token: Optional[str] = Header(None, alias="X-CyberScribe-Executor-Token")):
    if not x_cyberscribe_executor_token or x_cyberscribe_executor_token != EXECUTOR_TOKEN:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized: Invalid or missing X-CyberScribe-Executor-Token."
        )


@app.get("/health")
def health_check():
    return {
        "status": "UP",
        "service": "CyberScribe Windows Executor Daemon",
        "target": "WINDOWS_DEFENDER_FIREWALL",
        "target_port": 8000
    }


@app.post("/apply")
def apply_firewall_rule(req: ApplyRuleRequest, token: Optional[str] = Header(None, alias="X-CyberScribe-Executor-Token")):
    verify_auth(token)
    try:
        res = helper.apply_rule(
            action_id=req.action_id,
            ip_str=req.ip_address,
            port=req.port,
            allow_reserved=req.allow_reserved,
            direction=req.direction
        )
        return res
    except helper.HelperSecurityError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except helper.RuleVerificationError as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Unexpected error: {e}")


@app.post("/verify")
def verify_firewall_rule(req: VerifyRuleRequest, token: Optional[str] = Header(None, alias="X-CyberScribe-Executor-Token")):
    verify_auth(token)
    try:
        verified = helper.verify_rule(
            action_id=req.action_id,
            expected_ip=req.expected_ip,
            expected_port=req.expected_port,
            direction=req.direction
        )
        return {"status": "VERIFIED", "action_id": req.action_id, "verified": verified}
    except helper.RuleVerificationError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except helper.HelperSecurityError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@app.post("/rollback")
def rollback_firewall_rule(req: RollbackRuleRequest, token: Optional[str] = Header(None, alias="X-CyberScribe-Executor-Token")):
    verify_auth(token)
    try:
        res = helper.rollback_rule(action_id=req.action_id)
        return res
    except helper.HelperSecurityError as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


@app.get("/rules")
def list_managed_rules(token: Optional[str] = Header(None, alias="X-CyberScribe-Executor-Token")):
    verify_auth(token)
    return {"rules": helper.list_cyberscribe_rules()}


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=DEFAULT_EXECUTOR_PORT)
