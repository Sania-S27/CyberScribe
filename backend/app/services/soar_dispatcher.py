# backend/app/services/soar_dispatcher.py
import uuid
import logging
from typing import Dict, Any, Optional
import requests
import httpx
from sqlalchemy.orm import Session
from app.models import Tenant, AssetComponent, ContainmentAction
from app.services.containment_policy import AutonomousPolicyEngine

logger = logging.getLogger(__name__)


def dispatch_containment_action_to_tenant(
    action: ContainmentAction,
    tenant: Tenant,
    db: Session,
    delivery_id: Optional[str] = None,
    timeout_seconds: float = 5.0
) -> Dict[str, Any]:
    """
    Delivers a structured ContainmentAction to a tenant webhook receiver with strict tenant isolation.
    
    Status Semantics (Campus Guide contract):
    - DISPATCHED: Webhook request sent to receiver.
    - RECEIVED: Receiver acknowledged receipt with HTTP 200/201.
    - FAILED: Network error, timeout, or HTTP 4xx/5xx.
    
    SAFETY CONSTRAINTS:
    - An HTTP 200 response confirms delivery receipt for review. It does NOT prove
      that a live firewall rule was applied or verified. Action status becomes RECEIVED,
      NEVER APPLIED or VERIFIED.
    - Automated containment delivery must NEVER mark the underlying vulnerability RESOLVED.
    - Secrets (auth tokens, passwords, private keys) are strictly stripped from audit records.
    """
    # 1. Enforce strict tenant isolation
    if action.tenant_id != tenant.id:
        raise PermissionError(
            f"Tenant isolation violation: Action '{action.action_id}' belongs to tenant '{action.tenant_id}', not '{tenant.id}'."
        )

    # 2. Idempotency check: if already RECEIVED, return current state without re-dispatching
    if action.status == "RECEIVED":
        return {
            "status": "RECEIVED",
            "action_id": action.action_id,
            "tenant_id": tenant.id,
            "tenant_name": tenant.company_name,
            "message": f"Action {action.action_id} already received by {tenant.company_name}."
        }

    if not tenant.webhook_url:
        previous_status = action.status
        action.status = "FAILED"
        action.error_message = f"Tenant {tenant.company_name} has no configured webhook_url"
        AutonomousPolicyEngine._record_audit_log(
            db=db,
            tenant_id=tenant.id,
            action_id=action.id,
            event_type="SOAR_DISPATCH_FAILED",
            actor="SOAR_DISPATCHER",
            previous_status=previous_status,
            new_status="FAILED",
            details={"error": action.error_message}
        )
        db.commit()
        return {
            "status": "FAILED",
            "action_id": action.action_id,
            "tenant_id": tenant.id,
            "reason": action.error_message
        }

    actual_delivery_id = delivery_id or f"soar-act-{uuid.uuid4().hex[:12]}"
    previous_status = action.status

    # 3. Transition to DISPATCHED
    action.status = "DISPATCHED"
    AutonomousPolicyEngine._record_audit_log(
        db=db,
        tenant_id=tenant.id,
        action_id=action.id,
        event_type="SOAR_DISPATCHED",
        actor="SOAR_DISPATCHER",
        previous_status=previous_status,
        new_status="DISPATCHED",
        details={
            "delivery_id": actual_delivery_id,
            "target_indicator": action.indicator_value,
            "webhook_url": tenant.webhook_url,
            "action_type": action.action_type
        }
    )
    db.commit()

    token = getattr(tenant, "auth_token", None) or ""
    auth_header = token if token.startswith("Bearer ") else f"Bearer {token}" if token else ""
    headers = {
        "Content-Type": "application/json",
        "Authorization": auth_header
    }

    rule_spec = action.rule_spec or {}
    firewall_cmd = rule_spec.get("rule_name") or f"Block inbound TCP port {rule_spec.get('local_port', 8000)} from {action.indicator_value}"

    playbook_obj = {
        "playbook_name": f"Containment Action {action.action_id} ({action.action_type})",
        "recommended_action": f"Containment policy enforced: {action.action_type} on {action.indicator_value}",
        "firewall_rules": [f"iptables -A INPUT -s {action.indicator_value} -j DROP"] if action.indicator_value else [f"Rule: {firewall_cmd}"],
        "iocs": {action.indicator_type or "ip_addresses": [action.indicator_value]} if action.indicator_value else {"target": [action.action_id]},
        "sigma_rule": f"title: Containment Action {action.action_id}\nstatus: active",
        "patch_guidance": "Review incident and perform upstream vulnerability remediation."
    }

    payload = {
        "delivery_id": actual_delivery_id,
        "action_id": action.action_id,
        "tenant_id": str(tenant.id),
        "tenant_name": tenant.company_name,
        "playbook": playbook_obj,
        "iocs": playbook_obj["iocs"],
        "indicator_value": action.indicator_value,
        "indicator_type": action.indicator_type,
        "action_type": action.action_type,
        "policy_decision": action.policy_decision,
        "rule_spec": rule_spec
    }

    max_retries = 2
    attempt = 0
    is_success = False
    last_resp = None
    last_err = ""

    while attempt <= max_retries:
        attempt += 1
        try:
            response = requests.post(
                tenant.webhook_url,
                headers=headers,
                json=payload,
                timeout=timeout_seconds
            )
            last_resp = response
            if response.status_code in [200, 201]:
                is_success = True
                break
            elif response.status_code < 500:
                # 4xx client errors are non-retryable
                last_err = f"Webhook receiver returned HTTP {response.status_code}: {response.text[:200]}"
                break
            else:
                # 5xx server errors retryable
                last_err = f"Webhook receiver returned HTTP {response.status_code}: {response.text[:200]}"
        except requests.Timeout as te:
            last_err = f"SOAR dispatch connection timed out after {timeout_seconds}s: {te}"
        except Exception as err:
            last_err = f"SOAR dispatch network failure: {str(err)}"

    if is_success and last_resp:
        action.status = "RECEIVED"
        action.execution_output = (
            f"[SOAR DELIVERY] Tenant {tenant.company_name} acknowledged receipt with HTTP {last_resp.status_code} "
            f"(delivery_id: {actual_delivery_id}). Enforcement NOT confirmed."
        )
        AutonomousPolicyEngine._record_audit_log(
            db=db,
            tenant_id=tenant.id,
            action_id=action.id,
            event_type="SOAR_RECEIVED",
            actor="SOAR_DISPATCHER",
            previous_status="DISPATCHED",
            new_status="RECEIVED",
            details={
                "delivery_id": actual_delivery_id,
                "status_code": last_resp.status_code,
                "target_indicator": action.indicator_value,
                "enforcement_confirmed": False,
                "note": "Payload received by tenant for review. Does NOT assert live firewall changes."
            }
        )
        db.commit()

        return {
            "status": "RECEIVED",
            "action_id": action.action_id,
            "tenant_id": tenant.id,
            "tenant_name": tenant.company_name,
            "delivery_id": actual_delivery_id,
            "status_code": last_resp.status_code,
            "is_live_enforcement": False,
            "message": f"Containment action delivered to {tenant.company_name}. Acknowledged for review."
        }
    else:
        action.status = "FAILED"
        action.error_message = last_err or "SOAR dispatch failed after bounded retries"
        AutonomousPolicyEngine._record_audit_log(
            db=db,
            tenant_id=tenant.id,
            action_id=action.id,
            event_type="SOAR_DISPATCH_FAILED",
            actor="SOAR_DISPATCHER",
            previous_status="DISPATCHED",
            new_status="FAILED",
            details={
                "delivery_id": actual_delivery_id,
                "status_code": last_resp.status_code if last_resp else None,
                "error": action.error_message
            }
        )
        db.commit()
        return {
            "status": "FAILED",
            "action_id": action.action_id,
            "tenant_id": tenant.id,
            "reason": action.error_message
        }


async def match_and_dispatch_soar(threat_data: Dict[str, Any], db: Session):
    affected_software = threat_data.get("affected_software", [])
    if not affected_software:
        return {"status": "no_targets_found"}

    tenants = db.query(Tenant).all()
    dispatched_logs = []

    async with httpx.AsyncClient(timeout=8.0) as client:
        for tenant in tenants:
            assets = db.query(AssetComponent).filter(AssetComponent.tenant_id == tenant.id).all()
            matched = [
                a.software_name for a in assets 
                if any(target.lower() in a.software_name.lower() for target in affected_software)
            ]

            # If tenant runs affected software and has a webhook configured
            if matched and tenant.webhook_url:
                iocs = threat_data.get("iocs", {})
                ip_list = iocs.get("ip_addresses", ["127.0.0.1"]) if isinstance(iocs, dict) else ["127.0.0.1"]
                
                playbook = {
                    "playbook_id": f"SOAR-AUTO-{threat_data.get('cve_id', 'VULN')}",
                    "playbook_name": f"SOAR Auto Containment for {threat_data.get('cve_id', 'VULN')}",
                    "recommended_action": f"Automated quarantine for {threat_data.get('cve_id', 'VULN')} affecting {', '.join(matched)}",
                    "action_type": "AUTOMATED_CONTAINMENT",
                    "threat_level": threat_data.get("severity", "HIGH"),
                    "matched_assets": matched,
                    "firewall_rules": [f"iptables -A INPUT -s {ip} -j DROP" for ip in ip_list],
                    "iocs": iocs if isinstance(iocs, dict) else {"ip_addresses": ip_list},
                    "sigma_rule": f"title: Auto Detection for {threat_data.get('cve_id', 'VULN')}\nstatus: active",
                    "patch_guidance": f"Review and upgrade affected components: {', '.join(matched)}"
                }

                token = getattr(tenant, "auth_token", None) or ""
                auth_header = token if token.startswith("Bearer ") else f"Bearer {token}" if token else ""
                
                headers = {
                    "Content-Type": "application/json",
                    "Authorization": auth_header
                }

                payload = {
                    "tenant_id": str(tenant.id),
                    "tenant_name": tenant.company_name,
                    "playbook": playbook,
                    "iocs": iocs if isinstance(iocs, dict) else {"ip_addresses": ip_list}
                }

                try:
                    res = await client.post(tenant.webhook_url, json=payload, headers=headers)
                    dispatched_logs.append({
                        "tenant": tenant.company_name,
                        "status": res.status_code,
                        "delivery_status": "RECEIVED" if res.status_code in [200, 201] else "FAILED",
                        "rules_applied": playbook["firewall_rules"]
                    })
                except Exception as e:
                    logger.error(f"Failed delivery to {tenant.company_name}: {str(e)}")

    return dispatched_logs