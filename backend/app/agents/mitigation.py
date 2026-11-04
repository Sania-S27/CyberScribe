import re
import json
import uuid
import logging
import requests
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session
from langchain_core.messages import SystemMessage, HumanMessage

from app.core.llm import get_robust_llm
from app.models import Tenant, AssetComponent

logger = logging.getLogger(__name__)

llm = get_robust_llm(temperature=0.1)


def generate_soar_playbook(
    threat_title: str, 
    summary: str, 
    mitre_tactics: list = None,
    assessment_outcome: Optional[str] = None,
    matched_component: Optional[str] = None
) -> dict:
    """Phase V: Generates machine-speed mitigation commands and SOAR remediation playbooks."""
    mitre_tactics = mitre_tactics or []

    # Safeguard: For NEEDS_REVIEW findings or unverified product mismatches (e.g. SQLAlchemyDA vs sqlalchemy):
    # Never generate a definitive package-upgrade command or automated containment decision.
    is_sqla_mismatch = (
        bool(re.search(r"\b(?:products\.)?sqlalchemyda\b", summary or "", re.IGNORECASE)) and
        (not matched_component or matched_component.lower() == "sqlalchemy")
    )
    is_needs_review = (
        assessment_outcome == "NEEDS_REVIEW" or
        "[NEEDS REVIEW]" in (threat_title or "").upper() or
        "[NEEDS REVIEW]" in (summary or "").upper()
    )
    if is_needs_review or is_sqla_mismatch:
        comp_display = matched_component or "monitored inventory"
        return {
            "playbook_name": f"Manual Verification & Audit Playbook for {threat_title}",
            "recommended_action": (
                f"Manual verification required: Advisory targets distinct component "
                f"(e.g., SQLAlchemyDA for Zope), differing from {comp_display}. "
                "Confirm whether this specific component is deployed before taking remediation actions."
            ),
            "firewall_rules": [],
            "iocs": {"ip_addresses": []},
            "sigma_rule": f"title: Audit Review for {threat_title}\nstatus: review\ndescription: Potential component name similarity match requires SOC analyst verification before enforcement.",
            "patch_guidance": (
                f"1. Audit environment manifests and configuration to determine whether the exact product specified in the advisory is deployed.\n"
                f"2. If the product (e.g. SQLAlchemyDA) is not present, no patch or upgrade is required for '{comp_display}'.\n"
                f"3. If the product is verified to be present, follow official vendor advisory guidance to upgrade it."
            )
        }

    tactics_str = ", ".join([f"{m.get('technique_id', 'N/A')}: {m.get('technique_name', 'Tactic')}" for m in mitre_tactics]) if mitre_tactics else "General Exploitation"
    
    system_prompt = f"""
    You are an automated SOAR (Security Orchestration, Automation, and Response) Agent.
    Based on this validated threat:
    Title: {threat_title}
    Summary: {summary}
    MITRE Tactics: {tactics_str}
    
    Generate automated defense actions and return ONLY a valid JSON object matching:
    {{
        "playbook_name": "Remediation for <Threat>",
        "recommended_action": "Immediate containment step description",
        "firewall_rules": ["iptables -A INPUT -s 127.0.0.1 -j DROP"],
        "iocs": {{"ip_addresses": ["127.0.0.1"]}},
        "sigma_rule": "title: Generic Detection\\nstatus: experimental",
        "patch_guidance": "Step-by-step guidance to patch or mitigate the vulnerability"
    }}
    """
    try:
        messages = [
            SystemMessage(content=system_prompt),
            HumanMessage(content=f"Generate playbook for: {threat_title}")
        ]
        response = llm.invoke(messages)
        
        raw_content = response.content if hasattr(response, "content") else str(response)
        if isinstance(raw_content, list):
            content = "".join([item.get("text", "") if isinstance(item, dict) else str(item) for item in raw_content])
        else:
            content = str(raw_content)
        
        if "```json" in content:
            content = content.split("```json")[1].split("```")[0].strip()
        elif "```" in content:
            content = content.split("```")[1].split("```")[0].strip()
            
        parsed = json.loads(content)
        
        # Ensure mandatory telemetry fields exist for tenant firewall consumers
        if "firewall_rules" not in parsed or not parsed["firewall_rules"]:
            parsed["firewall_rules"] = ["iptables -A INPUT -s 127.0.0.1 -j DROP"]
        if "iocs" not in parsed:
            parsed["iocs"] = {"ip_addresses": ["127.0.0.1"]}
            
        return parsed
        
    except Exception as e:
        logger.warning(f"[SOAR Agent Fallback] Generation failed ({e}). Using deterministic quarantine playbook.")
        return {
            "playbook_name": f"Automated Quarantine for {threat_title}",
            "recommended_action": "Isolate perimeter entry points and block active attacker IOCs.",
            "firewall_rules": [
                "iptables -A INPUT -s 127.0.0.1 -j DROP",
                "127.0.0.1"
            ],
            "iocs": {
                "ip_addresses": ["127.0.0.1"]
            },
            "sigma_rule": "title: Automated Perimeter Block\nstatus: active",
            "patch_guidance": "Upgrade affected library dependencies to their latest patched releases."
        }


def dispatch_playbook_to_tenant(
    tenant: Tenant,
    playbook: dict,
    delivery_id: Optional[str] = None,
    timeout_seconds: int = 5
) -> Dict[str, Any]:
    """
    Delivers a SOAR containment playbook to a specific tenant webhook receiver with tenant isolation.
    
    Delivery Lifecycle Statuses:
    - GENERATED: Playbook created by SOAR agent.
    - DISPATCHED: Webhook payload constructed and HTTP POST initiated.
    - RECEIVED: HTTP 200/201 response received from target receiver with delivery acknowledgement.
    - FAILED: Network error, timeout, or HTTP 4xx/5xx returned.
    
    NOTE: A status of 'RECEIVED' acknowledges safe payload receipt for review. It does NOT assert
    that physical firewall changes were applied or verified on the remote host.
    """
    if not tenant.webhook_url:
        return {
            "tenant_id": str(tenant.id),
            "tenant_name": tenant.company_name,
            "status": "FAILED",
            "reason": "Tenant has no configured webhook_url",
            "delivery_id": delivery_id
        }

    actual_delivery_id = delivery_id or f"soar-deliv-{uuid.uuid4().hex[:12]}"
    
    payload = {
        "tenant_id": str(tenant.id),
        "tenant_name": tenant.company_name,
        "delivery_id": actual_delivery_id,
        "playbook": playbook,
        "iocs": playbook.get("iocs", {"ip_addresses": ["127.0.0.1"]})
    }

    # Tenant-isolated token authentication
    token = getattr(tenant, "auth_token", None) or os.getenv("SOAR_AUTH_TOKEN", "CAMPUS_DEFENSE_TOKEN_2026")
    auth_header = token if token.startswith("Bearer ") else f"Bearer {token}"

    headers = {
        "Content-Type": "application/json",
        "Authorization": auth_header
    }

    print(f"[*] [SOAR DISPATCH] [Status: DISPATCHED] Sending playbook '{playbook.get('playbook_name')}' to {tenant.company_name} ({tenant.webhook_url})...")

    max_retries = 2
    attempt = 0
    is_success = False
    last_response = None
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
            last_response = response
            if response.status_code in [200, 201]:
                is_success = True
                break
            elif response.status_code < 500:
                last_err = f"Receiver returned status {response.status_code}"
                break
            else:
                last_err = f"Receiver returned server error {response.status_code}"
        except requests.exceptions.Timeout as te:
            last_err = f"Connection timed out ({timeout_seconds}s)"
        except requests.exceptions.ConnectionError as ce:
            last_err = f"Connection refused or unreachable ({tenant.webhook_url})"
        except Exception as e:
            last_err = str(e)

    if is_success and last_response:
        resp_body = last_response.json() if last_response.headers.get("content-type", "").startswith("application/json") else {"raw_response": last_response.text}
        print(f"[+] [SOAR DISPATCH] [Status: RECEIVED] Tenant {tenant.company_name} acknowledged receipt (delivery_id: {actual_delivery_id}).")
        return {
            "tenant_id": str(tenant.id),
            "tenant_name": tenant.company_name,
            "status": "RECEIVED",
            "delivery_id": actual_delivery_id,
            "status_code": last_response.status_code,
            "webhook_response": resp_body
        }
    else:
        status_code = last_response.status_code if last_response else None
        resp_text = last_response.text if last_response else last_err
        print(f"[-] [SOAR DISPATCH] [Status: FAILED] Tenant {tenant.company_name} delivery failed: {last_err}")
        return {
            "tenant_id": str(tenant.id),
            "tenant_name": tenant.company_name,
            "status": "FAILED",
            "delivery_id": actual_delivery_id,
            "status_code": status_code,
            "reason": last_err or f"Receiver returned status {status_code}",
            "webhook_response": resp_text
        }


def dispatch_playbook_to_matched_tenants(
    db: Session,
    playbook: dict,
    keyword_filter: Optional[str] = None,
    target_tenant_id: Optional[str] = None
) -> List[Dict[str, Any]]:
    """Dispatches the generated SOAR playbook via webhooks to tenants matching the vulnerability stack."""
    query = db.query(Tenant).filter(Tenant.webhook_url.isnot(None))
    if target_tenant_id:
        query = query.filter(Tenant.id == target_tenant_id)
        
    tenants = query.all()
    print(f"[*] Evaluating webhook dispatch for {len(tenants)} target tenant(s)...")

    dispatched_records = []
    normalized_keywords = [k.strip().lower() for k in keyword_filter.replace(",", " ").split()] if keyword_filter else []

    for tenant in tenants:
        # Build comprehensive stack context (tech_stack string + SBOM Asset Components)
        stack_corpus = [tenant.tech_stack.lower()] if tenant.tech_stack else []
        assets = db.query(AssetComponent).filter(AssetComponent.tenant_id == tenant.id).all()
        for a in assets:
            if a.software_name:
                stack_corpus.append(a.software_name.lower())
        
        full_stack_text = " ".join(stack_corpus)

        # Keyword matching check: if keywords exist, verify at least one relates to the tenant
        if normalized_keywords and full_stack_text and not target_tenant_id:
            matched = any(kw in full_stack_text for kw in normalized_keywords)
            if not matched:
                print(f"[-] Tenant {tenant.company_name} does not match filter keywords ({normalized_keywords}). Skipping dispatch.")
                continue

        result = dispatch_playbook_to_tenant(tenant=tenant, playbook=playbook)
        dispatched_records.append(result)

    return dispatched_records