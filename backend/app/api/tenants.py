# backend/app/api/tenants.py
import json
import re
import logging
from fastapi import APIRouter, Depends, HTTPException, status, UploadFile, File
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Optional, List

logger = logging.getLogger("TenantsAPI")

from app.core.database import get_db
from app import models
from app.api.auth import get_current_user
from app.api.deps import require_super_admin
from sqlalchemy import or_, and_, not_, func

router = APIRouter(prefix="/tenants", tags=["Tenants"])


class TechStackUpdateRequest(BaseModel):
    tech_stack: Optional[str] = ""
    webhook_url: Optional[str] = None
    auth_token: Optional[str] = None
    remediation_policy: Optional[str] = None


def resolve_tenant_record(current_user: models.User, db: Session) -> models.Tenant:
    """Helper to reliably find the tenant with strict tenant isolation."""
    tenant = None
    # 1. Try finding by user.tenant_id
    if hasattr(current_user, "tenant_id") and current_user.tenant_id is not None:
        tenant = db.query(models.Tenant).filter(models.Tenant.id == current_user.tenant_id).first()
    
    # 2. Try finding where tenant.id == current_user.id
    if not tenant and hasattr(current_user, "id"):
        tenant = db.query(models.Tenant).filter(models.Tenant.id == current_user.id).first()
        
    # 3. Fallback only for super_admin platform operations
    if not tenant and getattr(current_user, "role", "") == "super_admin":
        tenant = db.query(models.Tenant).first()
        
    if not tenant:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, 
            detail="No matching tenant organization record found in database."
        )
    return tenant


@router.get("/profile")
def get_tenant_profile(
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    tenant = resolve_tenant_record(current_user, db)
    
    assets = db.query(models.AssetComponent).filter(models.AssetComponent.tenant_id == tenant.id).all()
    
    return {
        "company_name": tenant.company_name or "Enterprise Tenant",
        "tech_stack": tenant.tech_stack or "",
        "webhook_url": tenant.webhook_url or "",
        "auth_token": tenant.auth_token or "",
        "remediation_policy": getattr(tenant, "remediation_policy", "NOTIFY") or "NOTIFY",
        "assets": [
            {
                "id": a.id,
                "software_name": a.software_name,
                "software_version": a.software_version,
                "environment": a.environment,
                "created_at": str(a.created_at) if hasattr(a, "created_at") else ""
            } for a in assets
        ]
    }


@router.put("/tech-stack")
def update_tenant_tech_stack(
    payload: TechStackUpdateRequest,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    tenant = resolve_tenant_record(current_user, db)

    try:
        if payload.tech_stack is not None:
            tenant.tech_stack = payload.tech_stack.strip()
            
        if payload.webhook_url is not None:
            tenant.webhook_url = payload.webhook_url.strip()
            
        if payload.auth_token is not None:
            tenant.auth_token = payload.auth_token.strip()

        if payload.remediation_policy is not None:
            policy_val = payload.remediation_policy.strip().upper()
            if policy_val in ["NOTIFY", "AUTO_PATCH"]:
                tenant.remediation_policy = policy_val

        db.add(tenant)
        db.commit()
        db.refresh(tenant)

        return {
            "status": "success",
            "message": "Profile, remediation policy, and SOAR webhook settings updated successfully.",
            "data": {
                "company_name": tenant.company_name,
                "tech_stack": tenant.tech_stack or "",
                "webhook_url": tenant.webhook_url or "",
                "auth_token": tenant.auth_token or "",
                "remediation_policy": getattr(tenant, "remediation_policy", "NOTIFY") or "NOTIFY"
            }
        }
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, 
            detail=f"Failed to persist tenant changes: {str(e)}"
        )


@router.post("/upload-manifest")
async def upload_manifest(
    file: UploadFile = File(...),
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    tenant = resolve_tenant_record(current_user, db)

    content = await file.read()
    text_data = content.decode("utf-8", errors="ignore")
    filename = file.filename.lower()
    parsed_components = []

    try:
        if "requirements.txt" in filename:
            for line in text_data.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                match = re.match(r"^([a-zA-Z0-9\-_.]+)(?:[=<>!~]+(.+))?", line)
                if match:
                    name = match.group(1)
                    ver = match.group(2) or "latest"
                    parsed_components.append((name, ver))

        elif "package.json" in filename or "composer.json" in filename:
            data = json.loads(text_data)
            deps = data.get("dependencies", {})
            for name, ver in deps.items():
                clean_ver = re.sub(r"[\^~]", "", ver)
                parsed_components.append((name, clean_ver))
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, 
                detail="Unsupported manifest format. Upload requirements.txt or package.json"
            )

        for name, ver in parsed_components:
            existing = db.query(models.AssetComponent).filter(
                models.AssetComponent.tenant_id == tenant.id,
                models.AssetComponent.software_name == name
            ).first()
            
            if existing:
                existing.software_version = ver
            else:
                new_asset = models.AssetComponent(
                    tenant_id=tenant.id,
                    software_name=name,
                    software_version=ver,
                    environment="production"
                )
                db.add(new_asset)

        db.commit()
        return {
            "status": "success", 
            "message": f"Successfully parsed and ingested {len(parsed_components)} assets from {file.filename}"
        }
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, 
            detail=f"Failed to parse manifest: {str(e)}"
        )


from app.services.firewall_adapter import SimulatedFirewallAdapter, InvalidStateTransitionError, get_containment_adapter

@router.get("/containment/actions")
def get_tenant_containment_actions(
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Returns tenant-isolated simulated containment actions."""
    tenant = resolve_tenant_record(current_user, db)
    actions = db.query(models.ContainmentAction).filter(
        models.ContainmentAction.tenant_id == tenant.id
    ).order_by(models.ContainmentAction.created_at.desc()).all()

    formatted = []
    for a in actions:
        rule_spec = a.rule_spec or {}
        is_sim = True
        act_id = (a.action_id or "").lower()
        out_text = a.execution_output or ""
        
        if rule_spec.get("is_simulated") is False:
            is_sim = False
        elif out_text.startswith("[SIMULATED]") or a.status == "SIMULATED":
            is_sim = True
        elif "Windows Defender Firewall" in out_text and not out_text.startswith("[SIMULATED]"):
            is_sim = False

        executor_type = "SIMULATED_ADAPTER"
        if "FEDORA" in str(rule_spec).upper() or act_id.startswith("act-fed"):
            executor_type = "FEDORA_NFTABLES"
        elif "WINDOWS" in str(rule_spec).upper() or act_id.startswith("act-win") or "Windows Defender" in out_text:
            executor_type = "WINDOWS_DEFENDER_FIREWALL"

        formatted.append({
            "id": a.id,
            "action_id": a.action_id,
            "tenant_id": a.tenant_id,
            "indicator_value": a.indicator_value,
            "indicator_type": a.indicator_type,
            "action_type": a.action_type,
            "policy_decision": a.policy_decision,
            "policy_rule": a.policy_rule,
            "status": a.status,
            "is_simulated": is_sim,
            "adapter_mode": "SIMULATED / DRY_RUN" if is_sim else "LIVE_HOST_ENFORCEMENT",
            "executor_type": executor_type,
            "ttl_seconds": a.ttl_seconds,
            "applied_at": str(a.applied_at) if a.applied_at else None,
            "expires_at": str(a.expires_at) if a.expires_at else None,
            "verified_at": str(a.verified_at) if a.verified_at else None,
            "rolled_back_at": str(a.rolled_back_at) if a.rolled_back_at else None,
            "execution_output": a.execution_output,
            "created_at": str(a.created_at) if a.created_at else None
        })

    return {
        "tenant_id": tenant.id,
        "actions": formatted,
        "total": len(formatted),
        "mode": "HYBRID_SUPPORTED"
    }


@router.get("/containment/actions/{action_id}")
def get_tenant_containment_action_by_id(
    action_id: str,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Returns a specific containment action strictly enforcing tenant isolation."""
    tenant = resolve_tenant_record(current_user, db)
    action = db.query(models.ContainmentAction).filter(
        (models.ContainmentAction.action_id == action_id) | (models.ContainmentAction.id == action_id)
    ).first()

    if not action or action.tenant_id != tenant.id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Containment action '{action_id}' not found."
        )

    rule_spec = action.rule_spec or {}
    is_sim = True
    act_id = (action.action_id or "").lower()
    out_text = action.execution_output or ""
    if rule_spec.get("is_simulated") is False:
        is_sim = False
    elif out_text.startswith("[SIMULATED]") or action.status == "SIMULATED":
        is_sim = True
    elif "Windows Defender Firewall" in out_text and not out_text.startswith("[SIMULATED]"):
        is_sim = False

    executor_type = "SIMULATED_ADAPTER"
    if "FEDORA" in str(rule_spec).upper() or act_id.startswith("act-fed"):
        executor_type = "FEDORA_NFTABLES"
    elif "WINDOWS" in str(rule_spec).upper() or act_id.startswith("act-win") or "Windows Defender" in out_text:
        executor_type = "WINDOWS_DEFENDER_FIREWALL"

    return {
        "id": action.id,
        "action_id": action.action_id,
        "tenant_id": action.tenant_id,
        "indicator_value": action.indicator_value,
        "indicator_type": action.indicator_type,
        "action_type": action.action_type,
        "policy_decision": action.policy_decision,
        "policy_rule": action.policy_rule,
        "status": action.status,
        "is_simulated": is_sim,
        "adapter_mode": "SIMULATED / DRY_RUN" if is_sim else "LIVE_HOST_ENFORCEMENT",
        "executor_type": executor_type,
        "ttl_seconds": action.ttl_seconds,
        "applied_at": str(action.applied_at) if action.applied_at else None,
        "expires_at": str(action.expires_at) if action.expires_at else None,
        "verified_at": str(action.verified_at) if action.verified_at else None,
        "rolled_back_at": str(action.rolled_back_at) if action.rolled_back_at else None,
        "execution_output": action.execution_output,
        "created_at": str(action.created_at) if action.created_at else None,
        "mode": "HYBRID_SUPPORTED"
    }


@router.post("/containment/actions/{action_id}/rollback")
def rollback_tenant_containment_action(
    action_id: str,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Rolls back a containment action with strict tenant isolation."""
    tenant = resolve_tenant_record(current_user, db)
    action = db.query(models.ContainmentAction).filter(
        (models.ContainmentAction.action_id == action_id) | (models.ContainmentAction.id == action_id)
    ).first()

    if not action or action.tenant_id != tenant.id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Containment action '{action_id}' not found."
        )

    try:
        adapter = get_containment_adapter()
        result = adapter.rollback_containment(
            action=action,
            db=db,
            reason="Tenant manual rollback request",
            actor=f"USER_{current_user.email}",
            expected_tenant_id=tenant.id
        )
        return result
    except InvalidStateTransitionError as ste:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ste))
    except PermissionError as pe:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(pe))


@router.post("/containment/actions/expire")
def expire_tenant_containment_actions(
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Scans and expires all TTL-elapsed actions belonging strictly to the authenticated tenant."""
    tenant = resolve_tenant_record(current_user, db)
    adapter = get_containment_adapter()
    expired_results = adapter.expire_active_containment_actions(
        db=db,
        tenant_id=tenant.id,
        actor=f"USER_{current_user.email}"
    )
    return {
        "tenant_id": tenant.id,
        "expired_count": len(expired_results),
        "results": expired_results
    }


@router.get("/containment/audit-logs")
def get_tenant_containment_audit_logs(
    admin_ctx: dict = Depends(require_super_admin),
    db: Session = Depends(get_db)
):
    """Returns containment audit logs. Restricted exclusively to platform administrators."""
    logs = db.query(models.ContainmentAuditLog).order_by(models.ContainmentAuditLog.created_at.desc()).all()

    tenant_map = {t.id: t.company_name for t in db.query(models.Tenant).all()}
    formatted = []
    for l in logs:
        formatted.append({
            "id": l.id,
            "action_id": l.action_id,
            "tenant_id": l.tenant_id,
            "tenant_name": tenant_map.get(l.tenant_id, "Unknown"),
            "event_type": l.event_type,
            "actor": l.actor,
            "previous_status": l.previous_status,
            "new_status": l.new_status,
            "details": l.details,
            "created_at": str(l.created_at) if l.created_at else None
        })

    return {
        "logs": formatted,
        "total": len(formatted)
    }



@router.get("/reports/summary")
def get_tenant_report_summary(
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Returns an executive threat assessment posture summary for the tenant."""
    tenant = resolve_tenant_record(current_user, db)

    base_tenant_q = db.query(models.ThreatMatch).filter(models.ThreatMatch.tenant_id == tenant.id)
    total_matches = base_tenant_q.count()

    cond_affected = or_(
        models.ThreatMatch.ai_matching_reason.ilike('%[AFFECTED]%'),
        models.ThreatMatch.ai_matching_reason.ilike('%satisfies vulnerable constraint%')
    )
    cond_not_affected = or_(
        models.ThreatMatch.ai_matching_reason.ilike('%[NOT AFFECTED]%'),
        models.ThreatMatch.ai_matching_reason.ilike('%outside vulnerable range%')
    )
    cond_needs_review = and_(
        not_(cond_affected),
        not_(cond_not_affected)
    )

    active_affected = base_tenant_q.filter(
        models.ThreatMatch.status.in_(['OPEN', 'open', 'unmitigated', 'triaged', 'active', 'IN_PROGRESS', 'in_progress']),
        cond_affected
    ).count()
    review_required = base_tenant_q.filter(
        models.ThreatMatch.status.in_(['OPEN', 'open', 'unmitigated', 'triaged', 'active', 'IN_PROGRESS', 'in_progress']),
        cond_needs_review
    ).count()
    resolved = base_tenant_q.filter(
        models.ThreatMatch.status.in_(['RESOLVED', 'resolved', 'patched', 'mitigated'])
    ).count()
    safe_components = base_tenant_q.filter(cond_not_affected).count()
    asset_count = db.query(models.AssetComponent).filter(models.AssetComponent.tenant_id == tenant.id).count()
    containment_actions_count = db.query(models.ContainmentAction).filter(models.ContainmentAction.tenant_id == tenant.id).count()

    # Authoritative severity counts across ALL correlated findings for this tenant
    sev_query = db.query(
        models.ThreatReport.severity,
        func.count(models.ThreatMatch.id)
    ).join(
        models.ThreatReport, models.ThreatMatch.threat_report_id == models.ThreatReport.id
    ).filter(
        models.ThreatMatch.tenant_id == tenant.id
    ).group_by(models.ThreatReport.severity).all()

    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for sev_name, cnt in sev_query:
        s = (sev_name or "medium").lower()
        if s in sev_counts:
            sev_counts[s] += cnt
        else:
            sev_counts["medium"] += cnt

    # Health score
    health_score = 100 if active_affected == 0 else max(10, round(100 - (active_affected / max(active_affected + resolved, 1)) * 50))

    return {
        "company_name": tenant.company_name,
        "tenant_id": tenant.id,
        "health_score": health_score,
        "total_threat_matches": total_matches,
        "active_affected": active_affected,
        "review_required": review_required,
        "resolved_vulnerabilities": resolved,
        "safe_components": safe_components,
        "monitored_assets": asset_count,
        "severity_counts": sev_counts,
        "severity_total": sum(sev_counts.values()),
        "containment_actions_simulated": containment_actions_count,
        "generated_at": str(models.func.now())
    }


# ==============================================================================
# Software Patch Remediation Lifecycle Endpoints
# ==============================================================================
from app.services.patch_adapter import PatchManagementAdapter, PatchSecurityError, PatchStateError

class PatchProposalCreateRequest(BaseModel):
    package_name: str
    current_version: Optional[str] = None
    target_version: Optional[str] = None
    threat_match_id: Optional[str] = None
    asset_component_id: Optional[str] = None
    priority: Optional[str] = "HIGH"
    package_manager: Optional[str] = None

class PatchProposalRejectRequest(BaseModel):
    reason: str

class PatchProposalExecuteRequest(BaseModel):
    mode: Optional[str] = "simulated"


@router.get("/remediation/proposals")
def get_tenant_remediation_proposals(
    status: Optional[str] = None,
    page: int = 1,
    page_size: int = 20,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Lists software patch remediation proposals with strict tenant isolation."""
    tenant = resolve_tenant_record(current_user, db)
    query = db.query(models.PatchProposal).filter(models.PatchProposal.tenant_id == tenant.id)
    if status and status.upper() != "ALL":
        query = query.filter(models.PatchProposal.status == status.upper())
    
    total = query.count()
    proposals = query.order_by(models.PatchProposal.created_at.desc()).offset((page - 1) * page_size).limit(page_size).all()
    
    return {
        "tenant_id": tenant.id,
        "total": total,
        "page": page,
        "page_size": page_size,
        "proposals": [
            {
                "id": p.id,
                "proposal_id": p.proposal_id,
                "package_name": p.package_name,
                "current_version": p.current_version,
                "target_version": p.target_version,
                "package_manager": p.package_manager,
                "priority": p.priority,
                "status": p.status,
                "is_simulated": p.is_simulated,
                "command": p.command_spec.get("command") if p.command_spec else None,
                "approved_by": p.approved_by,
                "approved_at": str(p.approved_at) if p.approved_at else None,
                "applied_at": str(p.applied_at) if p.applied_at else None,
                "verified_at": str(p.verified_at) if p.verified_at else None,
                "execution_output": p.execution_output,
                "verification_output": p.verification_output,
                "error_message": p.error_message,
                "created_at": str(p.created_at) if p.created_at else None
            }
            for p in proposals
        ]
    }


@router.post("/remediation/proposals", status_code=status.HTTP_201_CREATED)
def create_remediation_proposal(
    req: PatchProposalCreateRequest,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Creates a new patch proposal for a vulnerable software component."""
    tenant = resolve_tenant_record(current_user, db)
    try:
        proposal = PatchManagementAdapter.create_proposal(
            db=db,
            tenant_id=tenant.id,
            package_name=req.package_name,
            current_version=req.current_version,
            target_version=req.target_version,
            threat_match_id=req.threat_match_id,
            asset_component_id=req.asset_component_id,
            priority=req.priority or "HIGH",
            package_manager=req.package_manager,
            actor=f"USER_{current_user.email}"
        )
        return {
            "status": "CREATED",
            "proposal_id": proposal.proposal_id,
            "package_name": proposal.package_name,
            "status_code": proposal.status
        }
    except PatchSecurityError as se:
        raise HTTPException(status_code=400, detail=str(se))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Proposal creation failed: {e}")


@router.post("/remediation/proposals/{proposal_id}/approve")
def approve_remediation_proposal(
    proposal_id: str,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Authorizes an existing patch proposal for execution."""
    tenant = resolve_tenant_record(current_user, db)
    try:
        p = PatchManagementAdapter.approve_proposal(
            db=db,
            proposal_id=proposal_id,
            approver=f"USER_{current_user.email}",
            tenant_id=tenant.id
        )
        return {
            "status": "APPROVED",
            "proposal_id": p.proposal_id,
            "approved_by": p.approved_by,
            "approved_at": str(p.approved_at)
        }
    except PatchStateError as pse:
        raise HTTPException(status_code=400, detail=str(pse))


@router.post("/remediation/proposals/{proposal_id}/reject")
def reject_remediation_proposal(
    proposal_id: str,
    req: PatchProposalRejectRequest,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Rejects a proposed patch."""
    tenant = resolve_tenant_record(current_user, db)
    try:
        p = PatchManagementAdapter.reject_proposal(
            db=db,
            proposal_id=proposal_id,
            reason=req.reason,
            actor=f"USER_{current_user.email}",
            tenant_id=tenant.id
        )
        return {
            "status": "REJECTED",
            "proposal_id": p.proposal_id
        }
    except PatchStateError as pse:
        raise HTTPException(status_code=400, detail=str(pse))


@router.post("/remediation/proposals/{proposal_id}/execute")
def execute_remediation_proposal(
    proposal_id: str,
    req: PatchProposalExecuteRequest,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Executes a patch proposal in simulated (default) or live mode."""
    tenant = resolve_tenant_record(current_user, db)
    try:
        res = PatchManagementAdapter.execute_patch(
            db=db,
            proposal_id=proposal_id,
            actor=f"USER_{current_user.email}",
            mode=req.mode or "simulated",
            tenant_id=tenant.id
        )
        return res
    except (PatchStateError, PatchSecurityError) as err:
        raise HTTPException(status_code=400, detail=str(err))


@router.get("/remediation/audit-logs")
def get_tenant_remediation_audit_logs(
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Returns patch remediation audit trail with strict tenant isolation."""
    tenant = resolve_tenant_record(current_user, db)
    logs = db.query(models.PatchAuditLog).filter(
        models.PatchAuditLog.tenant_id == tenant.id
    ).order_by(models.PatchAuditLog.created_at.desc()).limit(100).all()

    return {
        "tenant_id": tenant.id,
        "total": len(logs),
        "audit_logs": [
            {
                "id": l.id,
                "proposal_id": l.proposal_id,
                "event_type": l.event_type,
                "actor": l.actor,
                "previous_status": l.previous_status,
                "new_status": l.new_status,
                "details": l.details,
                "created_at": str(l.created_at) if l.created_at else None
            }
            for l in logs
        ]
    }


# ==============================================================================
# End-to-End Autonomous Vulnerability Response & Policy Endpoints
# ==============================================================================
from app.services.autonomous_response_orchestrator import AutonomousResponseOrchestrator
from app.services.fixed_version_service import FixedVersionDiscoveryService

class TenantPolicyUpdateRequest(BaseModel):
    remediation_policy: str  # NOTIFY | AUTO_PATCH

class OrchestrationRequest(BaseModel):
    threat_report_id: str
    supporting_malicious_ip: Optional[str] = None
    force_auto_patch: Optional[bool] = False
    is_simulated: Optional[bool] = None

class ManualRemediationRequest(BaseModel):
    installed_version: str
    notes: Optional[str] = None


@router.put("/policy")
def update_tenant_remediation_policy(
    req: TenantPolicyUpdateRequest,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Updates company remediation policy (NOTIFY vs AUTO_PATCH)."""
    tenant = resolve_tenant_record(current_user, db)
    clean_policy = (req.remediation_policy or "NOTIFY").strip().upper()
    if clean_policy not in ("NOTIFY", "AUTO_PATCH"):
        raise HTTPException(status_code=400, detail="remediation_policy must be 'NOTIFY' or 'AUTO_PATCH'")

    tenant.remediation_policy = clean_policy
    db.commit()

    return {
        "status": "SUCCESS",
        "tenant_id": tenant.id,
        "company_name": tenant.company_name,
        "remediation_policy": tenant.remediation_policy
    }


@router.post("/remediation/orchestrate")
def orchestrate_autonomous_response(
    req: OrchestrationRequest,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Executes the end-to-end autonomous response pipeline:
    SBOM match -> Incident creation -> Company notification ->
    Justified containment (if malicious IP provided) -> Fixed-version discovery ->
    Notification or Auto-patch.
    """
    tenant = resolve_tenant_record(current_user, db)
    try:
        res = AutonomousResponseOrchestrator.correlate_sbom_and_create_incident(
            db=db,
            tenant_id=tenant.id,
            threat_report_id=req.threat_report_id,
            supporting_malicious_ip=req.supporting_malicious_ip,
            force_auto_patch=bool(req.force_auto_patch),
            is_simulated=req.is_simulated
        )
        return res
    except ValueError as ve:
        raise HTTPException(status_code=404, detail=str(ve))
    except Exception as e:
        logger.error(f"Orchestration error: {e}")
        raise HTTPException(status_code=500, detail=f"Orchestration failed: {e}")


@router.post("/remediation/proposals/{proposal_id}/execute-and-release")
def execute_patch_and_release_containment(
    proposal_id: str,
    req: PatchProposalExecuteRequest,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Executes an approved patch, verifies new version against the vulnerability constraint,
    marks threat RESOLVED, and safely releases containment.
    """
    tenant = resolve_tenant_record(current_user, db)
    is_sim = req.mode != "live"
    try:
        res = AutonomousResponseOrchestrator.execute_patch_and_release(
            db=db,
            proposal_id=proposal_id,
            tenant_id=tenant.id,
            is_simulated=is_sim
        )
        return res
    except Exception as e:
        logger.error(f"Execute and release error: {e}")
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/threats/{match_id}/manual-remediation")
def report_manual_remediation(
    match_id: str,
    req: ManualRemediationRequest,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Allows company user to report an independent manual patch.
    Re-verifies version against vulnerability constraints and releases containment if safe.
    """
    tenant = resolve_tenant_record(current_user, db)
    try:
        res = AutonomousResponseOrchestrator.process_manual_remediation(
            db=db,
            threat_match_id=match_id,
            tenant_id=tenant.id,
            new_version=req.installed_version,
            notes=req.notes
        )
        return res
    except ValueError as ve:
        raise HTTPException(status_code=404, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/threats/{match_id}/fix-discovery")
def discover_fixed_version_for_match(
    match_id: str,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Discovers and verifies available fixed version for an active threat incident."""
    tenant = resolve_tenant_record(current_user, db)
    match = db.query(models.ThreatMatch).filter(
        models.ThreatMatch.id == match_id,
        models.ThreatMatch.tenant_id == tenant.id
    ).first()

    if not match:
        raise HTTPException(status_code=404, detail="Threat match not found.")

    asset = match.asset
    report = match.report
    if not asset or not report:
        raise HTTPException(status_code=400, detail="Threat match has missing asset or report relation.")

    res = FixedVersionDiscoveryService.discover_and_verify_fix(
        package_name=asset.software_name,
        current_version=asset.software_version,
        threat_report=report
    )
    return res


@router.get("/notifications")
def get_tenant_notifications(
    page: int = 1,
    page_size: int = 50,
    event_type: Optional[str] = None,
    channel: Optional[str] = None,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Retrieves tenant-isolated notification and alert delivery history."""
    tenant = resolve_tenant_record(current_user, db)
    query = db.query(models.TenantNotification).filter(
        models.TenantNotification.tenant_id == tenant.id
    )
    if event_type:
        query = query.filter(models.TenantNotification.event_type == event_type.strip().upper())
    if channel:
        query = query.filter(models.TenantNotification.channel == channel.strip().upper())

    total = query.count()
    notifications = (
        query.order_by(models.TenantNotification.created_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )

    from app.services.email_notification_service import is_smtp_configured
    smtp_active = is_smtp_configured()

    return {
        "status": "success",
        "total": total,
        "page": page,
        "page_size": page_size,
        "is_smtp_configured": smtp_active,
        "delivery_mode": "LIVE_SMTP" if smtp_active else "SIMULATION",
        "notifications": [
            {
                "id": n.id,
                "delivery_id": n.delivery_id,
                "event_type": n.event_type,
                "channel": getattr(n, "channel", "WEBHOOK") or "WEBHOOK",
                "cve_id": n.cve_id,
                "affected_component": n.affected_component,
                "installed_version": n.installed_version,
                "fixed_version": n.fixed_version,
                "recipient_url": n.recipient_url,
                "status": n.status,
                "status_code": n.status_code,
                "delivered": n.delivered,
                "human_confirmed": n.human_confirmed,
                "payload": n.payload,
                "error_message": n.error_message,
                "created_at": n.created_at.strftime("%Y-%m-%d %H:%M:%S") if n.created_at else ""
            }
            for n in notifications
        ]
    }


@router.post("/notifications/{delivery_id}/ack")
def acknowledge_notification(
    delivery_id: str,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Explicit SOC human sign-off acknowledging a delivered or recorded notification.
    Enforces that webhook/email delivery is distinguished from human receipt.
    """
    tenant = resolve_tenant_record(current_user, db)
    notif = db.query(models.TenantNotification).filter(
        models.TenantNotification.delivery_id == delivery_id,
        models.TenantNotification.tenant_id == tenant.id
    ).first()

    if not notif:
        raise HTTPException(status_code=404, detail="Notification record not found.")

    notif.human_confirmed = True
    db.commit()
    db.refresh(notif)

    return {
        "status": "ACKNOWLEDGED",
        "delivery_id": notif.delivery_id,
        "event_type": notif.event_type,
        "human_confirmed": True,
        "acknowledged_by": current_user.email,
        "message": "Notification successfully confirmed and acknowledged by authorized user."
    }


@router.post("/notifications/{delivery_id}/retry")
def retry_tenant_notification(
    delivery_id: str,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Retries an existing failed notification dispatch for the authenticated tenant.
    Enforces tenant boundaries, bounded backoff, and keeps human_confirmed unchanged.
    """
    tenant = resolve_tenant_record(current_user, db)
    notif = db.query(models.TenantNotification).filter(
        models.TenantNotification.delivery_id == delivery_id,
        models.TenantNotification.tenant_id == tenant.id
    ).first()

    if not notif:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Notification '{delivery_id}' not found for tenant '{tenant.company_name}'."
        )

    from app.services.notification_service import NotificationService
    res = NotificationService.retry_notification(db=db, delivery_id=delivery_id)

    return {
        "status": res["status"],
        "delivery_id": delivery_id,
        "delivered": res.get("delivered", False),
        "status_code": res.get("status_code"),
        "human_confirmed": res.get("human_confirmed", False),
        "error": res.get("error"),
        "message": res.get("message") or ("Notification successfully delivered via retry." if res.get("delivered") else "Notification retry failed.")
    }


class TestEmailRequest(BaseModel):
    target_email: Optional[str] = None


@router.post("/notifications/test-email")
def send_test_email(
    payload: TestEmailRequest = TestEmailRequest(),
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Restricted endpoint: Company users are prohibited from testing global SMTP configuration.
    Global email diagnostics are restricted to platform administrators in the Admin Dashboard.
    """
    if getattr(current_user, "role", None) != "super_admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied. Global email integration testing is restricted to platform administrators in the Admin Dashboard."
        )

    tenant = resolve_tenant_record(current_user, db)
    from app.services.email_notification_service import EmailNotificationService
    try:
        res = EmailNotificationService.send_test_email(
            db=db,
            tenant=tenant,
            requesting_user=current_user,
            target_email=payload.target_email
        )
        return res
    except ValueError as val_err:
        raise HTTPException(status_code=429, detail=str(val_err))
    except Exception as e:
        logger.error(f"Test email dispatch failed: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to dispatch test email: {str(e)}")


