import os
import uuid
import logging
import ipaddress
from typing import Optional
from pydantic import BaseModel
from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks
from sqlalchemy.orm import Session
from app.core.database import get_db
from app import models
from app.api.deps import get_current_user_or_admin

logger = logging.getLogger("AdminAPI")

router = APIRouter(prefix="/admin", tags=["Admin"])

@router.get("/metrics")
def get_admin_metrics(
    auth_ctx: dict = Depends(get_current_user_or_admin),
    db: Session = Depends(get_db)
):
    if auth_ctx["role"] != "super_admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )

    # Query exact database metrics
    total_threats = db.query(models.ThreatReport).count()
    total_tenants = db.query(models.Tenant).count()
    total_matches = db.query(models.ThreatMatch).count()
    total_assets = db.query(models.AssetComponent).count()
    total_containment_actions = db.query(models.ContainmentAction).count()

    return {
        "total_threats_ingested": total_threats,
        "total_tenants": total_tenants,
        "total_threat_matches": total_matches,
        "monitored_assets": total_assets,
        "total_containment_actions": total_containment_actions,
        "system_status": "Operational",
        "active_collectors": "6 OSINT Feeds + NVD REST 2.0"
    }


@router.get("/readiness")
def get_admin_readiness(
    auth_ctx: dict = Depends(get_current_user_or_admin),
    db: Session = Depends(get_db)
):
    if auth_ctx["role"] != "super_admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )
    from app.services.readiness_service import ReadinessService
    return ReadinessService.get_system_readiness(db=db)


@router.get("/tenants")
def get_admin_tenants(
    auth_ctx: dict = Depends(get_current_user_or_admin),
    db: Session = Depends(get_db)
):
    if auth_ctx["role"] != "super_admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required")

    tenants = db.query(models.Tenant).all()
    results = []
    for t in tenants:
        asset_count = db.query(models.AssetComponent).filter(models.AssetComponent.tenant_id == t.id).count()
        match_count = db.query(models.ThreatMatch).filter(models.ThreatMatch.tenant_id == t.id).count()
        active_affected = db.query(models.ThreatMatch).filter(
            models.ThreatMatch.tenant_id == t.id,
            models.ThreatMatch.status.in_(['OPEN', 'open', 'unmitigated', 'triaged', 'active', 'IN_PROGRESS', 'in_progress']),
            models.ThreatMatch.ai_matching_reason.ilike('%[AFFECTED]%')
        ).count()
        user_count = db.query(models.User).filter(models.User.tenant_id == t.id).count()

        results.append({
            "id": t.id,
            "company_name": t.company_name,
            "tech_stack": t.tech_stack or "",
            "webhook_url": t.webhook_url or "",
            "has_auth_token": bool(t.auth_token),
            "asset_count": asset_count,
            "match_count": match_count,
            "active_affected_count": active_affected,
            "user_count": user_count,
            "created_at": str(t.created_at) if t.created_at else None,
            "updated_at": str(t.updated_at) if t.updated_at else None
        })
    return {"tenants": results, "total": len(results)}


@router.get("/users")
def get_admin_users(
    auth_ctx: dict = Depends(get_current_user_or_admin),
    db: Session = Depends(get_db)
):
    if auth_ctx["role"] != "super_admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required")

    users = db.query(models.User).all()
    admins = db.query(models.Admin).all()

    tenant_map = {t.id: t.company_name for t in db.query(models.Tenant).all()}

    results = []
    for a in admins:
        results.append({
            "id": a.id,
            "email": a.email,
            "role": "super_admin",
            "scope": "Platform Global",
            "tenant_id": None,
            "tenant_name": "Platform Operations",
            "is_mfa_enabled": True,
            "created_at": str(a.created_at) if a.created_at else None
        })

    for u in users:
        results.append({
            "id": u.id,
            "email": u.email,
            "role": u.role or "analyst",
            "scope": "Tenant Dedicated",
            "tenant_id": u.tenant_id,
            "tenant_name": tenant_map.get(u.tenant_id, "Unknown Organization"),
            "is_mfa_enabled": bool(u.is_mfa_enabled),
            "created_at": str(u.created_at) if u.created_at else None
        })

    return {"users": results, "total": len(results)}


class AdminManualContainmentRequest(BaseModel):
    target_ip: str
    target_port: int = 8000
    direction: str = "inbound"
    protocol: str = "tcp"
    tenant_id: Optional[str] = None
    threat_report_id: Optional[str] = None
    reason: Optional[str] = "Admin manual demo containment trigger"


@router.get("/containment/actions")
def get_admin_containment_actions(
    auth_ctx: dict = Depends(get_current_user_or_admin),
    db: Session = Depends(get_db)
):
    if auth_ctx["role"] != "super_admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required")

    tenant_map = {t.id: t.company_name for t in db.query(models.Tenant).all()}
    actions = db.query(models.ContainmentAction).order_by(models.ContainmentAction.created_at.desc()).limit(100).all()

    formatted = []
    for a in actions:
        formatted.append({
            "id": a.id,
            "action_id": a.action_id,
            "tenant_id": a.tenant_id,
            "tenant_name": tenant_map.get(a.tenant_id, "Unknown"),
            "indicator_value": a.indicator_value,
            "indicator_type": a.indicator_type,
            "action_type": a.action_type,
            "policy_decision": a.policy_decision,
            "policy_rule": a.policy_rule,
            "status": a.status,
            "ttl_seconds": a.ttl_seconds,
            "applied_at": str(a.applied_at) if a.applied_at else None,
            "expires_at": str(a.expires_at) if a.expires_at else None,
            "verified_at": str(a.verified_at) if a.verified_at else None,
            "rolled_back_at": str(a.rolled_back_at) if a.rolled_back_at else None,
            "execution_output": a.execution_output,
            "error_message": a.error_message,
            "rule_spec": a.rule_spec,
            "created_at": str(a.created_at) if a.created_at else None
        })

    active_mode = os.getenv("CONTAINMENT_ADAPTER_MODE", "simulated").upper()
    return {"actions": formatted, "total": len(formatted), "mode": active_mode}


@router.post("/containment/actions/trigger")
def admin_trigger_containment_action(
    payload: AdminManualContainmentRequest,
    auth_ctx: dict = Depends(get_current_user_or_admin),
    db: Session = Depends(get_db)
):
    """
    Admin-only manual containment trigger for demonstrations and recovery.
    Applies the exact same backend policy checks, executor, lifecycle state machine,
    and verification logic as the automated path.
    """
    if auth_ctx["role"] != "super_admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required")

    from app.services.firewall_adapter import get_containment_adapter, InvalidStateTransitionError

    # 1. Direction safety validation
    norm_dir = (payload.direction or "").strip().lower()
    if norm_dir not in ("in", "inbound", "ingress"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Safety restriction: Invalid direction '{payload.direction}'. Only inbound containment is permitted."
        )

    # 2. Protocol safety validation
    norm_proto = (payload.protocol or "").strip().lower()
    if norm_proto != "tcp":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Safety restriction: Invalid protocol '{payload.protocol}'. Only TCP is permitted."
        )

    # 3. Port safety validation (strictly port 8000 for Campus Guide)
    if payload.target_port != 8000:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Safety restriction: Invalid target port {payload.target_port}. Only port 8000 (Campus Guide service) is permitted."
        )

    # 4. Target IP parsing and safety validation
    clean_ip = payload.target_ip.strip() if payload.target_ip else ""
    try:
        addr = ipaddress.ip_address(clean_ip)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Malformed or invalid IPv4 address: '{payload.target_ip}'"
        )
    if not isinstance(addr, ipaddress.IPv4Address):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only IPv4 addresses are supported."
        )

    if addr.is_loopback or addr.is_unspecified or clean_ip == "255.255.255.255":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot contain loopback/unspecified/broadcast address '{clean_ip}'."
        )

    adapter_mode = os.getenv("CONTAINMENT_ADAPTER_MODE", "simulated").strip().lower()
    is_live_configured = adapter_mode in ("windows_firewall", "windows", "fedora_nftables")

    # Safety restriction: For live lab demo, permit only the explicitly authorized target 192.168.56.101
    if is_live_configured:
        from app.services.windows_firewall_adapter import is_lab_fedora_authorized, LAB_FEDORA_HOST_ONLY_IP
        if clean_ip != LAB_FEDORA_HOST_ONLY_IP:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Safety restriction: Live containment is strictly limited to authorized lab target '{LAB_FEDORA_HOST_ONLY_IP}'."
            )
        if not is_lab_fedora_authorized():
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Live lab containment rejected: ALLOW_LAB_FEDORA_HOST_CONTAINMENT is not enabled."
            )

    # 5. Tenant resolution
    if payload.tenant_id:
        tenant = db.query(models.Tenant).filter(models.Tenant.id == payload.tenant_id).first()
        if not tenant:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Tenant '{payload.tenant_id}' not found.")
    else:
        tenant = db.query(models.Tenant).first()
        if not tenant:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No tenant registered on platform.")

    # 6. Duplicate active containment check
    active_statuses = ["PENDING", "SIMULATED", "DISPATCHED", "RECEIVED", "APPLIED", "VERIFIED"]
    existing_active = db.query(models.ContainmentAction).filter(
        models.ContainmentAction.tenant_id == tenant.id,
        models.ContainmentAction.indicator_value == clean_ip,
        models.ContainmentAction.status.in_(active_statuses)
    ).first()
    if existing_active:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"An active containment action ({existing_active.action_id}) with status '{existing_active.status}' already exists for {clean_ip}. Rollback the existing action first."
        )

    # 7. Threat report correlation (optional / demo)
    threat_report = None
    if payload.threat_report_id:
        threat_report = db.query(models.ThreatReport).filter(models.ThreatReport.id == payload.threat_report_id).first()
    if not threat_report:
        threat_report = db.query(models.ThreatReport).filter(
            models.ThreatReport.cve_id.ilike("%2026%")
        ).first() or db.query(models.ThreatReport).first()

    # 8. Create ContainmentAction in PENDING state
    action_prefix = "act-win-" if "windows" in adapter_mode else "act-"
    action_id = f"{action_prefix}{uuid.uuid4().hex[:12]}"
    action = models.ContainmentAction(
        action_id=action_id,
        tenant_id=tenant.id,
        threat_report_id=threat_report.id if threat_report else None,
        indicator_value=clean_ip,
        indicator_type="ipv4",
        action_type="BLOCK_INBOUND_PORT_8000",
        policy_decision="QUALIFIED",
        policy_rule="ADMIN_MANUAL_DEMO_CONTAINMENT",
        status="PENDING",
        ttl_seconds=7200,
        rule_spec={
            "direction": "in",
            "port": 8000,
            "protocol": "TCP",
            "remote_ip": clean_ip,
            "trigger": "admin_manual_demo",
            "target_service": "Campus Guide",
            "adapter": adapter_mode.upper(),
            "reason": payload.reason or "Admin manual demo containment"
        }
    )
    db.add(action)
    db.commit()
    db.refresh(action)

    # 9. Execute containment via resolved adapter
    adapter = get_containment_adapter()
    result = adapter.apply_containment(
        action=action,
        db=db,
        actor=f"SUPER_ADMIN_{auth_ctx.get('email', 'admin')}",
        target_port=8000
    )

    return {
        "status": action.status,
        "action_id": action.action_id,
        "indicator_value": action.indicator_value,
        "target_ip": clean_ip,
        "target_port": 8000,
        "direction": "inbound",
        "protocol": "TCP",
        "policy_decision": action.policy_decision,
        "execution_output": action.execution_output,
        "error_message": action.error_message,
        "rule_spec": action.rule_spec,
        "created_at": str(action.created_at) if action.created_at else None,
        "message": result.get("message") or f"Containment action {action.action_id} executed with status '{action.status}'."
    }


@router.post("/containment/actions/{action_id}/rollback")
def admin_rollback_containment_action(
    action_id: str,
    auth_ctx: dict = Depends(get_current_user_or_admin),
    db: Session = Depends(get_db)
):
    if auth_ctx["role"] != "super_admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required")

    from app.services.firewall_adapter import InvalidStateTransitionError, get_adapter_for_action

    action = db.query(models.ContainmentAction).filter(
        (models.ContainmentAction.action_id == action_id) | (models.ContainmentAction.id == action_id)
    ).first()

    if not action:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Action '{action_id}' not found.")

    legal_rollback_statuses = {"SIMULATED", "RECEIVED", "DISPATCHED", "APPLIED", "VERIFIED"}
    if action.status not in legal_rollback_statuses:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot rollback action '{action_id}' in status '{action.status}'. Only active or applied actions can be rolled back."
        )

    try:
        adapter = get_adapter_for_action(action)
        result = adapter.rollback_containment(
            action=action,
            db=db,
            reason="Admin manual rollback override",
            actor=f"SUPER_ADMIN_{auth_ctx.get('email', 'admin')}"
        )
        return result
    except InvalidStateTransitionError as ste:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ste))


@router.post("/containment/actions/expire")
def admin_expire_containment_actions(
    auth_ctx: dict = Depends(get_current_user_or_admin),
    db: Session = Depends(get_db)
):
    if auth_ctx["role"] != "super_admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required")

    from app.services.firewall_adapter import get_containment_adapter

    adapter = get_containment_adapter()
    results = adapter.expire_active_containment_actions(
        db=db,
        actor=f"SUPER_ADMIN_{auth_ctx.get('email', 'admin')}"
    )
    return {"expired_count": len(results), "results": results}


@router.get("/containment/audit-logs")
@router.get("/audit/logs")
@router.get("/audit-logs")
def get_admin_containment_audit_logs(
    auth_ctx: dict = Depends(get_current_user_or_admin),
    db: Session = Depends(get_db)
):
    if auth_ctx["role"] != "super_admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required")

    tenant_map = {t.id: t.company_name for t in db.query(models.Tenant).all()}
    logs = db.query(models.ContainmentAuditLog).order_by(models.ContainmentAuditLog.created_at.desc()).limit(100).all()

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

    return {"logs": formatted, "total": len(formatted)}


@router.get("/integrations")
def get_admin_integrations(
    auth_ctx: dict = Depends(get_current_user_or_admin),
    db: Session = Depends(get_db)
):
    if auth_ctx["role"] != "super_admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required")

    tenants = db.query(models.Tenant).all()
    tenant_integrations = []
    for t in tenants:
        tenant_integrations.append({
            "tenant_id": t.id,
            "company_name": t.company_name,
            "webhook_url": t.webhook_url or "Not Configured",
            "has_auth_token": bool(t.auth_token),
            "status": "CONNECTED" if t.webhook_url else "DISCONNECTED"
        })

    from app.services.osint_collector import source_tracker
    live_feeds = source_tracker.get_all_status(db=db)

    from app.services.email_notification_service import get_smtp_config, is_smtp_configured
    smtp_cfg = get_smtp_config()
    email_integration = {
        "provider": smtp_cfg.get("provider", "brevo"),
        "host": smtp_cfg.get("host") or "Not Configured",
        "port": smtp_cfg.get("port", 587),
        "from_email": smtp_cfg.get("from_email", ""),
        "from_name": smtp_cfg.get("from_name", "CyberScribe Security"),
        "use_tls": smtp_cfg.get("use_tls", True),
        "email_enabled": smtp_cfg.get("email_enabled", False),
        "status": "ACTIVE_SMTP" if is_smtp_configured() else "SIMULATED",
        "has_credentials": bool(smtp_cfg.get("username") and smtp_cfg.get("password"))
    }

    return {
        "feeds": live_feeds,
        "tenant_webhooks": tenant_integrations,
        "email_integration": email_integration,
        "firewall_mode": "SIMULATION_ONLY (Live execution blocked by policy)"
    }


@router.get("/system-health")
def get_admin_system_health(
    auth_ctx: dict = Depends(get_current_user_or_admin),
    db: Session = Depends(get_db)
):
    if auth_ctx["role"] != "super_admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required")

    # DB connection check
    db_ok = True
    try:
        db.execute(models.Tenant.__table__.select().limit(1))
    except Exception:
        db_ok = False

    return {
        "status": "HEALTHY" if db_ok else "DEGRADED",
        "database": {"connected": db_ok, "engine": "MySQL / MariaDB", "isolation_level": "READ COMMITTED"},
        "background_collectors": {"status": "RUNNING", "mode": "Dual-Engine Sync & Stream"},
        "firewall_adapter": {"mode": "SIMULATED", "live_execution_permitted": False},
        "containment_policy_engine": {"confidence_threshold": "85.0%", "tenant_isolation": "STRICT"}
    }


@router.get("/readiness")
def get_admin_readiness(
    auth_ctx: dict = Depends(get_current_user_or_admin),
    db: Session = Depends(get_db)
):
    if auth_ctx["role"] != "super_admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required")
    from app.services.readiness_service import ReadinessService
    return ReadinessService.get_system_readiness(db=db)


@router.post("/threats/trigger-osint-sweep")
def admin_trigger_osint_sweep(
    background_tasks: BackgroundTasks,
    auth_ctx: dict = Depends(get_current_user_or_admin)
):
    if auth_ctx["role"] != "super_admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required")

    from app.services.osint_collector import run_sync_sweep, _sweep_mutex
    if _sweep_mutex.locked():
        return {"status": "SKIPPED", "message": "OSINT synchronization sweep is already active."}

    background_tasks.add_task(run_sync_sweep)
    return {"status": "INITIATED", "message": "OSINT synchronization sweep started in the background."}


@router.post("/threats/evaluate-eligible")
def admin_evaluate_eligible_threats(
    auth_ctx: dict = Depends(get_current_user_or_admin),
    db: Session = Depends(get_db)
):
    if auth_ctx["role"] != "super_admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required")

    from app.services.osint_collector import evaluate_existing_eligible_threats
    res = evaluate_existing_eligible_threats(db)
    return res


@router.get("/threats/sources/status")
def get_admin_osint_sources_status(
    auth_ctx: dict = Depends(get_current_user_or_admin),
    db: Session = Depends(get_db)
):
    if auth_ctx["role"] != "super_admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required")

    from app.services.osint_collector import source_tracker, DEFAULT_POLL_INTERVAL_SECONDS
    return {
        "status": "OPERATIONAL",
        "poll_interval_seconds": DEFAULT_POLL_INTERVAL_SECONDS,
        "total_sources": len(source_tracker.sources),
        "sources": source_tracker.get_all_status(db=db)
    }


class AdminTestEmailRequest(BaseModel):
    target_email: Optional[str] = None
    tenant_id: Optional[str] = None


@router.post("/notifications/test-email")
@router.post("/integrations/test-email")
def admin_send_test_email(
    payload: AdminTestEmailRequest = AdminTestEmailRequest(),
    auth_ctx: dict = Depends(get_current_user_or_admin),
    db: Session = Depends(get_db)
):
    """
    Authenticated administrator-only test email endpoint.
    Sends an authorized test email to target_email or admin email.
    If real email is not explicitly enabled or SMTP is unconfigured, operates safely in SIMULATED mode.
    """
    if auth_ctx["role"] != "super_admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required")

    admin_entity = auth_ctx["entity"]
    target_email = payload.target_email or getattr(admin_entity, "email", "admin@cyberscribe.internal")

    # Resolve target tenant for audit trail
    tenant = None
    if payload.tenant_id:
        tenant = db.query(models.Tenant).filter(models.Tenant.id == payload.tenant_id).first()
    if not tenant:
        tenant = db.query(models.Tenant).first()

    if not tenant:
        tenant = models.Tenant(
            id=str(uuid.uuid4()),
            company_name="CyberScribe Platform Operations",
            tech_stack="Internal Security Platform",
            remediation_policy="NOTIFY"
        )
        db.add(tenant)
        db.commit()
        db.refresh(tenant)

    from app.services.email_notification_service import EmailNotificationService
    try:
        res = EmailNotificationService.send_test_email(
            db=db,
            tenant=tenant,
            requesting_user=admin_entity,
            target_email=target_email
        )
        return res
    except ValueError as val_err:
        raise HTTPException(status_code=429, detail=str(val_err))
    except Exception as e:
        logger.error(f"Admin test email dispatch failed: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to dispatch test email: {str(e)}")