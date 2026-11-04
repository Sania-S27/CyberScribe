# backend/app/api/threats.py
import re
import json
import math
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks
from pydantic import BaseModel
from sqlalchemy.orm import Session
from sqlalchemy import or_, and_, not_, desc, func

from app import models
from app.core.database import get_db
from app.api.deps import get_current_user, require_super_admin
from app.services.vector_store import query_similar_threats, add_threat_embedding
from app.agents.mitigation import generate_soar_playbook, dispatch_playbook_to_matched_tenants
from app.agents.orchestrator import cyber_scribe_orchestrator
from app.services.osint_collector import check_threat_match_for_tenant, run_sync_sweep, _sweep_mutex
from app.services.triage import predict_threat_severity

router = APIRouter(prefix="/public", tags=["Public OSINT"])


class ThreatIngestRequest(BaseModel):
    title: str
    cve_id: Optional[str] = "CVE-2026-AUTO"
    severity: Optional[str] = None
    summary: str
    raw_text: Optional[str] = ""
    affected_software: List[str] = []
    iocs: Optional[Dict[str, Any]] = {"ip_addresses": ["127.0.0.1"]}
    published_at: Optional[datetime] = None


@router.post("/threats/trigger-osint-sweep")
def trigger_osint_sweep(
    background_tasks: BackgroundTasks,
    admin_ctx: Dict[str, Any] = Depends(require_super_admin)
):
    """Manually triggers the live dual-engine OSINT collector in the background. Restricted to Platform Admin."""
    if _sweep_mutex.locked():
        return {"status": "SKIPPED", "message": "OSINT synchronization sweep is already active."}

    background_tasks.add_task(run_sync_sweep)
    return {"status": "INITIATED", "message": "OSINT synchronization sweep started in the background."}


@router.post("/threats/evaluate-eligible")
def trigger_evaluate_eligible_threats(
    admin_ctx: Dict[str, Any] = Depends(require_super_admin),
    db: Session = Depends(get_db)
):
    """Triggers autonomous evaluation of existing eligible threat matches and unlinked threat reports."""
    from app.services.osint_collector import evaluate_existing_eligible_threats
    res = evaluate_existing_eligible_threats(db)
    return res


@router.get("/threats/sources/status")
def get_osint_sources_status(
    admin_ctx: Dict[str, Any] = Depends(require_super_admin),
    db: Session = Depends(get_db)
):
    """Returns continuous OSINT ingestion health, synchronization metrics, and failure diagnostics. Restricted to Platform Admin."""
    from app.services.osint_collector import source_tracker, DEFAULT_POLL_INTERVAL_SECONDS
    return {
        "status": "OPERATIONAL",
        "poll_interval_seconds": DEFAULT_POLL_INTERVAL_SECONDS,
        "total_sources": len(source_tracker.sources),
        "sources": source_tracker.get_all_status(db=db)
    }



def extract_threat_match_metadata(m: models.ThreatMatch, db: Session) -> Dict[str, Any]:
    """Extracts component, version, and assessment outcome (AFFECTED / NOT_AFFECTED / NEEDS_REVIEW)."""
    reason = m.ai_matching_reason or ""
    outcome = "NEEDS_REVIEW"
    if "[AFFECTED]" in reason.upper():
        outcome = "AFFECTED"
    elif "[NOT AFFECTED]" in reason.upper():
        outcome = "NOT_AFFECTED"
    elif "[NEEDS REVIEW]" in reason.upper():
        outcome = "NEEDS_REVIEW"
    elif "satisfies vulnerable constraint" in reason:
        outcome = "AFFECTED"
    elif "outside vulnerable range" in reason:
        outcome = "NOT_AFFECTED"

    component = None
    version = None

    if m.asset_component_id:
        asset = db.query(models.AssetComponent).filter(models.AssetComponent.id == m.asset_component_id).first()
        if asset:
            component = asset.software_name
            version = asset.software_version

    if not component or not version:
        m_mismatch = re.search(r"mismatch with installed ['\"]?([a-zA-Z0-9_\-\.]+)['\"]?\s*(?:\(([^)]+)\)|\s+([0-9\.\w\-]+))", reason, re.IGNORECASE)
        if m_mismatch:
            component = component or m_mismatch.group(1)
            version = version or m_mismatch.group(2) or m_mismatch.group(3)
        else:
            m_inst = re.search(r"Installed ['\"]?([a-zA-Z0-9_\-\.]+)['\"]?\s+([0-9\.\w\-]+)", reason, re.IGNORECASE)
            if m_inst:
                component = component or m_inst.group(1)
                version = version or m_inst.group(2)
            else:
                m_comp = re.search(r"Component ['\"]?([a-zA-Z0-9_\-\.]+)['\"]?\s*\(([^)]+)\)", reason, re.IGNORECASE)
                if m_comp:
                    component = component or m_comp.group(1)
                    version = version or m_comp.group(2)

    return {
        "assessment_outcome": outcome,
        "matched_component": component or "Software Component",
        "installed_version": version or "Unspecified",
        "match_reason": reason
    }


def calculate_component_threat_exposure(tenant_id: str, db: Session) -> Dict[str, Any]:
    """
    Calculates distinct relevant threat counts per software component for a tenant.
    - Includes all registered AssetComponent items for the tenant (including those with 0 threats).
    - Counts distinct relevant threats (by threat_report_id or match id).
    - Excludes NOT_AFFECTED (safe/outside vulnerable range) and RESOLVED threats from the active vulnerability count.
    - Returns a dict with:
        'component_exposure': {comp_name: count, ...}
        'top_components': [[comp_name, count], ...] (sorted descending by count)
    """
    assets = db.query(models.AssetComponent).filter(models.AssetComponent.tenant_id == tenant_id).all()
    comp_threat_map: Dict[str, set] = {}
    name_lookup: Dict[str, str] = {}
    for a in assets:
        if a.software_name:
            clean_name = a.software_name.strip()
            comp_threat_map[clean_name] = set()
            name_lookup[clean_name.lower()] = clean_name

    matches = db.query(models.ThreatMatch).filter(models.ThreatMatch.tenant_id == tenant_id).all()
    for m in matches:
        reason = m.ai_matching_reason or ""
        # 1. Skip NOT_AFFECTED (outside vulnerable range or safe)
        if "[NOT AFFECTED]" in reason.upper() or "outside vulnerable range" in reason.lower():
            continue
        # 2. Skip RESOLVED/mitigated threats
        status_val = (m.status or "").strip().upper()
        if status_val in ["RESOLVED", "PATCHED", "MITIGATED"]:
            continue

        # 3. Resolve component name
        comp = None
        if m.asset_component_id:
            asset = db.query(models.AssetComponent).filter(models.AssetComponent.id == m.asset_component_id).first()
            if asset and asset.software_name:
                comp = asset.software_name.strip()

        if not comp:
            meta = extract_threat_match_metadata(m, db)
            extracted = meta.get("matched_component")
            if extracted and extracted != "Software Component":
                comp = extracted.strip()

        if not comp:
            continue

        canonical_comp = name_lookup.get(comp.lower(), comp)
        if canonical_comp not in comp_threat_map:
            comp_threat_map[canonical_comp] = set()
            name_lookup[canonical_comp.lower()] = canonical_comp

        threat_key = m.threat_report_id or m.id
        comp_threat_map[canonical_comp].add(threat_key)

    component_exposure = {c: len(threats) for c, threats in comp_threat_map.items()}
    sorted_comps = sorted(component_exposure.items(), key=lambda x: (-x[1], x[0]))

    return {
        "component_exposure": component_exposure,
        "top_components": [[c, cnt] for c, cnt in sorted_comps]
    }


def normalize_status(val: Optional[str]) -> str:
    """Normalizes internal or legacy database status to OPEN, IN_PROGRESS, or RESOLVED."""
    if not val:
        return "OPEN"
    s = str(val).strip().upper()
    if s in ["UNMITIGATED", "TRIAGED", "ACTIVE", "OPEN"]:
        return "OPEN"
    elif s in ["PATCHED", "MITIGATED", "RESOLVED"]:
        return "RESOLVED"
    elif s in ["IN_PROGRESS"]:
        return "IN_PROGRESS"
    return "OPEN"


@router.get("/threats/matches")
def get_tenant_threat_matches(
    page: int = 1,
    page_size: int = 10,
    status: Optional[str] = None,
    severity: Optional[str] = None,
    search: Optional[str] = None,
    assessment_outcome: Optional[str] = None,
    view: Optional[str] = None,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Fetches server-side paginated matched threats for the authenticated tenant with views (active/review/resolved/safe/all), normalized status, and rich SBOM metadata."""
    tenant_id = getattr(current_user, "tenant_id", None)
    if not tenant_id:
        return {
            "total": 0, "page": 1, "page_size": page_size, "total_pages": 1, "matches": [],
            "summary": {"total_correlated": 0, "active_affected": 0, "review_required": 0, "resolved": 0, "not_affected": 0, "health_score": 100, "top_components": [], "component_exposure": {}},
            "top_components": [],
            "component_exposure": {}
        }

    tenant = db.query(models.Tenant).filter(models.Tenant.id == tenant_id).first()
    if not tenant:
        return {
            "total": 0, "page": 1, "page_size": page_size, "total_pages": 1, "matches": [],
            "summary": {"total_correlated": 0, "active_affected": 0, "review_required": 0, "resolved": 0, "not_affected": 0, "health_score": 100, "top_components": [], "component_exposure": {}},
            "top_components": [],
            "component_exposure": {}
        }

    page = max(1, page)
    page_size = page_size if page_size in [10, 25, 50, 100, 1000] else 10

    target_tenant_id = tenant.id
    base_tenant_q = db.query(models.ThreatMatch).filter(models.ThreatMatch.tenant_id == target_tenant_id)

    # Reusable assessment outcome SQL filters
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

    # Compute aggregate tenant metrics
    total_corr = base_tenant_q.count()
    active_aff_count = base_tenant_q.filter(
        models.ThreatMatch.status.in_(['OPEN', 'open', 'unmitigated', 'triaged', 'active', 'IN_PROGRESS', 'in_progress']),
        cond_affected
    ).count()
    review_req_count = base_tenant_q.filter(
        models.ThreatMatch.status.in_(['OPEN', 'open', 'unmitigated', 'triaged', 'active', 'IN_PROGRESS', 'in_progress']),
        cond_needs_review
    ).count()
    resolved_count = base_tenant_q.filter(
        models.ThreatMatch.status.in_(['RESOLVED', 'resolved', 'patched', 'mitigated'])
    ).count()
    not_aff_count = base_tenant_q.filter(cond_not_affected).count()

    # Authoritative severity distribution across ALL correlated findings for this tenant
    sev_query = db.query(
        models.ThreatReport.severity,
        func.count(models.ThreatMatch.id)
    ).join(
        models.ThreatReport, models.ThreatMatch.threat_report_id == models.ThreatReport.id
    ).filter(
        models.ThreatMatch.tenant_id == target_tenant_id
    ).group_by(models.ThreatReport.severity).all()

    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for sev_name, cnt in sev_query:
        s = (sev_name or "medium").lower()
        if s in sev_counts:
            sev_counts[s] += cnt
        else:
            sev_counts["medium"] += cnt

    h_score = 100 if active_aff_count == 0 else max(10, round(100 - (active_aff_count / max(active_aff_count + resolved_count, 1)) * 50))
    comp_stats = calculate_component_threat_exposure(target_tenant_id, db)
    summary_dict = {
        "total_correlated": total_corr,
        "active_affected": active_aff_count,
        "review_required": review_req_count,
        "resolved": resolved_count,
        "not_affected": not_aff_count,
        "severity_counts": sev_counts,
        "severity_total": sum(sev_counts.values()),
        "health_score": h_score,
        "top_components": comp_stats["top_components"],
        "component_exposure": comp_stats["component_exposure"]
    }

    query = base_tenant_q

    # 1. Apply View filter if provided
    if view:
        v = view.strip().lower()
        if v == "active":
            # Active confirmed AFFECTED threats only (excludes NOT_AFFECTED and NEEDS_REVIEW)
            query = query.filter(
                models.ThreatMatch.status.in_(['OPEN', 'open', 'unmitigated', 'triaged', 'active', 'IN_PROGRESS', 'in_progress']),
                cond_affected
            )
        elif v == "review":
            # Ambiguous matches requiring review
            query = query.filter(
                models.ThreatMatch.status.in_(['OPEN', 'open', 'unmitigated', 'triaged', 'active', 'IN_PROGRESS', 'in_progress']),
                cond_needs_review
            )
        elif v == "resolved":
            # Verified resolved threats
            query = query.filter(
                models.ThreatMatch.status.in_(['RESOLVED', 'resolved', 'patched', 'mitigated'])
            )
        elif v in ["safe", "not_affected"]:
            # Verified safe / outside vulnerable range
            query = query.filter(cond_not_affected)
        # if v == "all", no view filter

    # 2. Apply Direct Assessment Outcome filter if provided
    if assessment_outcome and assessment_outcome.upper() != "ALL":
        ao = assessment_outcome.strip().upper()
        if ao == "AFFECTED":
            query = query.filter(cond_affected)
        elif ao == "NOT_AFFECTED":
            query = query.filter(cond_not_affected)
        elif ao == "NEEDS_REVIEW":
            query = query.filter(cond_needs_review)

    # 3. Apply Status filter
    if status and status.upper() != "ALL":
        st = status.strip().upper()
        if st in ["OPEN", "UNMITIGATED", "TRIAGED", "ACTIVE"]:
            query = query.filter(models.ThreatMatch.status.in_(["OPEN", "unmitigated", "triaged", "active"]))
        elif st in ["IN_PROGRESS"]:
            query = query.filter(models.ThreatMatch.status.in_(["IN_PROGRESS", "in_progress"]))
        elif st in ["RESOLVED", "PATCHED", "MITIGATED"]:
            query = query.filter(models.ThreatMatch.status.in_(["RESOLVED", "patched", "mitigated"]))
        else:
            query = query.filter(models.ThreatMatch.status == status.lower())

    joined_report = False
    if search and search.strip():
        term = f"%{search.strip()}%"
        query = query.join(models.ThreatReport, models.ThreatMatch.threat_report_id == models.ThreatReport.id)
        joined_report = True
        query = query.filter(
            or_(
                models.ThreatReport.title.ilike(term),
                models.ThreatReport.summary.ilike(term),
                models.ThreatReport.cve_id.ilike(term),
                models.ThreatMatch.ai_matching_reason.ilike(term)
            )
        )

    if severity and severity.upper() != "ALL":
        if not joined_report:
            query = query.join(models.ThreatReport, models.ThreatMatch.threat_report_id == models.ThreatReport.id)
        query = query.filter(models.ThreatReport.severity == severity.lower())

    total_count = query.count()
    total_pages = max(1, math.ceil(total_count / page_size))
    offset = (page - 1) * page_size

    matches = query.order_by(models.ThreatMatch.id.desc()).offset(offset).limit(page_size).all()

    formatted = []
    for m in matches:
        report = db.query(models.ThreatReport).filter(models.ThreatReport.id == m.threat_report_id).first()
        meta = extract_threat_match_metadata(m, db)
        formatted.append({
            "id": m.id,
            "threat_id": m.threat_report_id,
            "threat_title": report.title if report else "Threat Advisory",
            "cve_id": report.cve_id if (report and report.cve_id) else "CVE-N/A",
            "severity": report.severity if report else "HIGH",
            "summary": report.summary if report else "",
            "status": normalize_status(m.status),
            "ai_confidence_score": float(m.ai_confidence_score) if m.ai_confidence_score is not None else 94.0,
            "ai_matching_reason": m.ai_matching_reason,
            "assessment_outcome": meta["assessment_outcome"],
            "matched_component": meta["matched_component"],
            "installed_version": meta["installed_version"],
            "match_reason": meta["match_reason"],
            "published_at": report.published_at.strftime("%Y-%m-%d %H:%M") if (report and hasattr(report, "published_at") and report.published_at) else None,
            "created_at": report.created_at.strftime("%Y-%m-%d %H:%M") if (report and hasattr(report, "created_at") and report.created_at) else "",
            "date": (report.published_at or report.created_at).strftime("%Y-%m-%d %H:%M") if (report and hasattr(report, "created_at") and report.created_at) else "Recent",
            "threat_report": {
                "id": report.id if report else m.threat_report_id,
                "title": report.title if report else "Threat Advisory",
                "summary": report.summary if report else "",
                "severity": report.severity if report else "high",
                "cve_id": report.cve_id if report else None,
                "source_url": report.source_url if report else None,
                "published_at": str(report.published_at) if (report and hasattr(report, "published_at") and report.published_at) else None,
                "created_at": str(report.created_at) if (report and hasattr(report, "created_at")) else None,
                "stix_bundle": report.stix_bundle if report else None
            }
        })

    return {
        "total": total_count,
        "page": page,
        "page_size": page_size,
        "total_pages": total_pages,
        "matches": formatted,
        "summary": summary_dict,
        "top_components": comp_stats["top_components"],
        "component_exposure": comp_stats["component_exposure"]
    }


@router.post("/threats/resync-matches")
def resync_tenant_matches(
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Scans all database threat reports against tenant tech stack and ingested SBOM assets."""
    tenant_id = getattr(current_user, "tenant_id", None)
    if not tenant_id:
        raise HTTPException(status_code=403, detail="User not associated with a valid tenant organization")

    tenant = db.query(models.Tenant).filter(models.Tenant.id == tenant_id).first()
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant organization not found")

    stack_items = []
    if tenant.tech_stack:
        stack_items.extend([t.strip() for t in tenant.tech_stack.split(",") if t.strip()])

    assets = db.query(models.AssetComponent).filter(models.AssetComponent.tenant_id == tenant.id).all()
    for a in assets:
        stack_items.append(f"{a.software_name}:{getattr(a, 'software_version', '')}")

    full_stack_str = ", ".join(list(set(stack_items)))

    if not full_stack_str:
        return {"status": "NO_OP", "message": "Tenant has no registered tech stack or asset components."}

    all_reports = db.query(models.ThreatReport).all()
    new_matches_count = 0

    for rep in all_reports:
        existing_match = db.query(models.ThreatMatch).filter(
            models.ThreatMatch.tenant_id == tenant.id,
            models.ThreatMatch.threat_report_id == rep.id
        ).first()

        if not existing_match:
            is_match, conf, reason = check_threat_match_for_tenant(
                threat_title=rep.title or "",
                threat_summary=rep.summary or "",
                tenant_tech_stack=full_stack_str,
                threat_raw=getattr(rep, "raw_text", "") or ""
            )
            if is_match:
                rep_sev = (rep.severity or "medium").lower()
                # Vulnerability remediation status remains OPEN independent of webhook dispatch
                match_status = "OPEN"

                db.add(models.ThreatMatch(
                    tenant_id=tenant.id,
                    threat_report_id=rep.id,
                    status=match_status,
                    ai_confidence_score=conf,
                    ai_matching_reason=reason
                ))
                new_matches_count += 1

    db.commit()
    return {
        "status": "SUCCESS",
        "tenant_id": str(tenant.id),
        "tenant_name": tenant.company_name,
        "monitored_inventory": full_stack_str,
        "new_matches_created": new_matches_count
    }


@router.post("/threats/ingest", status_code=status.HTTP_201_CREATED)
def ingest_threat_advisory(
    payload: ThreatIngestRequest,
    db: Session = Depends(get_db)
):
    """Direct threat ingestion endpoint enforcing Critical/High automated mitigation."""
    try:
        computed_severity = payload.severity
        stix_bundle_dict = None

        # Execute LangGraph Multi-Agent pipeline if raw advisory text is provided
        if payload.raw_text and len(payload.raw_text.strip()) > 30:
            try:
                pipeline_result = cyber_scribe_orchestrator.invoke({"raw_text": payload.raw_text})
                final_rep = pipeline_result.get("final_report", {})
                if isinstance(final_rep, dict) and final_rep:
                    payload.title = final_rep.get("title") or payload.title
                    payload.summary = final_rep.get("summary") or payload.summary
                    if final_rep.get("cve_id"):
                        payload.cve_id = final_rep["cve_id"]
                    if final_rep.get("severity"):
                        computed_severity = final_rep["severity"]
                stix_from_pipeline = pipeline_result.get("stix_bundle")
                if stix_from_pipeline:
                    stix_bundle_dict = stix_from_pipeline
            except Exception as orch_err:
                print(f"[-] [Orchestrator Ingest Warning] Fallback to manual payload: {orch_err}")

        if not computed_severity or computed_severity.upper() == "UNKNOWN":
            computed_severity = predict_threat_severity(payload.summary or payload.title)

        if not stix_bundle_dict:
            stix_bundle_dict = {
                "type": "bundle",
                "id": f"bundle--{payload.cve_id.lower() if payload.cve_id else 'threat-auto'}",
                "spec_version": "2.1",
                "objects": [
                    {
                        "type": "vulnerability",
                        "spec_version": "2.1",
                        "id": f"vulnerability--{payload.cve_id.lower() if payload.cve_id else 'auto'}",
                        "name": payload.title,
                        "description": payload.summary,
                        "external_references": [{"source_name": "cve", "external_id": payload.cve_id}] if payload.cve_id else []
                    }
                ]
            }

        # Ensure unique source URL to prevent MySQL duplicate key errors
        unique_source = (
            f"https://nvd.nist.gov/vuln/detail/{payload.cve_id}" 
            if payload.cve_id and "AUTO" not in payload.cve_id 
            else f"manual-feed://{payload.title[:25].lower().replace(' ', '-')}-{payload.cve_id}"
        )

        # Deduplication Check: Prevent duplicate record insertion
        existing = db.query(models.ThreatReport).filter(
            or_(
                models.ThreatReport.source_url == unique_source,
                and_(models.ThreatReport.cve_id == payload.cve_id, models.ThreatReport.cve_id != None, payload.cve_id != "CVE-2026-AUTO")
            )
        ).first()

        if existing:
            return {
                "status": "DUPLICATE",
                "message": f"Threat '{payload.cve_id or payload.title}' already exists in database.",
                "report_id": existing.id,
                "cve_id": existing.cve_id,
                "title": existing.title,
                "severity": existing.severity,
                "dispatched": []
            }

        threat_report = models.ThreatReport(
            title=payload.title,
            cve_id=payload.cve_id,
            severity=computed_severity.lower(),
            summary=payload.summary,
            stix_bundle=stix_bundle_dict,
            source_url=unique_source,
            published_at=payload.published_at or datetime.now(timezone.utc).replace(tzinfo=None)
        )
        db.add(threat_report)
        db.commit()
        db.refresh(threat_report)

        # Index newly ingested threat into ChromaDB vector store
        try:
            add_threat_embedding(
                threat_id=threat_report.id,
                title=threat_report.title,
                summary=threat_report.summary or "",
                severity=threat_report.severity,
                source_url=threat_report.source_url,
                cve_id=threat_report.cve_id,
                published_at=threat_report.published_at
            )
        except Exception as vec_err:
            print(f"[!] [ChromaDB Indexing Warning] Failed to index manual threat {threat_report.id}: {vec_err}")

        # Policy Gate: Only Critical & High severity trigger automated SOAR containment
        is_high_or_critical = (computed_severity or "").lower() in ["critical", "high"]
        dispatch_results = []

        if is_high_or_critical:
            playbook = generate_soar_playbook(
                threat_title=threat_report.title,
                summary=threat_report.summary,
                mitre_tactics=[]
            )

            match_keywords = " ".join(payload.affected_software) if payload.affected_software else (threat_report.cve_id or threat_report.title)
            
            raw_dispatch = dispatch_playbook_to_matched_tenants(
                db=db,
                playbook=playbook,
                keyword_filter=match_keywords
            )
            
            if isinstance(raw_dispatch, list):
                dispatch_results = raw_dispatch
            elif raw_dispatch is not None:
                dispatch_results = [raw_dispatch]
            else:
                dispatch_results = []
                
            print(f"[SOAR] Critical/High alert dispatched for {threat_report.cve_id}.")
        else:
            print(f"[Advisory Policy] Severity '{computed_severity}' logged without immediate firewall containment.")

        # Correlate across all registered tenants
        raw_corpus = payload.raw_text or f"{payload.title} {payload.summary} {' '.join(payload.affected_software or [])}"
        tenants = db.query(models.Tenant).all()
        for tenant in tenants:
            stack_parts = []
            if tenant.tech_stack:
                stack_parts.append(tenant.tech_stack)
            assets = db.query(models.AssetComponent).filter(models.AssetComponent.tenant_id == tenant.id).all()
            for a in assets:
                software_name = (getattr(a, 'software_name', '') or '').strip()
                software_version = (getattr(a, 'software_version', '') or '').strip()
                if software_name:
                    stack_parts.append(f"{software_name}:{software_version}" if software_version else software_name)
            
            full_tech_stack = ", ".join(list(set(stack_parts)))
            if full_tech_stack:
                is_match, conf, reason = check_threat_match_for_tenant(
                    threat_title=threat_report.title or "",
                    threat_summary=threat_report.summary or "",
                    tenant_tech_stack=full_tech_stack,
                    threat_raw=raw_corpus
                )
                if is_match:
                    # Vulnerability remediation status remains OPEN independent of webhook dispatch acknowledgement
                    match_status = "OPEN"
                    db.add(models.ThreatMatch(
                        tenant_id=tenant.id,
                        threat_report_id=threat_report.id,
                        status=match_status,
                        ai_confidence_score=conf,
                        ai_matching_reason=reason
                    ))
        db.commit()

        return {
            "status": "SUCCESS",
            "message": f"Threat report ingested. Policy containment: {'DISPATCHED' if is_high_or_critical else 'ADVISORY_ONLY'}",
            "report_id": threat_report.id,
            "cve_id": threat_report.cve_id,
            "severity": threat_report.severity,
            "dispatched": dispatch_results
        }
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Ingestion failed: {str(e)}")


@router.get("/threats")
def get_global_threats(
    page: int = 1,
    page_size: int = 10,
    severity: Optional[str] = None,
    search: Optional[str] = None,
    days: Optional[str] = "90",
    db: Session = Depends(get_db)
):
    """
    Returns server-side paginated global threat intelligence reports.
    Supports filtering by search term, severity, and configurable date window (default: last 90 days / 3 months).
    """
    page = max(1, page)
    page_size = page_size if page_size in [10, 25, 50] else 10

    query = db.query(models.ThreatReport)

    # Date range filtering (default: 90 days / 3 months; "all" reveals full historical dataset)
    # Includes reports with genuine published_at >= cutoff OR (published_at IS NULL AND created_at >= cutoff)
    if days and days.lower() != "all":
        try:
            num_days = int(days)
            cutoff_date = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=num_days)
            query = query.filter(
                or_(
                    models.ThreatReport.published_at >= cutoff_date,
                    and_(
                        models.ThreatReport.published_at.is_(None),
                        models.ThreatReport.created_at >= cutoff_date
                    )
                )
            )
        except ValueError:
            pass

    # Severity filtering
    if severity and severity.upper() != "ALL":
        query = query.filter(models.ThreatReport.severity == severity.lower())

    # Search filtering
    if search and search.strip():
        term = f"%{search.strip()}%"
        query = query.filter(
            or_(
                models.ThreatReport.title.ilike(term),
                models.ThreatReport.summary.ilike(term),
                models.ThreatReport.cve_id.ilike(term)
            )
        )

    total_count = query.count()
    total_pages = max(1, math.ceil(total_count / page_size))
    offset = (page - 1) * page_size

    reports = query.order_by(
        desc(func.coalesce(models.ThreatReport.published_at, models.ThreatReport.created_at)),
        desc(models.ThreatReport.created_at)
    ).offset(offset).limit(page_size).all()

    formatted_reports = []
    for r in reports:
        formatted_reports.append({
            "id": r.id,
            "title": r.title,
            "summary": r.summary,
            "severity": r.severity,
            "cve": r.cve_id,
            "source": r.source_url,
            "published_at": r.published_at.strftime("%Y-%m-%d %H:%M") if (hasattr(r, "published_at") and r.published_at) else None,
            "date": (r.published_at or r.created_at).strftime("%Y-%m-%d %H:%M") if (hasattr(r, "created_at") and r.created_at) else "Recent",
            "created_at": r.created_at.strftime("%Y-%m-%d %H:%M") if (hasattr(r, "created_at") and r.created_at) else "Recent"
        })

    return {
        "total": total_count,
        "page": page,
        "page_size": page_size,
        "total_pages": total_pages,
        "threats": formatted_reports
    }


@router.get("/threats/semantic-search")
def semantic_threat_search(query: str):
    search_results = query_similar_threats(query_text=query, n_results=5)
    return {"query": query, "matches": search_results}


@router.get("/threats/{report_id}/stix")
def get_threat_stix_bundle(report_id: str, db: Session = Depends(get_db)):
    report = db.query(models.ThreatReport).filter(
        (models.ThreatReport.id == report_id) | (models.ThreatReport.cve_id == report_id)
    ).first()
    if not report:
        raise HTTPException(status_code=404, detail="Threat report not found")

    stix_data = report.stix_bundle
    if isinstance(stix_data, str):
        try:
            stix_data = json.loads(stix_data)
        except Exception:
            pass

    if not stix_data or not isinstance(stix_data, dict):
        cve_clean = (report.cve_id or "threat").lower().replace("_", "-")
        stix_data = {
            "type": "bundle",
            "id": f"bundle--{cve_clean}",
            "spec_version": "2.1",
            "objects": [
                {
                    "type": "vulnerability",
                    "spec_version": "2.1",
                    "id": f"vulnerability--{cve_clean}",
                    "name": report.title,
                    "description": report.summary or report.title,
                    "external_references": [{"source_name": "cve", "external_id": report.cve_id}] if report.cve_id else []
                }
            ]
        }

    return {
        "report_id": report.id,
        "title": report.title,
        "stix_version": "2.1",
        "stix_bundle": stix_data
    }


@router.get("/threats/{report_id}/pdf")
def export_threat_report_pdf(report_id: str, db: Session = Depends(get_db)):
    """Exports an individual threat report as a standards-compliant PDF 1.4 document."""
    from fastapi.responses import Response
    from app.services.pdf_service import generate_threat_pdf_bytes

    report = db.query(models.ThreatReport).filter(
        (models.ThreatReport.id == report_id) | (models.ThreatReport.cve_id == report_id)
    ).first()
    if not report:
        raise HTTPException(status_code=404, detail="Threat report not found")

    mitre_techs = []
    if report.stix_bundle and isinstance(report.stix_bundle, dict) and "objects" in report.stix_bundle:
        for obj in report.stix_bundle["objects"]:
            if obj.get("type") == "attack-pattern":
                name = obj.get("name", "")
                ext_refs = obj.get("external_references", [])
                ext_id = ext_refs[0].get("external_id") if ext_refs else ""
                mitre_techs.append(f"{ext_id}: {name}" if ext_id else name)

    pdf_bytes = generate_threat_pdf_bytes(report, mitre_techs)
    cve_name = (report.cve_id or "threat").lower().replace(" ", "-")

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="cyberscribe_{cve_name}.pdf"',
            "Content-Length": str(len(pdf_bytes))
        }
    )


@router.get("/threats/{report_id}/playbook")
def get_threat_playbook(report_id: str, db: Session = Depends(get_db)):
    report = db.query(models.ThreatReport).filter(
        (models.ThreatReport.id == report_id) | (models.ThreatReport.cve_id == report_id)
    ).first()
    if not report:
        raise HTTPException(status_code=404, detail="Threat report not found")

    mitre_tactics = []
    if report.stix_bundle and isinstance(report.stix_bundle, dict) and "objects" in report.stix_bundle:
        for obj in report.stix_bundle["objects"]:
            if obj.get("type") == "attack-pattern":
                ext_refs = obj.get("external_references", [])
                tech_id = ext_refs[0].get("external_id") if ext_refs else "N/A"
                mitre_tactics.append({"technique_id": tech_id, "technique_name": obj.get("name")})

    # Retrieve associated tenant match outcome if available
    match = db.query(models.ThreatMatch).filter(models.ThreatMatch.threat_report_id == report.id).first()
    meta = extract_threat_match_metadata(match, db) if match else {}
    outcome = meta.get("assessment_outcome")
    component = meta.get("matched_component")

    playbook = generate_soar_playbook(
        threat_title=report.title,
        summary=report.summary,
        mitre_tactics=mitre_tactics,
        assessment_outcome=outcome,
        matched_component=component
    )

    dispatch_results = []
    # Safeguard: NEEDS_REVIEW findings must never trigger automatic containment or dispatch
    if outcome != "NEEDS_REVIEW":
        raw_dispatch = dispatch_playbook_to_matched_tenants(
            db=db,
            playbook=playbook,
            keyword_filter=report.cve_id or report.title
        )
        dispatch_results = raw_dispatch if isinstance(raw_dispatch, list) else ([] if raw_dispatch is None else [raw_dispatch])

    return {
        "report_id": report.id,
        "threat_title": report.title,
        "playbook": playbook,
        "dispatched": dispatch_results
    }


@router.post("/threats/{match_id}/mitigate")
def apply_threat_mitigation(
    match_id: str,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Manually marks a threat match as patched after SOC remediation."""
    match_entry = db.query(models.ThreatMatch).filter(models.ThreatMatch.id == match_id).first()
    
    if not match_entry:
        raise HTTPException(status_code=404, detail="Threat match record not found")
    
    tenant_id = getattr(current_user, "tenant_id", None)
    if tenant_id and getattr(current_user, "role", "") != "super_admin":
        if match_entry.tenant_id != tenant_id:
            raise HTTPException(status_code=403, detail="Access denied: Cannot mitigate threat belonging to another tenant")

    match_entry.status = "RESOLVED"
    db.commit()
    db.refresh(match_entry)
    
    return {
        "status": "SUCCESS",
        "message": f"Threat match {match_id} successfully marked as RESOLVED.",
        "match_id": match_entry.id,
        "new_status": match_entry.status
    }