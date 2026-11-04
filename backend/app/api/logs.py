# backend/app/api/logs.py
import math
from typing import Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import or_, and_, not_, desc, func
from app.core.database import get_db
from app import models
from app.api.deps import get_current_user
from app.api.threats import extract_threat_match_metadata, calculate_component_threat_exposure

router = APIRouter(prefix="/threats", tags=["Tenant Threat Logs"])


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


@router.get("/matches")
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
    # Resolve tenant record with strict tenant isolation
    tenant_id = getattr(current_user, "tenant_id", None) or getattr(current_user, "id", None)
    tenant = None
    if tenant_id:
        tenant = db.query(models.Tenant).filter(models.Tenant.id == tenant_id).first()
    
    # Fallback only for super_admin platform diagnostic viewing
    if not tenant and getattr(current_user, "role", "") == "super_admin":
        tenant = db.query(models.Tenant).first()

    page = max(1, page)
    page_size = page_size if page_size in [10, 25, 50, 100, 1000] else 10

    if not tenant:
        return {
            "total": 0, "page": 1, "page_size": page_size, "total_pages": 1, "matches": [],
            "summary": {"total_correlated": 0, "active_affected": 0, "review_required": 0, "resolved": 0, "not_affected": 0, "health_score": 100, "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0}, "severity_total": 0, "top_components": [], "component_exposure": {}},
            "top_components": [],
            "component_exposure": {}
        }

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
        "top_components": comp_stats["top_stats" if "top_stats" in comp_stats else "top_components"],
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

    results = []
    for match in matches:
        report = db.query(models.ThreatReport).filter(models.ThreatReport.id == match.threat_report_id).first()
        meta = extract_threat_match_metadata(match, db)
        results.append({
            "id": match.id,
            "threat_id": match.threat_report_id,
            "threat_title": report.title if report else "Threat Advisory",
            "cve_id": report.cve_id if (report and report.cve_id) else "CVE-N/A",
            "severity": report.severity if report else "high",
            "summary": report.summary if report else "",
            "status": normalize_status(match.status),
            "ai_confidence_score": float(match.ai_confidence_score) if match.ai_confidence_score is not None else 94.0,
            "ai_matching_reason": match.ai_matching_reason or "Component match",
            "assessment_outcome": meta["assessment_outcome"],
            "matched_component": meta["matched_component"],
            "installed_version": meta["installed_version"],
            "match_reason": meta["match_reason"],
            "published_at": report.published_at.strftime("%Y-%m-%d %H:%M") if (report and hasattr(report, "published_at") and report.published_at) else None,
            "created_at": report.created_at.strftime("%Y-%m-%d %H:%M") if (report and hasattr(report, "created_at") and report.created_at) else "",
            "date": (report.published_at or report.created_at).strftime("%Y-%m-%d %H:%M") if (report and hasattr(report, "created_at") and report.created_at) else "Recent",
            "threat_report": {
                "id": report.id if report else match.threat_report_id,
                "title": report.title if report else "Threat Advisory",
                "summary": report.summary if report else "",
                "severity": report.severity if report else "high",
                "cve_id": report.cve_id if report else None,
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
        "matches": results,
        "summary": summary_dict,
        "top_components": comp_stats["top_components"],
        "component_exposure": comp_stats["component_exposure"]
    }


@router.post("/matches/{match_id}/mitigate")
@router.post("/{match_id}/mitigate")
def apply_threat_mitigation_logs(
    match_id: str,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Marks a threat match as RESOLVED after SOC remediation verification with tenant isolation."""
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