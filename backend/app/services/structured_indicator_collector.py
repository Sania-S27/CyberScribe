"""
Structured Threat Indicator Ingestion Service
----------------------------------------------
Ingests trustworthy, structured network indicators from official/established
threat intelligence sources (initial implementation: abuse.ch Feodo Tracker C2 blocklist),
validates them via Python's `ipaddress` module, constructs `NetworkIndicatorCandidate`
objects with preserved evidence provenance, and evaluates them deterministically
against `AutonomousPolicyEngine` with automated hand-off to `SimulatedFirewallAdapter`.

SAFETY GUARANTEES:
1. No LLMs in the execution or confidence authorization path.
2. Grounded deterministic confidence from feed metadata (online C2 status = 95.0, offline = 88.0).
3. Public IPv4 destination blocking scope only; bogons and protected IPs rejected.
4. Tenant isolation preserved: each tenant evaluates candidates independently.
5. Duplicate active actions deterministically rejected.
6. All containment actions remain strictly SIMULATED; no host firewall execution.
7. Preserves all historical records without database deletion.
"""

import json
import logging
import urllib.request
import urllib.error
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any, Tuple
from sqlalchemy.orm import Session

from app import models
from app.models import ContainmentAction, ContainmentAuditLog
from app.services.containment_policy import (
    AutonomousPolicyEngine,
    NetworkIndicatorCandidate,
    MIN_CONFIDENCE_THRESHOLD,
    MAX_INDICATOR_AGE_DAYS
)
from app.services.firewall_adapter import SimulatedFirewallAdapter

logger = logging.getLogger("structured_indicator_collector")

# Default official structured feed: abuse.ch Feodo Tracker Botnet C2 blocklist
FEODO_TRACKER_JSON_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
SOURCE_NAME = "FEODO_TRACKER_C2"
USER_AGENT = "CyberScribe-Threat-Intelligence/1.0 (+https://github.com/cyberscribe)"


def parse_timestamp(ts_val: Any) -> Optional[datetime]:
    """Safely parses date strings from feed into timezone-naive UTC datetime."""
    if not ts_val:
        return None
    if isinstance(ts_val, datetime):
        if ts_val.tzinfo:
            return ts_val.astimezone(timezone.utc).replace(tzinfo=None)
        return ts_val

    ts_str = str(ts_val).strip()

    # Try ISO 8601 parsing with timezone conversion (handles +00:00, -05:00, Z)
    try:
        iso_str = ts_str.replace("Z", "+00:00")
        parsed_iso = datetime.fromisoformat(iso_str)
        if parsed_iso.tzinfo:
            return parsed_iso.astimezone(timezone.utc).replace(tzinfo=None)
        return parsed_iso
    except (ValueError, TypeError):
        pass

    formats = [
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d",
    ]
    for fmt in formats:
        try:
            parsed = datetime.strptime(ts_str, fmt)
            return parsed
        except ValueError:
            continue
    return None


def calculate_grounded_confidence(record: Dict[str, Any]) -> float:
    """
    Deterministically computes indicator confidence based purely on feed telemetry.
    No LLM inference or synthetic confidence scoring is used.
    Confirmed active C2 nodes receive 95.0%.
    Recently observed offline C2 nodes receive 88.0%.
    Unverified or ambiguous status receive 65.0% (fails 85.0% policy threshold).
    """
    raw_status = str(record.get("status", "")).strip().lower()
    if raw_status == "online":
        return 95.0
    elif raw_status == "offline":
        return 88.0
    return 65.0


def fetch_raw_feed(
    feed_url: str = FEODO_TRACKER_JSON_URL,
    timeout: int = 15,
    headers: Optional[Dict[str, str]] = None
) -> List[Dict[str, Any]]:
    """Fetches raw JSON feed from the structured provider with timeout and error isolation."""
    req_headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    if headers:
        req_headers.update(headers)

    req = urllib.request.Request(feed_url, headers=req_headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            if response.status != 200:
                logger.error(f"Structured feed returned HTTP {response.status} from {feed_url}")
                return []
            content = response.read().decode("utf-8")
            data = json.loads(content)
            if isinstance(data, list):
                return data
            logger.warning("Feed returned JSON that is not a list of records.")
            return []
    except Exception as exc:
        logger.error(f"Failed to fetch structured feed from {feed_url}: {exc}")
        return []


def process_structured_indicator_record(
    record: Dict[str, Any],
    tenant: models.Tenant,
    db: Session,
    source_name: str = SOURCE_NAME
) -> Tuple[bool, Optional[ContainmentAction], str]:
    """
    Parses, validates, and processes a single structured indicator record for a specific tenant.
    Returns: (success: bool, action: Optional[ContainmentAction], reason: str)
    """
    ip_raw = str(record.get("ip_address", "")).strip()

    # If port attached e.g. "1.2.3.4:8080", clean to host IP
    if ":" in ip_raw and not ip_raw.startswith("["):
        ip_parts = ip_raw.split(":")
        ip_raw = ip_parts[0].strip()

    valid, parsed_ip, ip_err = AutonomousPolicyEngine.validate_ip_address(ip_raw)
    if not valid:
        return False, None, ip_err or "REJECTED_INVALID_IP"

    # Observation timestamp resolution (prefer last_online, fallback to first_seen)
    obs_time = parse_timestamp(record.get("last_online")) or parse_timestamp(record.get("first_seen"))
    if not obs_time:
        return False, None, "REJECTED_MISSING_EVIDENCE_TIMESTAMP"

    confidence = calculate_grounded_confidence(record)
    malware_family = record.get("malware") or "Unknown_Botnet_C2"
    as_name = record.get("as_name") or record.get("as_number") or "Unknown_ASN"
    port = record.get("port") or "N/A"

    evidence_summary = (
        f"Grounded botnet C2 observation from {source_name}. "
        f"Malware: {malware_family}, Port: {port}, AS: {as_name}, Status: {record.get('status', 'unknown')}"
    )

    candidate = NetworkIndicatorCandidate(
        indicator_value=str(parsed_ip),
        tenant_id=tenant.id,
        confidence_score=confidence,
        evidence_source=source_name,
        is_structured_ioc=True,
        evidence_summary=evidence_summary,
        observed_at=obs_time,
        indicator_type="ipv4",
        ttl_seconds=3600,
        metadata={
            "feed_source": source_name,
            "malware_family": malware_family,
            "port": port,
            "as_name": as_name,
            "raw_status": record.get("status")
        }
    )

    # 1. Deterministic Policy Evaluation
    qualified, action, reason = AutonomousPolicyEngine.evaluate_candidate(
        candidate=candidate,
        db=db,
        actor=f"STRUCTURED_FEED_{source_name}"
    )

    if not qualified or not action:
        return False, None, reason

    # 2. Automated Hand-off to Active Firewall Adapter
    try:
        from app.services.firewall_adapter import get_containment_adapter
        adapter = get_containment_adapter()
        containment_result = adapter.apply_containment(
            action=action,
            db=db,
            actor=f"STRUCTURED_FEED_{source_name}"
        )
        return True, action, containment_result.get("status", "SIMULATED")
    except Exception as err:
        logger.error(f"Error executing containment for {action.action_id}: {err}")
        return False, action, f"CONTAINMENT_FAILED: {str(err)}"


def ingest_and_process_structured_indicators(
    db: Session,
    raw_indicators: Optional[List[Dict[str, Any]]] = None,
    feed_url: str = FEODO_TRACKER_JSON_URL,
    target_tenant_id: Optional[str] = None,
    source_name: str = SOURCE_NAME
) -> Dict[str, Any]:
    """
    Main orchestrator for structured indicator ingestion.
    Fetches raw feed (or uses provided fixture), iterates tenants, validates indicators,
    evaluates policy, and stages simulated rules.
    """
    try:
        from app.services.osint_collector import source_tracker
        source_tracker.record_start("Feodo Tracker C2")
    except Exception:
        source_tracker = None

    if raw_indicators is None:
        try:
            raw_indicators = fetch_raw_feed(feed_url=feed_url)
        except Exception as feed_err:
            if source_tracker:
                source_tracker.record_failure("Feodo Tracker C2", str(feed_err))
            raise feed_err

    if not raw_indicators:
        if source_tracker:
            source_tracker.record_success("Feodo Tracker C2", 0, 0, 0, None)
        return {
            "status": "COMPLETED",
            "source": source_name,
            "total_indicators_received": 0,
            "qualified_actions": 0,
            "rejected_actions": 0,
            "rejections": {},
            "actions": []
        }

    # Tenant target resolution
    if target_tenant_id:
        tenants = db.query(models.Tenant).filter(models.Tenant.id == target_tenant_id).all()
    else:
        tenants = db.query(models.Tenant).all()

    if not tenants:
        if source_tracker:
            source_tracker.record_success("Feodo Tracker C2", 0, 0, len(raw_indicators), "No registered tenants")
        return {
            "status": "COMPLETED",
            "source": source_name,
            "message": "No registered tenants found for containment evaluation.",
            "total_indicators_received": len(raw_indicators),
            "qualified_actions": 0,
            "rejected_actions": 0,
            "rejections": {"NO_ACTIVE_TENANTS": len(raw_indicators)},
            "actions": []
        }

    qualified_count = 0
    rejected_count = 0
    rejections_breakdown: Dict[str, int] = {}
    staged_actions = []

    for tenant in tenants:
        for item in raw_indicators:
            success, action, outcome = process_structured_indicator_record(
                record=item,
                tenant=tenant,
                db=db,
                source_name=source_name
            )

            if success and action:
                qualified_count += 1
                staged_actions.append({
                    "action_id": action.action_id,
                    "tenant_id": tenant.id,
                    "tenant_name": tenant.company_name,
                    "indicator": action.indicator_value,
                    "status": action.status,
                    "applied_at": action.applied_at.isoformat() if action.applied_at else None,
                    "expires_at": action.expires_at.isoformat() if action.expires_at else None,
                    "is_simulated": True
                })
            else:
                rejected_count += 1
                rejections_breakdown[outcome] = rejections_breakdown.get(outcome, 0) + 1

    if source_tracker:
        last_desc = f"{qualified_count} qualified IOCs" if qualified_count else "Telemetry sweep complete"
        source_tracker.record_success(
            "Feodo Tracker C2",
            new_count=qualified_count,
            duplicates_count=rejected_count,
            last_item=last_desc
        )

    return {
        "status": "COMPLETED",
        "source": source_name,
        "total_indicators_received": len(raw_indicators),
        "tenants_evaluated": len(tenants),
        "qualified_actions": qualified_count,
        "rejected_actions": rejected_count,
        "rejection_breakdown": rejections_breakdown,
        "actions": staged_actions
    }
