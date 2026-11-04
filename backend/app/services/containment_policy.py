"""
Autonomous Containment Policy Engine (Phase 1)
-----------------------------------------------
Implements deterministic evaluation of structured IPv4 network indicators
for autonomous destination-IP blocking.

CRITICAL SAFETY SAFEGUARDS:
1. No LLM in the privileged execution path: decisions are strictly deterministic.
2. Complete separation of software vulnerability assessment (CVE) from network indicator validation.
3. Network blocking requires validated, high-confidence (>= 85.0%), recent (<= 7 days)
   indicators from trusted sources with an eligible registered tenant target.
4. An AFFECTED CVE alone NEVER authorizes blocking an arbitrary IP.
5. An independently verified malicious indicator does NOT require an AFFECTED CVE match.
6. Rejects NEEDS_REVIEW findings unless independent corroborated network evidence satisfies policy.
7. Rejects NOT_AFFECTED findings as vulnerability-remediation triggers.
8. Rigorous IP validation using `ipaddress`: rejects loopback, private, multicast,
   link-local, reserved, unspecified, broadcast, and configured protected infrastructure.
9. Rejects arbitrary IPs merely mentioned in RSS or untrusted articles without structured IOC evidence.
10. All policy decisions (qualifications and rejections) are immutably recorded in audit logs.
"""

import ipaddress
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Optional, List, Dict, Any, Tuple
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError

from app import models
from app.models import ContainmentAction, ContainmentAuditLog


# Explicit Policy Thresholds
MIN_CONFIDENCE_THRESHOLD = 85.0
MAX_INDICATOR_AGE_DAYS = 7
DEFAULT_CONTAINMENT_TTL_SECONDS = 3600  # 1 hour
ACTIVE_CONTAINMENT_STATUSES = [
    'PENDING', 'SIMULATED', 'DISPATCHED', 'RECEIVED', 'APPLIED', 'VERIFIED'
]

# Explicit Trusted Intelligence / Telemetry Sources
TRUSTED_EVIDENCE_SOURCES = {
    "CISA_KEV",
    "CISA_IOC",
    "SURICATA_ALERT",
    "MISP_VERIFIED",
    "ALIENVAULT_PULSE_VERIFIED",
    "CAMPUS_SOC_VERIFIED",
    "STRUCTURED_THREAT_FEED",
    "NIST_NVD_VERIFIED",
    "FEODO_TRACKER_C2"
}

# Configured Protected Addresses (Critical Internet & Enterprise Infrastructure)
PROTECTED_IPV4_HOSTS = {
    ipaddress.IPv4Address("1.1.1.1"),        # Cloudflare Primary DNS
    ipaddress.IPv4Address("1.0.0.1"),        # Cloudflare Secondary DNS
    ipaddress.IPv4Address("8.8.8.8"),        # Google Primary DNS
    ipaddress.IPv4Address("8.8.4.4"),        # Google Secondary DNS
    ipaddress.IPv4Address("9.9.9.9"),        # Quad9 Primary DNS
    ipaddress.IPv4Address("149.112.112.112"),# Quad9 Secondary DNS
    ipaddress.IPv4Address("208.67.222.222"), # OpenDNS Primary
    ipaddress.IPv4Address("208.67.220.220")  # OpenDNS Secondary
}

# Sensitive / Secret Keys to Redact from Audit Details
SENSITIVE_KEYS = {
    "auth_token", "password", "secret", "token", "api_key",
    "kms_key_arn", "authorization", "bearer", "private_key"
}


def sanitize_audit_details(data: Any) -> Any:
    """Recursively redacts sensitive tokens and secret keys from audit log dictionaries."""
    if isinstance(data, dict):
        sanitized = {}
        for k, v in data.items():
            if any(s in k.lower() for s in SENSITIVE_KEYS):
                sanitized[k] = "[REDACTED_SECRET]"
            else:
                sanitized[k] = sanitize_audit_details(v)
        return sanitized
    elif isinstance(data, list):
        return [sanitize_audit_details(elem) for elem in data]
    return data


@dataclass
class NetworkIndicatorCandidate:
    """Structured input candidate for deterministic containment policy evaluation."""
    indicator_value: str
    tenant_id: str
    confidence_score: float
    evidence_source: str
    is_structured_ioc: bool
    evidence_summary: str = ""
    observed_at: Optional[datetime] = None
    indicator_type: str = "ipv4"
    threat_report_id: Optional[str] = None
    threat_match_id: Optional[str] = None
    vulnerability_status: Optional[str] = None  # e.g., AFFECTED, NOT_AFFECTED, NEEDS_REVIEW
    ttl_seconds: int = DEFAULT_CONTAINMENT_TTL_SECONDS
    metadata: Dict[str, Any] = field(default_factory=dict)


class AutonomousPolicyEngine:
    """Deterministic Autonomous Response Policy Engine for Phase 1 containment."""

    @classmethod
    def validate_ip_address(cls, ip_str: str) -> Tuple[bool, Optional[ipaddress.IPv4Address], Optional[str]]:
        """
        Validates an IPv4 address string against strict public destination-blocking criteria.
        Rejects malformed, non-IPv4, loopback, private, multicast, link-local,
        reserved, unspecified, broadcast, and protected infrastructure addresses.
        """
        if not ip_str or not isinstance(ip_str, str):
            return False, None, "REJECTED_EMPTY_OR_NON_STRING_IP"

        clean_ip = ip_str.strip()

        try:
            addr = ipaddress.ip_address(clean_ip)
        except ValueError:
            return False, None, "REJECTED_MALFORMED_IP_ADDRESS"

        if not isinstance(addr, ipaddress.IPv4Address):
            return False, None, "REJECTED_NON_IPV4_ADDRESS_FAMILY"

        if addr.is_loopback:
            return False, None, "REJECTED_LOOPBACK_ADDRESS"

        if clean_ip == "255.255.255.255":
            return False, None, "REJECTED_BROADCAST_ADDRESS"

        if addr.is_unspecified:
            return False, None, "REJECTED_UNSPECIFIED_ADDRESS"

        if addr.is_multicast:
            return False, None, "REJECTED_MULTICAST_ADDRESS"

        if addr.is_link_local:
            return False, None, "REJECTED_LINK_LOCAL_ADDRESS"

        if addr.is_reserved:
            return False, None, "REJECTED_RESERVED_ADDRESS"

        if addr.is_private:
            from app.services.windows_firewall_adapter import is_authorized_private_ip
            if not is_authorized_private_ip(clean_ip):
                return False, None, "REJECTED_PRIVATE_ADDRESS"

        if addr in PROTECTED_IPV4_HOSTS:
            return False, None, "REJECTED_PROTECTED_INFRASTRUCTURE_IP"

        return True, addr, None

    @classmethod
    def resolve_containment_direction(cls, action: ContainmentAction) -> Optional[str]:
        """
        Distinguishes malicious inbound source IPs from outbound C2 destinations.
        Returns:
          - 'in': for inbound attack/exploit sources targeting local services (e.g. port 8000)
          - 'out': for outbound C2 botnet destinations (e.g. Feodo Tracker C2, malware beacons)
          - None: if the direction cannot be established from evidence or policy
        """
        # 1. Inspect explicit action_type
        atype = (getattr(action, "action_type", "") or "").upper()
        if atype in ("BLOCK_INBOUND_PORT_8000", "BLOCK_INBOUND_IPV4", "BLOCK_INGRESS_IPV4"):
            return "in"
        if atype in ("BLOCK_IPV4_DESTINATION", "BLOCK_EGRESS_IPV4", "BLOCK_OUTBOUND_IPV4", "BLOCK_C2_DESTINATION"):
            return "out"

        # 2. Inspect rule_spec if already annotated
        rule_spec = getattr(action, "rule_spec", None) or {}
        spec_dir = str(rule_spec.get("direction", "")).lower()
        if spec_dir in ("in", "inbound", "ingress"):
            return "in"
        if spec_dir in ("out", "outbound", "egress"):
            return "out"

        # 3. Inspect associated threat report, candidate metadata, and policy context
        report = getattr(action, "threat_report", None)
        spec_summary = str(rule_spec.get("evidence_summary", "") if isinstance(rule_spec, dict) else "")
        spec_source = str(rule_spec.get("evidence_source", "") if isinstance(rule_spec, dict) else "")
        spec_feed = str(rule_spec.get("feed_source", "") if isinstance(rule_spec, dict) else "")
        evidence_text = f"{action.policy_rule or ''} {getattr(action, 'execution_output', '') or ''} {getattr(action, 'evidence_summary', '') or ''} {spec_summary} {spec_source} {spec_feed}"
        if report:
            evidence_text += f" {report.title or ''} {report.summary or ''} {getattr(report, 'source_url', '') or ''}"
        evidence_lower = evidence_text.lower()

        # Specific directional indicator patterns
        inbound_patterns = (
            "payload delivered from", "attack from", "exploit from", "exploit traffic from",
            "traffic from", "exploit payload from", "incoming from", "scanner from",
            "brute force from", "inbound", "ingress", "remote exploit", "request smuggling"
        )
        outbound_patterns = (
            "feodo", "beacon to", "beaconing to", "exfiltration to", "callback to",
            "c2 destination", "outbound", "egress", "botnet c2", "command and control server"
        )

        has_inbound = any(k in evidence_lower for k in inbound_patterns)
        has_outbound = any(k in evidence_lower for k in outbound_patterns)

        # Explicit delivery/attack from remote source takes priority for inbound service defense
        if has_inbound and not any(k in evidence_lower for k in ("beacon to", "beaconing to", "exfiltration to", "callback to")):
            return "in"
        if has_outbound and not has_inbound:
            return "out"

        return None

    @classmethod
    def evaluate_candidate(
        cls,
        candidate: NetworkIndicatorCandidate,
        db: Session,
        actor: str = "AUTONOMOUS_POLICY_ENGINE"
    ) -> Tuple[bool, Optional[ContainmentAction], str]:
        """
        Deterministically evaluates a network indicator candidate against policy rules.
        Creates persistent ContainmentAction and ContainmentAuditLog records.
        Returns: (qualified: bool, action: Optional[ContainmentAction], reason: str)
        """
        now = datetime.now(timezone.utc).replace(tzinfo=None)

        # 1. Tenant Verification
        tenant = db.query(models.Tenant).filter(models.Tenant.id == candidate.tenant_id).first()
        if not tenant:
            reason = "REJECTED_INVALID_OR_MISSING_TENANT"
            cls._record_audit_log(
                db=db,
                tenant_id=candidate.tenant_id,
                action_id=None,
                event_type="POLICY_REJECTION",
                actor=actor,
                details={"reason": reason, "candidate_ip": candidate.indicator_value}
            )
            return False, None, reason

        # 2. Indicator Type & IP Scope Validation
        if candidate.indicator_type.lower() != "ipv4":
            reason = f"REJECTED_UNSUPPORTED_INDICATOR_TYPE_{candidate.indicator_type.upper()}"
            cls._record_audit_log(
                db=db,
                tenant_id=candidate.tenant_id,
                action_id=None,
                event_type="POLICY_REJECTION",
                actor=actor,
                details={"reason": reason, "indicator_type": candidate.indicator_type}
            )
            return False, None, reason

        valid_ip, parsed_ip, ip_error = cls.validate_ip_address(candidate.indicator_value)
        if not valid_ip:
            cls._record_audit_log(
                db=db,
                tenant_id=candidate.tenant_id,
                action_id=None,
                event_type="POLICY_REJECTION",
                actor=actor,
                details={"reason": ip_error, "candidate_ip": candidate.indicator_value}
            )
            return False, None, ip_error

        # 3. Separation of Vulnerability Remediation vs Network Containment
        # Rule: NOT_AFFECTED must be rejected as vulnerability-remediation trigger
        if candidate.vulnerability_status == "NOT_AFFECTED":
            reason = "REJECTED_NOT_AFFECTED_TRIGGER"
            cls._record_audit_log(
                db=db,
                tenant_id=candidate.tenant_id,
                action_id=None,
                event_type="POLICY_REJECTION",
                actor=actor,
                details={
                    "reason": reason,
                    "explanation": "NOT_AFFECTED software findings must not trigger remediation actions.",
                    "candidate_ip": candidate.indicator_value
                }
            )
            return False, None, reason

        # Rule: NEEDS_REVIEW findings rejected for automatic blocking unless independent corroborated network evidence satisfies policy
        has_independent_corroboration = (
            candidate.is_structured_ioc and
            candidate.confidence_score >= MIN_CONFIDENCE_THRESHOLD and
            candidate.evidence_source in TRUSTED_EVIDENCE_SOURCES
        )
        if candidate.vulnerability_status == "NEEDS_REVIEW" and not has_independent_corroboration:
            reason = "REJECTED_NEEDS_REVIEW_WITHOUT_INDEPENDENT_CORROBORATION"
            cls._record_audit_log(
                db=db,
                tenant_id=candidate.tenant_id,
                action_id=None,
                event_type="POLICY_REJECTION",
                actor=actor,
                details={
                    "reason": reason,
                    "vulnerability_status": "NEEDS_REVIEW",
                    "explanation": "NEEDS_REVIEW findings cannot trigger automatic containment without independent high-confidence network corroboration."
                }
            )
            return False, None, reason

        # Rule: An AFFECTED CVE alone must never authorize blocking an arbitrary IP without verified network evidence
        if not candidate.is_structured_ioc:
            reason = "REJECTED_UNSTRUCTURED_OR_ARBITRARY_INDICATOR"
            cls._record_audit_log(
                db=db,
                tenant_id=candidate.tenant_id,
                action_id=None,
                event_type="POLICY_REJECTION",
                actor=actor,
                details={
                    "reason": reason,
                    "explanation": "Network blocking requires structured, validated IOC evidence. Arbitrary text/RSS mentions cannot authorize blocking."
                }
            )
            return False, None, reason

        # 4. Evidence Source Trust Validation
        if candidate.evidence_source not in TRUSTED_EVIDENCE_SOURCES:
            reason = f"REJECTED_UNTRUSTED_EVIDENCE_SOURCE_{candidate.evidence_source or 'UNKNOWN'}"
            cls._record_audit_log(
                db=db,
                tenant_id=candidate.tenant_id,
                action_id=None,
                event_type="POLICY_REJECTION",
                actor=actor,
                details={"reason": reason, "evidence_source": candidate.evidence_source}
            )
            return False, None, reason

        # 5. Deterministic Confidence Threshold
        if candidate.confidence_score < MIN_CONFIDENCE_THRESHOLD:
            reason = f"REJECTED_INSUFFICIENT_CONFIDENCE_{candidate.confidence_score:.1f}_BELOW_{MIN_CONFIDENCE_THRESHOLD:.1f}"
            cls._record_audit_log(
                db=db,
                tenant_id=candidate.tenant_id,
                action_id=None,
                event_type="POLICY_REJECTION",
                actor=actor,
                details={
                    "reason": reason,
                    "confidence_score": candidate.confidence_score,
                    "required_threshold": MIN_CONFIDENCE_THRESHOLD
                }
            )
            return False, None, reason

        # 6. Recency / Age Validation
        if not candidate.observed_at:
            reason = "REJECTED_MISSING_EVIDENCE_TIMESTAMP"
            cls._record_audit_log(
                db=db,
                tenant_id=candidate.tenant_id,
                action_id=None,
                event_type="POLICY_REJECTION",
                actor=actor,
                details={"reason": reason}
            )
            return False, None, reason

        # Normalize observed_at if tz-aware
        obs_time = candidate.observed_at.replace(tzinfo=None) if candidate.observed_at.tzinfo else candidate.observed_at
        cutoff = now - timedelta(days=MAX_INDICATOR_AGE_DAYS)
        if obs_time < cutoff:
            reason = f"REJECTED_EXPIRED_INDICATOR_EVIDENCE_AGE_EXCEEDS_{MAX_INDICATOR_AGE_DAYS}_DAYS"
            cls._record_audit_log(
                db=db,
                tenant_id=candidate.tenant_id,
                action_id=None,
                event_type="POLICY_REJECTION",
                actor=actor,
                details={
                    "reason": reason,
                    "observed_at": obs_time.isoformat(),
                    "max_age_days": MAX_INDICATOR_AGE_DAYS
                }
            )
            return False, None, reason

        if obs_time > (now + timedelta(hours=1)):
            reason = "REJECTED_INVALID_FUTURE_TIMESTAMP"
            cls._record_audit_log(
                db=db,
                tenant_id=candidate.tenant_id,
                action_id=None,
                event_type="POLICY_REJECTION",
                actor=actor,
                details={"reason": reason, "observed_at": obs_time.isoformat()}
            )
            return False, None, reason

        # 7. Duplicate Active Action Prevention (Tenant Isolation)
        # Check if an active action already exists for this tenant & IP
        existing_action = db.query(ContainmentAction).filter(
            ContainmentAction.tenant_id == candidate.tenant_id,
            ContainmentAction.indicator_value == str(parsed_ip),
            ContainmentAction.status.in_(ACTIVE_CONTAINMENT_STATUSES),
            ContainmentAction.expires_at > now
        ).first()

        if existing_action:
            reason = f"REJECTED_DUPLICATE_ACTIVE_CONTAINMENT_ACTION_{existing_action.action_id}"
            cls._record_audit_log(
                db=db,
                tenant_id=candidate.tenant_id,
                action_id=existing_action.id,
                event_type="POLICY_REJECTION",
                actor=actor,
                details={
                    "reason": reason,
                    "existing_action_id": existing_action.action_id,
                    "existing_status": existing_action.status
                }
            )
            return False, None, reason

        # 8. All Policy Checks Passed -> QUALIFIED
        action_uuid = str(uuid.uuid4())
        human_action_id = f"act-auto-{action_uuid[:12]}"
        ttl = max(60, min(candidate.ttl_seconds or DEFAULT_CONTAINMENT_TTL_SECONDS, 86400 * 7))

        action = ContainmentAction(
            id=action_uuid,
            action_id=human_action_id,
            tenant_id=candidate.tenant_id,
            threat_report_id=candidate.threat_report_id,
            threat_match_id=candidate.threat_match_id,
            indicator_value=str(parsed_ip),
            indicator_type="ipv4",
            action_type="BLOCK_IPV4_DESTINATION",
            policy_decision="QUALIFIED",
            policy_rule="deterministic_autonomous_destination_blocking_v1",
            status="PENDING",
            ttl_seconds=ttl,
            expires_at=now + timedelta(seconds=ttl),
            rule_spec={
                "action": "DROP_EGRESS_IPV4",
                "direction": "egress",
                "destination_ip": str(parsed_ip),
                "is_simulated": True,
                "confidence_score": candidate.confidence_score,
                "evidence_source": candidate.evidence_source
            }
        )
        db.add(action)
        try:
            db.flush()
        except IntegrityError:
            db.rollback()
            # Fetch the conflicting active action created concurrently
            conflicting_action = db.query(ContainmentAction).filter(
                ContainmentAction.tenant_id == candidate.tenant_id,
                ContainmentAction.indicator_value == str(parsed_ip),
                ContainmentAction.status.in_(ACTIVE_CONTAINMENT_STATUSES)
            ).first()
            action_id_str = conflicting_action.action_id if conflicting_action else "CONCURRENT"
            reason = f"REJECTED_DUPLICATE_ACTIVE_CONTAINMENT_ACTION_{action_id_str}"
            cls._record_audit_log(
                db=db,
                tenant_id=candidate.tenant_id,
                action_id=conflicting_action.id if conflicting_action else None,
                event_type="POLICY_REJECTION",
                actor=actor,
                details={
                    "reason": reason,
                    "concurrency_conflict": True,
                    "candidate_ip": candidate.indicator_value
                }
            )
            return False, None, reason

        cls._record_audit_log(
            db=db,
            tenant_id=candidate.tenant_id,
            action_id=action.id,
            event_type="POLICY_EVALUATION",
            actor=actor,
            new_status="PENDING",
            details={
                "decision": "QUALIFIED",
                "action_id": action.action_id,
                "target_ip": str(parsed_ip),
                "confidence_score": candidate.confidence_score,
                "evidence_source": candidate.evidence_source,
                "ttl_seconds": ttl
            }
        )
        db.commit()

        return True, action, "QUALIFIED"

    @classmethod
    def _record_audit_log(
        cls,
        db: Session,
        tenant_id: str,
        action_id: Optional[str],
        event_type: str,
        actor: str,
        details: Dict[str, Any],
        previous_status: Optional[str] = None,
        new_status: Optional[str] = None
    ) -> ContainmentAuditLog:
        """Creates an immutable, sanitized audit entry."""
        sanitized = sanitize_audit_details(details)
        log_entry = ContainmentAuditLog(
            id=str(uuid.uuid4()),
            action_id=action_id,
            tenant_id=tenant_id,
            event_type=event_type,
            actor=actor,
            previous_status=previous_status,
            new_status=new_status,
            details=sanitized
        )
        db.add(log_entry)
        db.commit()
        return log_entry
