"""
CyberScribe Autonomous Vulnerability Response Orchestrator
-----------------------------------------------------------
Connects the end-to-end autonomous vulnerability response lifecycle:
SBOM match -> vulnerability incident -> company notification -> justified containment ->
fixed-version discovery -> notification or authorized automatic patch -> verification -> safe release of containment.

SECURITY SAFEGUARDS:
1. Grounded Grounding: Vulnerabilities match authoritative package names and version constraints.
2. Containment Justification: Vulnerability match alone NEVER triggers an IP block; requires supporting
   malicious IP or incident evidence.
3. Policy Enforcement: Respects per-company policies ('NOTIFY' vs 'AUTO_PATCH').
4. Simulation Safety: Patching and containment default to simulation mode unless explicitly authorized.
5. Verification Gate: Containment is released ONLY when the patch is verified and vulnerability evaluates to NOT_AFFECTED.
6. Multi-Tenant Isolation: Every step validates tenant ownership.
"""

import os
import re
import ipaddress
import uuid
import logging
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List, Tuple
from sqlalchemy.orm import Session

from app.models import (
    Tenant,
    AssetComponent,
    ThreatReport,
    ThreatMatch,
    ContainmentAction,
    ContainmentAuditLog,
    PatchProposal,
    PatchAuditLog
)
from app.services.version_matcher import (
    evaluate_version_applicability,
    normalize_package_name
)
from app.services.windows_firewall_adapter import (
    WindowsFirewallAdapter,
    validate_ip_for_containment,
    DOCUMENTATION_NETWORKS,
    RFC1918_PRIVATE_NETWORKS,
    LAB_FEDORA_HOST_ONLY_IP,
    is_lab_fedora_containment_allowed,
    is_authorized_private_ip
)
from app.services.firewall_adapter import get_containment_adapter, get_adapter_for_action
from app.services.fixed_version_service import FixedVersionDiscoveryService
from app.services.patch_adapter import PatchManagementAdapter
from app.services.notification_service import NotificationService
from app.services.containment_policy import AutonomousPolicyEngine

logger = logging.getLogger("AutonomousResponseOrchestrator")


class AutonomousResponseOrchestrator:
    """Orchestrates end-to-end vulnerability lifecycle from match to containment release."""

    @classmethod
    def is_live_patching_enabled(cls) -> bool:
        """Returns True if live host patching is enabled via PATCH_ADAPTER_MODE='live', 'live_windows', or 'live_fedora'."""
        mode = os.getenv("PATCH_ADAPTER_MODE", "simulated").strip().lower()
        return mode in ("live", "live_windows", "live_fedora")

    @classmethod
    def is_live_containment_enabled(cls) -> bool:
        """Returns True if live host firewall operations are enabled."""
        mode = os.getenv("CONTAINMENT_ADAPTER_MODE", "simulated").strip().lower()
        return mode in (
            "windows_firewall", "windows_defender", "windows_live", "windows",
            "fedora_nftables", "fedora", "live"
        )

    @classmethod
    def resolve_firewall_adapter(
        cls,
        tenant: Optional[Tenant] = None,
        asset: Optional[AssetComponent] = None,
        mode_override: Optional[str] = None
    ):
        """
        Dynamically selects the appropriate firewall adapter class.
        1. Explicit mode_override if provided.
        2. Configured CONTAINMENT_ADAPTER_MODE if set.
        3. Platform detection from tenant tech_stack or asset environment:
           - Linux/Fedora/CentOS/RHEL -> FedoraNftablesAdapter
           - Windows/IIS/Campus Guide -> WindowsFirewallAdapter
        4. Safe default -> SimulatedFirewallAdapter
        """
        if mode_override:
            return get_containment_adapter(mode_override)

        env_mode = os.getenv("CONTAINMENT_ADAPTER_MODE")
        if env_mode:
            return get_containment_adapter(env_mode)

        stack = (tenant.tech_stack if tenant and tenant.tech_stack else "").lower()
        env_str = (asset.environment if asset and asset.environment else "").lower()

        if any(k in stack or k in env_str for k in ("fedora", "nftables", "rhel", "centos")):
            from app.services.fedora_nftables_adapter import FedoraNftablesAdapter
            return FedoraNftablesAdapter
        elif "linux" in stack and not any(k in stack for k in ("windows", "fastapi")):
            from app.services.fedora_nftables_adapter import FedoraNftablesAdapter
            return FedoraNftablesAdapter

        # Default host environment is Windows Defender Firewall (Campus Guide port 8000)
        from app.services.windows_firewall_adapter import WindowsFirewallAdapter
        return WindowsFirewallAdapter

    @classmethod
    def resolve_package_manager_for_asset(
        cls,
        asset: Optional[AssetComponent] = None,
        tenant: Optional[Tenant] = None
    ) -> str:
        """
        Resolves package manager ('pip', 'dnf', 'apt', 'yum') for target asset.
        Supports Python/Campus Guide, Fedora/RHEL, and Debian/Ubuntu targets.
        """
        env_pm = os.getenv("DEFAULT_PACKAGE_MANAGER")
        if env_pm and env_pm in ("pip", "dnf", "apt", "yum"):
            return env_pm

        stack = (tenant.tech_stack if tenant and tenant.tech_stack else "").lower()
        pkg_name = (asset.software_name if asset and asset.software_name else "").lower()

        if any(k in stack for k in ("fedora", "rhel", "centos")):
            return "dnf"
        if any(k in stack for k in ("ubuntu", "debian")):
            return "apt"

        python_pkgs = {
            "fastapi", "uvicorn", "pydantic", "sqlalchemy", "requests",
            "flask", "django", "urllib3", "cryptography", "numpy", "pandas",
            "pytest", "feedparser", "httpx", "starlette", "jinja2"
        }
        if pkg_name in python_pkgs or "python" in stack:
            return "pip"

        return "pip"

    @classmethod
    def _is_safe_threat_indicator_ip(cls, cand: str) -> bool:
        """Returns True if cand is a valid public IPv4 address or an RFC 5737 documentation test IP."""
        if not cand or not isinstance(cand, str):
            return False
        try:
            addr = ipaddress.ip_address(cand.strip())
            if not isinstance(addr, ipaddress.IPv4Address):
                return False
            if (
                addr.is_loopback
                or addr.is_unspecified
                or addr.is_multicast
                or addr.is_link_local
                or str(addr) == "255.255.255.255"
            ):
                return False
            # Explicitly authorized private IPs (Fedora lab host-only IP or configured enterprise private indicators)
            if is_authorized_private_ip(str(addr)):
                return True
            if any(addr in net for net in RFC1918_PRIVATE_NETWORKS):
                return False
            if addr.is_reserved:
                # Permitted only if within RFC 5737 documentation networks used for test fixtures
                return any(addr in net for net in DOCUMENTATION_NETWORKS)
            return True
        except Exception:
            return False

    @classmethod
    def extract_malicious_ip_from_report(cls, threat_report: Optional[ThreatReport]) -> Optional[str]:
        """
        Safely extracts a validated malicious IPv4 address from STIX bundle or threat advisory text.
        Rejects loopback, private, broadcast, multicast, link-local, and unspecified IPs.
        """
        if not threat_report:
            return None

        # 1. Inspect STIX bundle indicator objects
        bundle = threat_report.stix_bundle
        if isinstance(bundle, dict):
            objects = bundle.get("objects", [])
            for obj in objects:
                if not isinstance(obj, dict):
                    continue
                pattern = obj.get("pattern", "")
                m = re.search(r"ipv4-addr:value\s*=\s*'([0-9\.]+)'", pattern)
                if m:
                    cand = m.group(1)
                    if cls._is_safe_threat_indicator_ip(cand):
                        try:
                            return validate_ip_for_containment(cand, allow_reserved=True)
                        except Exception:
                            pass
                if obj.get("type") in ("indicator", "ipv4-addr"):
                    cand = obj.get("value") or obj.get("name")
                    if cand and cls._is_safe_threat_indicator_ip(cand):
                        try:
                            return validate_ip_for_containment(cand, allow_reserved=True)
                        except Exception:
                            pass

        # 2. Inspect title and summary text
        text = f"{threat_report.title or ''} {threat_report.summary or ''}"
        ip_candidates = re.findall(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", text)
        for cand in ip_candidates:
            if not cls._is_safe_threat_indicator_ip(cand):
                continue
            try:
                return validate_ip_for_containment(cand, allow_reserved=True)
            except Exception:
                continue

        return None

    @classmethod
    def is_tenant_containment_authorized(cls, tenant: Optional[Tenant]) -> Tuple[bool, Optional[str]]:
        """
        Evaluates whether the tenant is registered, active, and authorized for autonomous containment.
        Fails closed if tenant is missing or inactive/suspended.
        """
        if not tenant:
            return False, "TENANT_NOT_FOUND"
        sub_status = getattr(tenant, "subscription_status", "active") or "active"
        if str(sub_status).lower() in ("suspended", "disabled", "inactive"):
            return False, f"TENANT_CONTAINMENT_PROHIBITED_STATUS_{str(sub_status).upper()}"
        return True, None

    @classmethod
    def is_asset_containment_authorized(
        cls,
        asset: Optional[AssetComponent],
        tenant: Optional[Tenant]
    ) -> Tuple[bool, Optional[str]]:
        """
        Determines if the target asset is registered, tenant-owned, and authorized
        for autonomous containment execution.
        Rejects unmanaged, unsupported, air-gapped, or tenant-mismatched assets.
        """
        if not asset:
            return False, "ASSET_NOT_FOUND"
        if not tenant or asset.tenant_id != tenant.id:
            return False, "UNAUTHORIZED_TENANT_ASSET_MISMATCH"

        env_clean = (asset.environment or "").strip().lower()
        unsupported_keywords = (
            "unsupported", "unmanaged", "airgapped", "manual_only",
            "unsupported_os", "unauthorized", "legacy_isolated", "external", "isolated"
        )
        if any(k in env_clean for k in unsupported_keywords):
            return False, f"UNSUPPORTED_TARGET_ENVIRONMENT_{env_clean.upper()}"

        return True, None

    @classmethod
    def correlate_sbom_and_create_incident(
        cls,
        db: Session,
        tenant_id: str,
        threat_report_id: str,
        supporting_malicious_ip: Optional[str] = None,
        force_auto_patch: bool = False,
        is_simulated: Optional[bool] = None
    ) -> Dict[str, Any]:
        """
        Phase 2 & 3:
        - Correlates threat report against tenant's registered SBOM components.
        - Idempotently creates or updates ThreatMatch incident with linked asset_component_id.
        - Dispatches company notification.
        - If supporting malicious IP evidence is provided, stages/applies justified containment.
        """
        tenant = db.query(Tenant).filter(Tenant.id == tenant_id).first()
        if not tenant:
            raise ValueError(f"Tenant '{tenant_id}' not found.")

        threat_report = db.query(ThreatReport).filter(ThreatReport.id == threat_report_id).first()
        if not threat_report:
            raise ValueError(f"Threat report '{threat_report_id}' not found.")

        assets = db.query(AssetComponent).filter(AssetComponent.tenant_id == tenant.id).all()
        corpus = f"{threat_report.title or ''} {threat_report.summary or ''}"

        matched_asset = None
        match_classification = "NOT_AFFECTED"
        match_confidence = 0.0
        match_reason = ""

        # Evaluate each asset
        for asset in assets:
            cls_out, conf, reason = evaluate_version_applicability(
                installed_version=asset.software_version,
                threat_text=corpus,
                pkg_name=asset.software_name
            )
            if cls_out == "AFFECTED":
                matched_asset = asset
                match_classification = cls_out
                match_confidence = conf
                match_reason = reason
                break
            elif cls_out == "NEEDS_REVIEW" and not matched_asset:
                matched_asset = asset
                match_classification = cls_out
                match_confidence = conf
                match_reason = reason

        if not matched_asset or match_classification == "NOT_AFFECTED":
            return {
                "status": "NO_MATCH",
                "tenant_id": tenant.id,
                "tenant_name": tenant.company_name,
                "cve_id": threat_report.cve_id,
                "message": "No affected SBOM components identified for this tenant."
            }

        # Idempotently find or create ThreatMatch
        match = db.query(ThreatMatch).filter(
            ThreatMatch.tenant_id == tenant.id,
            ThreatMatch.threat_report_id == threat_report.id,
            ThreatMatch.asset_component_id == matched_asset.id
        ).first()

        if not match:
            # Also check legacy match without asset_component_id
            match = db.query(ThreatMatch).filter(
                ThreatMatch.tenant_id == tenant.id,
                ThreatMatch.threat_report_id == threat_report.id
            ).first()

        if not match:
            match = ThreatMatch(
                id=str(uuid.uuid4()),
                tenant_id=tenant.id,
                asset_component_id=matched_asset.id,
                threat_report_id=threat_report.id,
                status="OPEN",
                ai_confidence_score=match_confidence,
                ai_matching_reason=match_reason
            )
            db.add(match)
            db.commit()
            db.refresh(match)
        else:
            # Ensure asset_component_id is linked
            if not match.asset_component_id:
                match.asset_component_id = matched_asset.id
                db.commit()

        # Step 2: Company Notification of confirmed incident
        raw_policy = getattr(tenant, "remediation_policy", "NOTIFY") or "NOTIFY"
        remediation_policy = "AUTO_PATCH" if str(raw_policy).strip().upper() == "AUTO_PATCH" else "NOTIFY"
        notif_result = NotificationService.send_incident_notification(
            db=db,
            tenant=tenant,
            event_type="VULNERABILITY_CONFIRMED",
            threat_report=threat_report,
            asset=matched_asset,
            remediation_policy=remediation_policy,
            additional_evidence=match_reason
        )

        # Step 3: Justified Containment (Phase 3)
        # SAFETY RULE: Vulnerability match alone must NOT trigger an IP block without supporting malicious IP!
        target_ip = supporting_malicious_ip or cls.extract_malicious_ip_from_report(threat_report)
        containment_result = None
        if target_ip:
            # 1. Tenant containment authorization check
            is_tenant_auth, tenant_auth_reason = cls.is_tenant_containment_authorized(tenant)
            is_authorized, auth_reason = cls.is_asset_containment_authorized(matched_asset, tenant)

            if not is_tenant_auth:
                logger.warning(
                    f"Containment suppressed for tenant '{tenant.company_name}': {tenant_auth_reason}."
                )
                AutonomousPolicyEngine._record_audit_log(
                    db=db,
                    tenant_id=tenant.id,
                    action_id=None,
                    event_type="CONTAINMENT_SUPPRESSED_UNAUTHORIZED_TENANT",
                    actor="AUTONOMOUS_ORCHESTRATOR",
                    details={"reason": tenant_auth_reason, "candidate_ip": target_ip}
                )
                containment_result = {
                    "status": "REJECTED",
                    "action_id": None,
                    "target_ip": target_ip,
                    "direction": None,
                    "error": tenant_auth_reason,
                    "requires_further_evidence_or_approval": True
                }
            elif not is_authorized:
                logger.warning(
                    f"Containment suppressed for asset '{matched_asset.software_name}' (tenant: {tenant.id}): {auth_reason}. Queued for review."
                )
                AutonomousPolicyEngine._record_audit_log(
                    db=db,
                    tenant_id=tenant.id,
                    action_id=None,
                    event_type="CONTAINMENT_SUPPRESSED_UNSUPPORTED_OR_UNAUTHORIZED",
                    actor="AUTONOMOUS_ORCHESTRATOR",
                    details={
                        "reason": auth_reason,
                        "asset_id": matched_asset.id,
                        "asset_name": matched_asset.software_name,
                        "asset_environment": matched_asset.environment,
                        "candidate_ip": target_ip,
                        "requires_manual_review": True
                    }
                )
                containment_result = {
                    "status": "REJECTED",
                    "action_id": None,
                    "target_ip": target_ip,
                    "direction": None,
                    "error": auth_reason,
                    "requires_further_evidence_or_approval": True
                }
            elif match_classification == "NEEDS_REVIEW" or match_confidence < 85.0:
                review_reason = f"UNCERTAIN_THREAT_MATCH_{match_classification}_CONFIDENCE_{match_confidence:.1f}"
                logger.warning(
                    f"Containment suppressed for uncertain threat {threat_report.cve_id} on {matched_asset.software_name}: {review_reason}. Queued for review."
                )
                AutonomousPolicyEngine._record_audit_log(
                    db=db,
                    tenant_id=tenant.id,
                    action_id=None,
                    event_type="CONTAINMENT_SUPPRESSED_UNCERTAIN_THREAT",
                    actor="AUTONOMOUS_ORCHESTRATOR",
                    details={
                        "reason": review_reason,
                        "match_classification": match_classification,
                        "match_confidence": match_confidence,
                        "threat_report_id": threat_report.id,
                        "cve_id": threat_report.cve_id,
                        "candidate_ip": target_ip,
                        "requires_manual_review": True
                    }
                )
                containment_result = {
                    "status": "REJECTED",
                    "action_id": None,
                    "target_ip": target_ip,
                    "direction": None,
                    "error": review_reason,
                    "requires_further_evidence_or_approval": True
                }
            else:
                try:
                    clean_ip = validate_ip_for_containment(target_ip, allow_reserved=True)
                except Exception as e:
                    logger.warning(f"Invalid containment IP '{target_ip}': {e}")
                    AutonomousPolicyEngine._record_audit_log(
                        db=db,
                        tenant_id=tenant.id,
                        action_id=None,
                        event_type="CONTAINMENT_SUPPRESSED_INVALID_INDICATOR",
                        actor="AUTONOMOUS_ORCHESTRATOR",
                        details={"reason": str(e), "candidate_ip": target_ip}
                    )
                    containment_result = {
                        "status": "REJECTED",
                        "action_id": None,
                        "target_ip": target_ip,
                        "direction": None,
                        "error": str(e),
                        "requires_further_evidence_or_approval": True
                    }
                    clean_ip = None

                if clean_ip:
                    adapter = cls.resolve_firewall_adapter(tenant=tenant, asset=matched_asset)
                    is_sim = not cls.is_live_containment_enabled() if is_simulated is None else is_simulated

                    is_fedora = "Fedora" in adapter.__name__
                    action_prefix = "act-fed" if is_fedora else "act-win"

                    # Determine traffic direction from threat report & incident evidence
                    evidence_text = f"{threat_report.title or ''} {threat_report.summary or ''} {match.ai_matching_reason or ''} {getattr(threat_report, 'source_url', '') or ''}".lower()
                    inbound_patterns = (
                        "payload delivered from", "attack from", "exploit from", "exploit traffic from",
                        "traffic from", "exploit payload from", "incoming from", "scanner from",
                        "brute force from", "inbound", "ingress", "remote exploit", "request smuggling"
                    )
                    outbound_patterns = (
                        "feodo", "beacon to", "beaconing to", "exfiltration to", "callback to",
                        "c2 destination", "outbound", "egress", "botnet c2", "command and control server"
                    )

                    has_inbound = any(k in evidence_text for k in inbound_patterns)
                    has_outbound = any(k in evidence_text for k in outbound_patterns)

                    if has_inbound and not any(k in evidence_text for k in ("beacon to", "beaconing to", "exfiltration to", "callback to")):
                        if is_fedora:
                            action_type = "BLOCK_INGRESS_IPV4"
                        elif clean_ip == LAB_FEDORA_HOST_ONLY_IP or matched_asset.software_name.lower() in ("campus guide", "fastapi", "uvicorn"):
                            action_type = "BLOCK_INBOUND_PORT_8000"
                        else:
                            action_type = "BLOCK_INBOUND_IPV4"
                    elif has_outbound and not has_inbound:
                        action_type = "BLOCK_IPV4_DESTINATION"
                    else:
                        action_type = None

                    if action_type is None:
                        logger.warning(
                            f"Containment suppressed for incident on {matched_asset.software_name}: "
                            f"Traffic direction (inbound exploit source vs outbound C2 destination) could not be established from evidence."
                        )
                        containment_result = {
                            "status": "REJECTED",
                            "action_id": None,
                            "target_ip": clean_ip,
                            "direction": None,
                            "error": (
                                "CONTAINMENT_DIRECTION_UNRESOLVED: Traffic direction cannot be established from evidence. "
                                "Firewall rule suppressed; manual approval or further evidence required."
                            ),
                            "requires_further_evidence_or_approval": True
                        }
                    else:
                        existing_action = db.query(ContainmentAction).filter(
                            ContainmentAction.tenant_id == tenant.id,
                            ContainmentAction.indicator_value == clean_ip,
                            ContainmentAction.status.in_(["PENDING", "SIMULATED", "APPLIED", "VERIFIED"])
                        ).first()

                        if existing_action:
                            logger.info(f"Active containment action already exists for {clean_ip} (action_id: {existing_action.action_id}). Skipping duplicate creation.")
                            containment_result = {
                                "status": existing_action.status,
                                "action_id": existing_action.action_id,
                                "target_ip": clean_ip,
                                "direction": existing_action.action_type,
                                "is_simulated": existing_action.status == "SIMULATED",
                                "message": f"Active containment action already active: {existing_action.action_id}"
                            }
                        else:
                            action_id = f"{action_prefix}-{uuid.uuid4().hex[:12]}"

                            containment_action = ContainmentAction(
                                id=str(uuid.uuid4()),
                                action_id=action_id,
                                tenant_id=tenant.id,
                                threat_report_id=threat_report.id,
                                threat_match_id=match.id,
                                indicator_value=clean_ip,
                                indicator_type="ipv4",
                                action_type=action_type,
                                policy_decision="QUALIFIED",
                                policy_rule="JUSTIFIED_INCIDENT_EXPLOIT_CONTAINMENT",
                                status="PENDING",
                                ttl_seconds=7200
                            )
                            db.add(containment_action)
                            db.commit()
                            db.refresh(containment_action)

                            # Apply containment using resolved adapter
                            containment_result = adapter.apply_containment(
                                action=containment_action,
                                db=db,
                                actor="AUTONOMOUS_ORCHESTRATOR",
                                target_port=8000 if action_type == "BLOCK_INBOUND_PORT_8000" else 0,
                                is_simulated=is_sim
                            )
                        try:
                            if containment_result and containment_result.get("status") in ("SIMULATED", "APPLIED", "VERIFIED"):
                                NotificationService.send_incident_notification(
                                    db=db,
                                    tenant=tenant,
                                    event_type="CONTAINMENT_APPLIED",
                                    threat_report=threat_report,
                                    asset=matched_asset,
                                    remediation_policy=remediation_policy,
                                    containment_action_id=containment_result.get("action_id"),
                                    additional_evidence=f"Justified containment rule staged for IP {clean_ip} ({action_type})."
                                )
                            elif containment_result and containment_result.get("status") == "FAILED":
                                NotificationService.send_incident_notification(
                                    db=db,
                                    tenant=tenant,
                                    event_type="CONTAINMENT_FAILED",
                                    threat_report=threat_report,
                                    asset=matched_asset,
                                    remediation_policy=remediation_policy,
                                    containment_action_id=containment_result.get("action_id"),
                                    additional_evidence=f"Containment execution failed for IP {clean_ip}: {containment_result.get('error')}"
                                )
                        except Exception as notif_err:
                            logger.error(f"Containment notification dispatch warning: {notif_err}")
        else:
            logger.info("Containment suppressed: No malicious IP evidence provided with vulnerability match.")

        # Step 4: Fixed-Version Discovery (Phase 4)
        resolved_pm = cls.resolve_package_manager_for_asset(matched_asset, tenant)
        fix_discovery = FixedVersionDiscoveryService.discover_and_verify_fix(
            package_name=matched_asset.software_name,
            current_version=matched_asset.software_version,
            threat_report=threat_report,
            package_manager=resolved_pm
        )

        patch_proposal = None
        existing_prop = None
        # Step 5: Remediation under Company Policy (Phase 5)
        is_already_fixed = (fix_discovery.get("status") == "ALREADY_FIXED")
        is_candidate_found = bool(fix_discovery.get("fixed_version")) and not is_already_fixed
        is_verified = fix_discovery.get("is_verified", False)
        is_authoritative = fix_discovery.get("is_authoritative", False)
        is_live_blocked = fix_discovery.get("live_execution_blocked", False)
        blocking_reason = fix_discovery.get("blocking_reason")

        if is_candidate_found:
            fixed_ver = fix_discovery["fixed_version"]
            
            # Check for existing proposal
            existing_prop = db.query(PatchProposal).filter(
                PatchProposal.tenant_id == tenant.id,
                PatchProposal.threat_match_id == match.id
            ).first()

            if not existing_prop:
                prop_res = PatchManagementAdapter.create_proposal(
                    db=db,
                    tenant_id=tenant.id,
                    threat_match_id=match.id,
                    asset_component_id=matched_asset.id,
                    package_name=matched_asset.software_name,
                    target_version=fixed_ver,
                    current_version=matched_asset.software_version,
                    package_manager=resolved_pm,
                    is_authoritative=is_authoritative,
                    live_execution_blocked=is_live_blocked,
                    blocking_reason=blocking_reason
                )
                patch_proposal = prop_res

            # If policy is NOTIFY: dispatch FIX_AVAILABLE and PATCH_APPROVAL_REQUIRED notifications
            active_prop = patch_proposal or existing_prop
            if remediation_policy == "NOTIFY" and not force_auto_patch:
                if is_verified:
                    NotificationService.send_incident_notification(
                        db=db,
                        tenant=tenant,
                        event_type="FIX_AVAILABLE",
                        threat_report=threat_report,
                        asset=matched_asset,
                        fixed_version=fixed_ver,
                        remediation_policy="NOTIFY",
                        additional_evidence=f"Verified compatible fix {fixed_ver} is available upstream."
                    )
                if active_prop:
                    NotificationService.send_incident_notification(
                        db=db,
                        tenant=tenant,
                        event_type="PATCH_APPROVAL_REQUIRED",
                        threat_report=threat_report,
                        asset=matched_asset,
                        fixed_version=fixed_ver,
                        remediation_policy="NOTIFY",
                        additional_evidence=f"Patch proposal '{active_prop.proposal_id}' created for {active_prop.package_name} ({matched_asset.software_version} -> {fixed_ver}). Explicit SOC authorization required."
                    )
            elif remediation_policy == "AUTO_PATCH" or force_auto_patch:
                report_sev = (threat_report.severity or "medium").lower() if threat_report else "medium"
                if report_sev not in ("critical", "high") and not force_auto_patch:
                    logger.info(f"Auto-patching skipped for {report_sev} severity threat. Only Critical and High qualify.")
                    active_prop = patch_proposal or existing_prop
                    return {
                        "status": "AUTO_PATCH_SKIPPED_LOW_SEVERITY",
                        "incident_id": match.id,
                        "tenant_id": tenant.id,
                        "cve_id": threat_report.cve_id,
                        "severity": report_sev,
                        "matched_component": matched_asset.software_name,
                        "installed_version": matched_asset.software_version,
                        "fixed_version": fixed_ver,
                        "remediation_policy": remediation_policy,
                        "containment": containment_result,
                        "patch_proposal": active_prop.proposal_id if active_prop else None,
                        "message": f"Threat severity '{report_sev}' is below Critical/High auto-patch threshold; proposal held for review."
                    }

                exec_is_sim = not cls.is_live_patching_enabled() if is_simulated is None else is_simulated

                # If candidate is an unverified inferred constraint bound, block auto-patching entirely
                if fix_discovery.get("status") == "INFERRED_CANDIDATE":
                    logger.warning(f"AUTO_PATCH blocked: {blocking_reason}")
                    return {
                        "status": "AUTO_PATCH_BLOCKED",
                        "incident_id": match.id,
                        "tenant_id": tenant.id,
                        "cve_id": threat_report.cve_id,
                        "matched_component": matched_asset.software_name,
                        "installed_version": matched_asset.software_version,
                        "fixed_version": fixed_ver,
                        "remediation_policy": remediation_policy,
                        "containment": containment_result,
                        "blocking_reason": blocking_reason,
                        "patch_proposal": patch_proposal.proposal_id if patch_proposal else (existing_prop.proposal_id if existing_prop else None)
                    }

                # If live execution requested but package release not confirmed in registry, block live execution
                if not exec_is_sim and is_live_blocked:
                    logger.warning(f"AUTO_PATCH live execution blocked: {blocking_reason}")
                    return {
                        "status": "AUTO_PATCH_BLOCKED",
                        "incident_id": match.id,
                        "tenant_id": tenant.id,
                        "cve_id": threat_report.cve_id,
                        "matched_component": matched_asset.software_name,
                        "installed_version": matched_asset.software_version,
                        "fixed_version": fixed_ver,
                        "remediation_policy": remediation_policy,
                        "containment": containment_result,
                        "blocking_reason": blocking_reason,
                        "patch_proposal": patch_proposal.proposal_id if patch_proposal else (existing_prop.proposal_id if existing_prop else None)
                    }

                # AUTO_PATCH: Automatically approve and execute patch proposal
                prop_obj = patch_proposal or existing_prop
                if prop_obj.status in ("SIMULATED", "EXECUTED", "SUCCESS_VERIFIED_AND_RELEASED", "AUTO_PATCHED_AND_RESOLVED"):
                    logger.info(f"Patch proposal {prop_obj.proposal_id} is already in state '{prop_obj.status}'. Skipping duplicate execution.")
                    outcome_status = "AUTO_PATCH_SIMULATED" if prop_obj.status == "SIMULATED" else "AUTO_PATCHED_AND_RESOLVED"
                    return {
                        "status": outcome_status,
                        "incident_id": match.id,
                        "tenant_id": tenant.id,
                        "cve_id": threat_report.cve_id,
                        "matched_component": matched_asset.software_name,
                        "installed_version": matched_asset.software_version,
                        "fixed_version": fixed_ver,
                        "remediation_policy": remediation_policy,
                        "containment": containment_result,
                        "patch_proposal": prop_obj.proposal_id,
                        "message": f"Proposal already processed with status: {prop_obj.status}"
                    }

                prop_id = prop_obj.proposal_id
                if prop_obj.status == "PROPOSED":
                    PatchManagementAdapter.approve_proposal(
                        db=db,
                        proposal_id=prop_id,
                        approver="AUTONOMOUS_POLICY_AUTO_PATCH",
                        tenant_id=tenant.id
                    )
                exec_res = cls.execute_patch_and_release(
                    db=db,
                    proposal_id=prop_id,
                    tenant_id=tenant.id,
                    is_simulated=exec_is_sim
                )
                is_live_resolved = exec_res.get("status") == "SUCCESS_VERIFIED_AND_RELEASED"
                is_sim_ok = exec_res.get("status") == "SIMULATED_PATCH_SUCCEEDED"
                outcome_status = "AUTO_PATCHED_AND_RESOLVED" if is_live_resolved else ("AUTO_PATCH_SIMULATED" if is_sim_ok else "AUTO_PATCH_FAILED")

                return {
                    "status": outcome_status,
                    "incident_id": match.id,
                    "tenant_id": tenant.id,
                    "cve_id": threat_report.cve_id,
                    "matched_component": matched_asset.software_name,
                    "installed_version": matched_asset.software_version,
                    "fixed_version": fixed_ver,
                    "remediation_policy": remediation_policy,
                    "containment": containment_result,
                    "patch_execution": exec_res
                }

        prop_info = None
        if patch_proposal or existing_prop:
            active_prop = patch_proposal or existing_prop
            prop_info = {
                "proposal_id": active_prop.proposal_id,
                "package_name": active_prop.package_name,
                "target_version": active_prop.target_version,
                "status": active_prop.status
            }

        return {
            "status": "INCIDENT_CREATED",
            "incident_id": match.id,
            "tenant_id": tenant.id,
            "tenant_name": tenant.company_name,
            "cve_id": threat_report.cve_id,
            "matched_component": matched_asset.software_name,
            "installed_version": matched_asset.software_version,
            "assessment_outcome": match_classification,
            "notification": notif_result,
            "containment": containment_result,
            "fix_discovery": fix_discovery,
            "patch_proposal": prop_info
        }

    @classmethod
    def execute_patch_and_release(
        cls,
        db: Session,
        proposal_id: str,
        tenant_id: str,
        is_simulated: bool = True
    ) -> Dict[str, Any]:
        """
        Phase 6: Verification and Safe Unblocking
        1. Executes patch (simulation or live).
        2. Verifies installed version against package inventory.
        3. Re-evaluates vulnerability constraint to guarantee safety.
        4. Releases containment rule on Windows Defender Firewall.
        5. Confirms rule removal and marks incident RESOLVED.
        """
        proposal = db.query(PatchProposal).filter(PatchProposal.proposal_id == proposal_id).first()
        tenant = proposal.tenant if proposal else None
        threat_report = proposal.threat_match.report if proposal and proposal.threat_match else None
        asset = proposal.asset if proposal else None
        remediation_policy = getattr(tenant, "remediation_policy", "NOTIFY") if tenant else "NOTIFY"

        mode_str = "simulated" if is_simulated else "live"

        # Dispatch PATCH_STARTED
        if tenant and threat_report:
            NotificationService.send_incident_notification(
                db=db,
                tenant=tenant,
                event_type="PATCH_STARTED",
                threat_report=threat_report,
                asset=asset,
                fixed_version=proposal.target_version if proposal else None,
                remediation_policy=remediation_policy,
                additional_evidence=f"Patch deployment initiated for '{proposal.package_name}' -> '{proposal.target_version}' (mode: {mode_str})."
            )

        # 1. Execute patch
        exec_res = PatchManagementAdapter.execute_patch(
            db=db,
            proposal_id=proposal_id,
            actor="AUTONOMOUS_ORCHESTRATOR",
            mode=mode_str,
            tenant_id=tenant_id
        )

        expected_statuses = ("SIMULATED",) if is_simulated else ("VERIFIED",)
        if not proposal or exec_res.get("status") not in expected_statuses:
            err_msg = exec_res.get("error") or f"Patch execution failed or returned unexpected status '{exec_res.get('status')}' (expected {expected_statuses})."
            if tenant and threat_report:
                NotificationService.send_incident_notification(
                    db=db,
                    tenant=tenant,
                    event_type="PATCH_FAILED",
                    threat_report=threat_report,
                    asset=asset,
                    fixed_version=proposal.target_version if proposal else None,
                    remediation_policy=remediation_policy,
                    additional_evidence=err_msg
                )
            return {
                "status": "PATCH_EXECUTION_FAILED",
                "proposal_id": proposal_id,
                "error": err_msg
            }

        # Dispatch PATCH_SUCCEEDED
        if tenant and threat_report:
            NotificationService.send_incident_notification(
                db=db,
                tenant=tenant,
                event_type="PATCH_SUCCEEDED",
                threat_report=threat_report,
                asset=asset,
                fixed_version=proposal.target_version,
                remediation_policy=remediation_policy,
                additional_evidence=f"Package upgrade command completed successfully ({mode_str}). Target version staged: {proposal.target_version}."
            )

        # 3. Authoritative Re-evaluation: Does the new version resolve the advisory?
        match = proposal.threat_match
        target_version = proposal.target_version

        if threat_report:
            corpus = f"{threat_report.title or ''} {threat_report.summary or ''}"
            cls_out, conf, reason = evaluate_version_applicability(
                installed_version=target_version,
                threat_text=corpus,
                pkg_name=proposal.package_name
            )

            if cls_out != "NOT_AFFECTED":
                if tenant:
                    NotificationService.send_incident_notification(
                        db=db,
                        tenant=tenant,
                        event_type="PATCH_FAILED",
                        threat_report=threat_report,
                        asset=asset,
                        fixed_version=target_version,
                        remediation_policy=remediation_policy,
                        additional_evidence=f"Installed version {target_version} failed verification check: {reason}. Containment retained."
                    )
                return {
                    "status": "REMEDIATION_UNRESOLVED",
                    "proposal_id": proposal_id,
                    "target_version": target_version,
                    "evaluation": cls_out,
                    "reason": reason,
                    "message": "Installed version does not satisfy the vulnerability constraint. Containment retained."
                }

        # Dispatch REMEDIATION_VERIFIED
        if tenant and threat_report:
            NotificationService.send_incident_notification(
                db=db,
                tenant=tenant,
                event_type="REMEDIATION_VERIFIED",
                threat_report=threat_report,
                asset=asset,
                fixed_version=target_version,
                remediation_policy=remediation_policy,
                additional_evidence=f"Installed version {target_version} evaluated to NOT_AFFECTED against vulnerability constraint. Verification passed."
            )

        # 4. In LIVE mode: Update AssetComponent version, mark ThreatMatch RESOLVED, and release containment.
        # In SIMULATED mode: Retain OPEN status, do NOT update Asset software version, and NEVER release containment.
        if not is_simulated:
            if proposal.asset:
                proposal.asset.software_version = target_version
            if match:
                match.status = "RESOLVED"
            db.commit()

            # 5. Safe Release of Containment
            released_containment_actions = []
            if match:
                active_actions = db.query(ContainmentAction).filter(
                    ContainmentAction.threat_match_id == match.id,
                    ContainmentAction.status.in_(["SIMULATED", "APPLIED", "VERIFIED"])
                ).all()

                for action in active_actions:
                    adapter = get_adapter_for_action(action)
                    rollback_res = adapter.rollback_containment(
                        action=action,
                        db=db,
                        actor="AUTONOMOUS_REMEDIATION_RELEASE"
                    )
                    released_containment_actions.append(rollback_res)

            # 6. Dispatch Final Notification: Containment Released & Vulnerability Resolved
            tenant = proposal.tenant
            if tenant and threat_report:
                NotificationService.send_incident_notification(
                    db=db,
                    tenant=tenant,
                    event_type="CONTAINMENT_RELEASED",
                    threat_report=threat_report,
                    asset=proposal.asset,
                    fixed_version=target_version,
                    remediation_policy=getattr(tenant, "remediation_policy", "NOTIFY"),
                    additional_evidence=f"Vulnerability resolved by upgrade to {target_version}. Containment rule removed."
                )

            return {
                "status": "SUCCESS_VERIFIED_AND_RELEASED",
                "proposal_id": proposal_id,
                "package_name": proposal.package_name,
                "verified_version": target_version,
                "vulnerability_status": "RESOLVED",
                "containment_released": released_containment_actions,
                "message": f"Patch verified ({target_version}). Threat resolved and containment safely released."
            }
        else:
            # SIMULATED MODE: Record simulated validation outcome separately, retaining incident OPEN and containment active
            db.commit()
            current_threat_status = match.status if match else "OPEN"
            return {
                "status": "SIMULATED_PATCH_SUCCEEDED",
                "proposal_id": proposal_id,
                "package_name": proposal.package_name,
                "verified_version": target_version,
                "is_simulated": True,
                "vulnerability_status": current_threat_status,
                "simulation_outcome": "SIMULATED_SUCCESS",
                "containment_released": [],
                "message": f"Simulated patch validation succeeded for {proposal.package_name} -> {target_version}. Incident remains {current_threat_status} and containment is retained until live execution."
            }

    @classmethod
    def process_manual_remediation(
        cls,
        db: Session,
        threat_match_id: str,
        tenant_id: str,
        new_version: str,
        notes: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Allows company to independently report a manual patch.
        Re-verifies against vulnerability constraints and releases containment if safe.
        """
        match = db.query(ThreatMatch).filter(
            ThreatMatch.id == threat_match_id,
            ThreatMatch.tenant_id == tenant_id
        ).first()

        if not match:
            raise ValueError("Threat match not found or tenant unauthorized.")

        threat_report = match.report
        asset = match.asset
        package_name = asset.software_name if asset else "unknown"

        corpus = f"{threat_report.title or ''} {threat_report.summary or ''}" if threat_report else ""
        classification, conf, reason = evaluate_version_applicability(
            installed_version=new_version,
            threat_text=corpus,
            pkg_name=package_name
        )

        if classification != "NOT_AFFECTED":
            return {
                "status": "REJECTED_STILL_AFFECTED",
                "installed_version": new_version,
                "classification": classification,
                "reason": reason,
                "message": f"Version '{new_version}' does not resolve {threat_report.cve_id if threat_report else 'CVE'}. Containment retained."
            }

        # Update asset & match
        if asset:
            asset.software_version = new_version
        match.status = "RESOLVED"
        db.commit()

        # Release containment
        released_actions = []
        active_actions = db.query(ContainmentAction).filter(
            ContainmentAction.threat_match_id == match.id,
            ContainmentAction.status.in_(["SIMULATED", "APPLIED", "VERIFIED"])
        ).all()

        for act in active_actions:
            adapter = get_adapter_for_action(act)
            res = adapter.rollback_containment(act, db, actor="MANUAL_REMEDIATION_RELEASE")
            released_actions.append(res)

        # Dispatch automatic notifications for manual remediation resolution
        tenant = match.tenant or db.query(Tenant).filter(Tenant.id == tenant_id).first()
        if tenant and threat_report:
            NotificationService.send_incident_notification(
                db=db,
                tenant=tenant,
                event_type="REMEDIATION_VERIFIED",
                threat_report=threat_report,
                asset=asset,
                fixed_version=new_version,
                remediation_policy=getattr(tenant, "remediation_policy", "NOTIFY") or "NOTIFY",
                additional_evidence=f"Manual remediation verified with package {package_name} upgraded to {new_version}. Notes: {notes or 'N/A'}"
            )
            if released_actions:
                NotificationService.send_incident_notification(
                    db=db,
                    tenant=tenant,
                    event_type="CONTAINMENT_RELEASED",
                    threat_report=threat_report,
                    asset=asset,
                    fixed_version=new_version,
                    remediation_policy=getattr(tenant, "remediation_policy", "NOTIFY") or "NOTIFY",
                    additional_evidence=f"Temporary containment rules safely released following verified manual remediation to {new_version}."
                )

        return {
            "status": "RESOLVED_AND_RELEASED",
            "threat_match_id": threat_match_id,
            "package_name": package_name,
            "installed_version": new_version,
            "released_containment": released_actions,
            "notes": notes,
            "message": f"Manual remediation verified with version {new_version}. Threat resolved and containment released."
        }
