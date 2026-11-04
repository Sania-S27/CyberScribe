# backend/app/services/osint_collector.py
import os
import re
import time
import asyncio
import hashlib
import threading
import requests
import feedparser
import traceback
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, List, Any
from sqlalchemy.orm import Session

from app.core.database import SessionLocal
from app import models
from app.agents.orchestrator import cyber_scribe_orchestrator
from app.agents.mitigation import generate_soar_playbook, dispatch_playbook_to_matched_tenants
from app.core.agent_logger import (
    log_agent,
    log_ingestion_start,
    log_ingestion_success,
    log_ingestion_error,
    log_report_saved,
    log_correlation_match,
    log_containment_eval,
    log_containment_action,
    log_soar_dispatch
)

try:
    from app.services.vector_store import add_threat_embedding
except ImportError:
    def add_threat_embedding(*args, **kwargs):
        pass

from app.services.version_matcher import evaluate_version_applicability, normalize_package_name

OSINT_FEEDS = {
    "CISA Advisories": "https://www.cisa.gov/cybersecurity-advisories/all.xml",
    "The Hacker News": "https://feeds.feedburner.com/TheHackersNews",
    "Krebs on Security": "https://krebsonsecurity.com/feed/",
    "SecurityWeek": "https://www.securityweek.com/feed/",
    "Dark Reading": "https://www.darkreading.com/rss.xml"
}

DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Accept": "application/xml,text/xml,application/xhtml+xml,text/html;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate"
}

# Configurable scheduling interval (default: 4 hours = 14400s)
DEFAULT_POLL_INTERVAL_SECONDS = int(os.environ.get("OSINT_POLL_INTERVAL_SECONDS", "14400"))

# Keywords to ensure we only spend LLM quota on actual security vulnerabilities
ACTIONABLE_KEYWORDS = [
    "vulnerability", "cve-", "exploit", "rce", "zero-day", "0-day",
    "injection", "arbitrary code", "remote code", "privilege escalation",
    "bypass", "denial of service", "ssrf", "xss", "backdoor", "patch"
]

# Ingestion concurrency mutex to prevent overlapping scheduler and manual sweeps
_sweep_mutex = threading.Lock()


class SourceTelemetry:
    """Tracks telemetry, sync timestamps, and diagnostics for an individual intelligence source."""
    def __init__(self, name: str, source_type: str, url: str, cadence: str = "Every 4 Hours"):
        self.name = name
        self.source_type = source_type
        self.url = url
        self.cadence = cadence
        self.status = "IDLE"  # IDLE, SYNCING, HEALTHY, WARNING, ERROR
        self.last_attempt_at: Optional[datetime] = None
        self.last_success_at: Optional[datetime] = None
        self.last_discovered_item: Optional[str] = None
        self.new_items_count: int = 0
        self.updated_items_count: int = 0
        self.duplicates_skipped_count: int = 0
        self.failures_count: int = 0
        self.last_error: Optional[str] = None

    def to_dict(self, awaiting_review_count: int = 0) -> dict:
        return {
            "name": self.name,
            "type": self.source_type,
            "url": self.url,
            "frequency": self.cadence,
            "status": self.status,
            "last_attempt": self.last_attempt_at.isoformat() if self.last_attempt_at else None,
            "last_sync": self.last_success_at.isoformat() if self.last_success_at else None,
            "last_discovered_item": self.last_discovered_item,
            "new_items": self.new_items_count,
            "updated_items": self.updated_items_count,
            "duplicates_skipped": self.duplicates_skipped_count,
            "failures": self.failures_count,
            "last_error": self.last_error,
            "awaiting_review": awaiting_review_count
        }


class SourceSyncTracker:
    """Thread-safe telemetry registry for continuous OSINT ingestion health tracking."""
    def __init__(self):
        self._lock = threading.Lock()
        self.sources: Dict[str, SourceTelemetry] = {}
        self._init_sources()

    def _init_sources(self):
        for name, url in OSINT_FEEDS.items():
            self.sources[name] = SourceTelemetry(name=name, source_type="RSS/Atom Feed", url=url, cadence="Every 4 Hours")
        self.sources["NVD NIST REST API 2.0"] = SourceTelemetry(
            name="NVD NIST REST API 2.0",
            source_type="REST API (2.0)",
            url="https://services.nvd.nist.gov/rest/json/cves/2.0",
            cadence="Every 4 Hours"
        )
        self.sources["Feodo Tracker C2"] = SourceTelemetry(
            name="Feodo Tracker C2",
            source_type="JSON Blocklist",
            url="https://feodotracker.abuse.ch/downloads/ipblocklist.json",
            cadence="Hourly"
        )

    def record_start(self, source_name: str):
        with self._lock:
            if source_name not in self.sources:
                self.sources[source_name] = SourceTelemetry(name=source_name, source_type="Intelligence Source", url="")
            src = self.sources[source_name]
            src.status = "SYNCING"
            src.last_attempt_at = datetime.now(timezone.utc).replace(tzinfo=None)

    def record_success(self, source_name: str, new_count: int = 0, updated_count: int = 0, duplicates_count: int = 0, last_item: Optional[str] = None):
        with self._lock:
            if source_name not in self.sources:
                self.sources[source_name] = SourceTelemetry(name=source_name, source_type="Intelligence Source", url="")
            src = self.sources[source_name]
            src.status = "HEALTHY"
            now = datetime.now(timezone.utc).replace(tzinfo=None)
            src.last_attempt_at = now
            src.last_success_at = now
            src.last_error = None
            src.failures_count = 0
            src.new_items_count += new_count
            src.updated_items_count += updated_count
            src.duplicates_skipped_count += duplicates_count
            if last_item:
                src.last_discovered_item = last_item

    def record_failure(self, source_name: str, error_msg: str):
        with self._lock:
            if source_name not in self.sources:
                self.sources[source_name] = SourceTelemetry(name=source_name, source_type="Intelligence Source", url="")
            src = self.sources[source_name]
            src.status = "ERROR"
            src.last_attempt_at = datetime.now(timezone.utc).replace(tzinfo=None)
            src.failures_count += 1
            src.last_error = str(error_msg)[:300]

    def get_all_status(self, db: Optional[Session] = None) -> List[dict]:
        awaiting_count = 0
        if db:
            try:
                awaiting_count = db.query(models.ThreatMatch).filter(
                    models.ThreatMatch.ai_matching_reason.ilike("%[NEEDS REVIEW]%"),
                    models.ThreatMatch.status.in_(['OPEN', 'open', 'unmitigated', 'triaged', 'active'])
                ).count()
            except Exception:
                awaiting_count = 0

        with self._lock:
            return [src.to_dict(awaiting_review_count=awaiting_count) for src in self.sources.values()]


# Global singleton tracker instance
source_tracker = SourceSyncTracker()


def compute_content_hash(title: str, summary: str, severity: str = "") -> str:
    """Computes a canonical SHA-256 content fingerprint for deduplication and update tracking."""
    raw = f"{(title or '').strip()}||{(summary or '').strip()}||{(severity or '').strip()}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def fetch_feed_with_retry(feed_url: str, max_retries: int = 2, timeout: int = 15):
    """Executes HTTP request with bounded retries, redirect handling, and exponential backoff for network resilience."""
    for attempt in range(max_retries + 1):
        try:
            res = requests.get(feed_url, headers=DEFAULT_HEADERS, timeout=timeout, allow_redirects=True)
            if res.status_code == 200:
                return res
            elif res.status_code in [429, 500, 502, 503, 504]:
                if attempt < max_retries:
                    time.sleep(1.0 * (attempt + 1))
                    continue
            return res
        except (requests.RequestException, Exception) as req_err:
            if attempt < max_retries:
                time.sleep(1.0 * (attempt + 1))
                continue
            raise req_err



def clean_package_name(entry_str: str) -> tuple[str, Optional[str]]:
    """Strips version pins, comparison operators, and bracket extras like [bcrypt] or [cryptography]."""
    cleaned = re.sub(r"\[.*?\]", "", entry_str.strip())
    match = re.split(r"([=<>~!:@\s]+)", cleaned, maxsplit=1)
    pkg_name = match[0].strip().lower()
    version = None
    if len(match) > 2 and match[2].strip():
        raw_v = match[2].strip()
        if raw_v.lower() not in ["none", "null", "undefined"]:
            version = raw_v
    return pkg_name, version


def check_threat_match_for_tenant(
    threat_title: str, 
    threat_summary: str, 
    tenant_tech_stack: str,
    threat_raw: str = ""
) -> tuple[bool, float, str]:
    if not tenant_tech_stack:
        return False, 0.0, ""

    corpus = f"{threat_title or ''} {threat_summary or ''} {threat_raw or ''}".strip()
    entries = [e.strip() for e in tenant_tech_stack.split(",") if e.strip()]

    best_match = None
    for entry in entries:
        pkg_name, version = clean_package_name(entry)
        if not pkg_name or len(pkg_name) < 3:
            continue

        classification, conf, reason = evaluate_version_applicability(
            installed_version=version,
            threat_text=corpus,
            pkg_name=pkg_name
        )

        if classification == "AFFECTED":
            return True, conf, reason
        elif classification == "NEEDS_REVIEW":
            if not best_match:
                best_match = (True, conf, reason)

    if best_match:
        return best_match

    return False, 0.0, ""


def process_threat_tenant_correlations(db: Session, threat_report: models.ThreatReport, raw_context: str = ""):
    """Correlates threat reports across tenants, auto-mitigates High/Critical threats, and saves status."""
    tenants = db.query(models.Tenant).all()
    for tenant in tenants:
        stack_parts = []
        if tenant.tech_stack:
            stack_parts.append(tenant.tech_stack)
        
        assets = db.query(models.AssetComponent).filter(models.AssetComponent.tenant_id == tenant.id).all()
        for a in assets:
            sw_name = (a.software_name or "").strip()
            sw_ver = (getattr(a, 'software_version', None) or "").strip()
            if sw_name:
                stack_parts.append(f"{sw_name}:{sw_ver}" if sw_ver else sw_name)

        full_tech_stack = ", ".join(list(set(stack_parts)))
        if not full_tech_stack:
            continue

        existing_match = db.query(models.ThreatMatch).filter(
            models.ThreatMatch.tenant_id == tenant.id,
            models.ThreatMatch.threat_report_id == threat_report.id
        ).first()

        if not existing_match:
            is_match, conf, reason = check_threat_match_for_tenant(
                threat_title=threat_report.title,
                threat_summary=threat_report.summary,
                tenant_tech_stack=full_tech_stack,
                threat_raw=raw_context
            )
            if is_match:
                report_severity = (threat_report.severity or "medium").lower()
                is_high_or_critical = report_severity in ["critical", "high"]
                is_affected = "[AFFECTED]" in reason.upper() or "satisfies vulnerable constraint" in reason.lower()
                is_needs_review = "[NEEDS REVIEW]" in reason.upper() or not is_affected
                
                outcome = "AFFECTED" if is_affected else "NEEDS_REVIEW" if is_needs_review else "INFORMATIONAL"
                log_correlation_match(tenant.company_name, outcome, full_tech_stack[:40])
                
                final_status = "OPEN"

                # Safety Safeguard: Only confirmed AFFECTED threats authorize automated SOAR mitigation.
                # NEEDS_REVIEW findings must never trigger automatic containment or webhook dispatch.
                if is_affected and is_high_or_critical and tenant.webhook_url:
                    try:
                        playbook = generate_soar_playbook(
                            threat_title=threat_report.title,
                            summary=threat_report.summary,
                            mitre_tactics=[],
                            assessment_outcome="AFFECTED"
                        )
                        dispatch_results = dispatch_playbook_to_matched_tenants(
                            db=db,
                            playbook=playbook,
                            keyword_filter=threat_report.cve_id or threat_report.title,
                            target_tenant_id=tenant.id
                        )
                        if dispatch_results and any(r.get("status") == "RECEIVED" for r in dispatch_results):
                            log_soar_dispatch(tenant.company_name, threat_report.title, "RECEIVED")
                    except Exception as soar_err:
                        print(f"[-] SOAR Dispatch warning: {soar_err}")
                elif is_needs_review:
                    log_agent("CONTAINMENT", f"Automated containment suppressed for tenant '{tenant.company_name}': Finding requires manual review.", emoji="🛡️")
                else:
                    log_agent("CONTAINMENT", f"Severity '{report_severity}' logged as advisory without firewall rule staging.", emoji="ℹ️")

                # Connect End-to-End Autonomous Response Orchestrator
                if is_affected:
                    try:
                        from app.services.autonomous_response_orchestrator import AutonomousResponseOrchestrator
                        orch_res = AutonomousResponseOrchestrator.correlate_sbom_and_create_incident(
                            db=db,
                            tenant_id=tenant.id,
                            threat_report_id=threat_report.id,
                            force_auto_patch=False
                        )
                        print(f"[+] Autonomous orchestrator processed incident for {tenant.company_name}: {orch_res.get('status')}")
                    except Exception as orch_err:
                        print(f"[-] Autonomous orchestrator invocation error: {orch_err}")
                else:
                    # Informational or NEEDS_REVIEW threat match record
                    try:
                        db.add(models.ThreatMatch(
                            tenant_id=tenant.id,
                            threat_report_id=threat_report.id,
                            status=final_status,
                            ai_confidence_score=conf,
                            ai_matching_reason=reason[:65535] if reason else None
                        ))
                        db.commit()
                    except Exception as match_save_err:
                        db.rollback()
                        print(f"[-] Failed to save ThreatMatch for tenant {tenant.company_name}: {match_save_err}")
        else:
            # If an existing match is OPEN and AFFECTED, check if orchestrator needs to evaluate it
            reason = existing_match.ai_matching_reason or ""
            is_affected = "[AFFECTED]" in reason.upper() or "satisfies vulnerable constraint" in reason.lower()
            if is_affected and existing_match.status in ("OPEN", "open", "unmitigated", "active"):
                has_prop = db.query(models.PatchProposal).filter(
                    models.PatchProposal.tenant_id == tenant.id,
                    models.PatchProposal.threat_match_id == existing_match.id
                ).first()
                if not has_prop:
                    try:
                        from app.services.autonomous_response_orchestrator import AutonomousResponseOrchestrator
                        orch_res = AutonomousResponseOrchestrator.correlate_sbom_and_create_incident(
                            db=db,
                            tenant_id=tenant.id,
                            threat_report_id=threat_report.id,
                            force_auto_patch=False
                        )
                        print(f"[+] Autonomous orchestrator processed existing incident for {tenant.company_name}: {orch_res.get('status')}")
                    except Exception as orch_err:
                        print(f"[-] Autonomous orchestrator invocation error on existing match: {orch_err}")


def prune_old_threats(db: Session, retention_days: int = 30):
    """
    Non-destructive intelligence lifecycle policy:
    Preserves all historical threat intelligence records for retrospective matching,
    research, and audit trails without deleting data from the database.
    """
    try:
        cutoff_date = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=retention_days)
        total_reports = db.query(models.ThreatReport).count()
        historical_count = db.query(models.ThreatReport).filter(
            models.ThreatReport.created_at < cutoff_date
        ).count()
        print(f"[*] [Intelligence Retention Policy] Preserving all {total_reports} threat records ({historical_count} historical >{retention_days}d). Zero-deletion policy active.")
    except Exception as prune_err:
        print(f"[-] Retention policy check warning: {prune_err}")


def is_test_fixture(cve_id: Optional[str] = None, source_url: Optional[str] = None, title: Optional[str] = None) -> bool:
    """Identifies test fixture mock entries so they are excluded from live ingestion and metrics."""
    if cve_id:
        cve_upper = cve_id.upper()
        if "TEST" in cve_upper or cve_upper.startswith("CVE-2026-AUTO") or "MOCK" in cve_upper:
            return True
    if source_url:
        if source_url.startswith("manual-feed://") or "test-fixture" in source_url.lower():
            return True
    if title:
        title_upper = title.upper()
        if "[TEST FIXTURE]" in title_upper or "MOCK THREAT" in title_upper:
            return True
    return False


def fetch_targeted_cves_for_inventory(db: Session, lookback_days: int = 30):
    """
    Targeted OSINT: Ingests specific CVEs matching tenant environment assets from NVD 2.0.
    Distinguishes newly published vulnerabilities from older vulnerabilities modified recently.
    Preserves meaningful updates, deduplicates unchanged items, and records telemetry.
    """
    source_name = "NVD NIST REST API 2.0"
    source_tracker.record_start(source_name)
    log_ingestion_start(f"Checking NVD 2.0 for registered tenant asset components (Lookback: {lookback_days}d)...")
    
    target_components = set()
    tenants = db.query(models.Tenant).all()
    for t in tenants:
        if t.tech_stack:
            for item in t.tech_stack.split(","):
                name, _ = clean_package_name(item)
                if name and len(name) >= 3:
                    target_components.add(name)
        assets = db.query(models.AssetComponent).filter(models.AssetComponent.tenant_id == t.id).all()
        for a in assets:
            name, _ = clean_package_name(a.software_name)
            if name and len(name) >= 3:
                target_components.add(name)

    headers = {"User-Agent": "CyberScribe-Threat-Agent/1.0"}
    cutoff_dt = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=lookback_days)

    new_count = 0
    updated_count = 0
    dups_count = 0
    last_discovered = None

    # Limit to top 5 components per sweep to avoid NVD rate-limiting
    for component in list(target_components)[:5]:
        try:
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={component}&resultsPerPage=5"
            res = requests.get(url, headers=headers, timeout=10)
            if res.status_code != 200:
                time.sleep(2.0)
                continue

            vulnerabilities = res.json().get("vulnerabilities", [])
            for item in vulnerabilities:
                cve_data = item.get("cve", {})
                cve_id = cve_data.get("id")
                if not cve_id or is_test_fixture(cve_id=cve_id):
                    continue

                source_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                existing = db.query(models.ThreatReport).filter(
                    (models.ThreatReport.source_url == source_url) | (models.ThreatReport.cve_id == cve_id)
                ).first()

                descriptions = cve_data.get("descriptions", [])
                english_desc = next((d['value'] for d in descriptions if d.get('lang') == 'en'), "No description available.")
                
                # Extract publication and modification timestamps from NVD (do not fabricate if missing)
                published_str = cve_data.get("published")
                published_dt = None
                if published_str:
                    try:
                        clean_pub = published_str.replace("Z", "").split(".")[0]
                        published_dt = datetime.fromisoformat(clean_pub)
                    except Exception:
                        published_dt = None

                modified_str = cve_data.get("lastModified")
                modified_dt = None
                if modified_str:
                    try:
                        clean_mod = modified_str.replace("Z", "").split(".")[0]
                        modified_dt = datetime.fromisoformat(clean_mod)
                    except Exception:
                        modified_dt = None

                # Distinguish newly published vs recently modified older CVEs
                is_recently_modified_older = False
                if published_dt and published_dt < cutoff_dt:
                    if modified_dt and modified_dt >= cutoff_dt:
                        is_recently_modified_older = True

                title_prefix = "[Recently Revised] " if is_recently_modified_older else ""
                product_label = component.capitalize()
                if re.search(r"\b(?:products\.)?sqlalchemyda\b", english_desc, re.IGNORECASE):
                    product_label = "SQLAlchemyDA"
                elif re.search(r"\bfastapi-admin\b", english_desc, re.IGNORECASE):
                    product_label = "fastapi-admin"
                elif re.search(r"\breactos\b", english_desc, re.IGNORECASE):
                    product_label = "ReactOS"

                report_title = f"{title_prefix}{product_label} Advisory: {cve_id}"
                threat_text = f"CVE ID: {cve_id}. Component: {product_label}. {english_desc}"

                metrics = cve_data.get("metrics", {})
                cvss_data = metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {}) if metrics.get("cvssMetricV31") else {}
                severity = cvss_data.get("baseSeverity", "HIGH").lower()

                # Defensive sanitization to prevent MySQL DataError 1406
                clean_title = report_title.strip()[:1000]
                clean_source_url = source_url.strip()[:768]
                clean_cve = (cve_id or "").strip()[:255]
                clean_summary = english_desc
                clean_severity = severity if severity in ('low', 'medium', 'high', 'critical') else 'high'

                try:
                    if not existing:
                        existing = models.ThreatReport(
                            source_url=clean_source_url,
                            title=clean_title,
                            summary=clean_summary,
                            severity=clean_severity,
                            cve_id=clean_cve,
                            published_at=published_dt,
                            stix_bundle={
                                "type": "bundle",
                                "id": f"bundle--{clean_cve.lower()}",
                                "spec_version": "2.1",
                                "objects": [
                                    {
                                        "type": "vulnerability",
                                        "id": f"vulnerability--{clean_cve.lower()}",
                                        "name": clean_title,
                                        "description": clean_summary
                                    }
                                ]
                            }
                        )
                        db.add(existing)
                        db.commit()
                        db.refresh(existing)
                        new_count += 1
                        last_discovered = f"{clean_cve} ({product_label})"
                        log_report_saved(existing.id, existing.title, existing.cve_id)

                        try:
                            add_threat_embedding(
                                threat_id=existing.id,
                                title=existing.title,
                                summary=existing.summary or "",
                                severity=existing.severity,
                                source_url=existing.source_url,
                                cve_id=existing.cve_id,
                                published_at=existing.published_at
                            )
                        except Exception as embed_err:
                            print(f"[-] [ChromaDB Warning] Could not store embedding for targeted CVE: {embed_err}")
                    else:
                        # Check for meaningful updates (e.g. revised summary, changed severity, or newly available published_at)
                        has_update = False
                        if clean_summary and existing.summary != clean_summary and len(clean_summary) > len(existing.summary or ""):
                            existing.summary = clean_summary
                            has_update = True
                        if clean_severity and existing.severity != clean_severity:
                            existing.severity = clean_severity
                            has_update = True
                        if published_dt and not existing.published_at:
                            existing.published_at = published_dt
                            has_update = True

                        if has_update:
                            existing.updated_at = datetime.now(timezone.utc).replace(tzinfo=None)
                            db.commit()
                            updated_count += 1
                            last_discovered = f"{clean_cve} (Updated)"
                            log_report_saved(existing.id, existing.title, existing.cve_id)
                        else:
                            dups_count += 1

                    process_threat_tenant_correlations(db, existing, raw_context=threat_text)
                except Exception as item_err:
                    db.rollback()
                    print(f"[-] Error processing targeted CVE {cve_id}: {item_err}")
            
            # Rate-limit guard for NVD public API
            time.sleep(2.0)
        except Exception as err:
            try:
                db.rollback()
            except Exception:
                pass
            print(f"[-] Error querying targeted NVD for {component}: {err}")

    source_tracker.record_success(source_name, new_count=new_count, updated_count=updated_count, duplicates_count=dups_count, last_item=last_discovered)
    log_ingestion_success(source_name, new_count=new_count, updated_count=updated_count, skipped_count=dups_count)


def fetch_general_osint_feeds(db: Session, lookback_days: int = 30):
    """
    Broad OSINT: Ingests cyber news, ransomware alerts, and CISA advisories.
    Applies configurable lookback window, robust bounded retries, and safe publication date extraction.
    Preserves meaningful updates and deduplicates unchanged entries.
    """
    log_ingestion_start(f"Scanning broad RSS threat intelligence feeds (Lookback: {lookback_days}d)...")
    cutoff_time = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=lookback_days)

    for source_name, feed_url in OSINT_FEEDS.items():
        source_tracker.record_start(source_name)
        log_agent("INGESTION", f"Collecting RSS feed: '{source_name}'...", emoji="📡")
        new_in_feed = 0
        updated_in_feed = 0
        dups_in_feed = 0
        last_item_in_feed = None

        try:
            domain = feed_url.split('/')[2]
            try:
                last_db_entry = db.query(models.ThreatReport).filter(
                    models.ThreatReport.source_url.contains(domain),
                    models.ThreatReport.published_at.isnot(None)
                ).order_by(models.ThreatReport.published_at.desc()).first()
                last_time = last_db_entry.published_at if last_db_entry else cutoff_time
            except Exception as q_err:
                db.rollback()
                last_time = cutoff_time

            res = fetch_feed_with_retry(feed_url, max_retries=2, timeout=12)
            if res.status_code != 200:
                err_msg = f"HTTP {res.status_code} fetching {source_name}"
                source_tracker.record_failure(source_name, err_msg)
                log_ingestion_error(source_name, err_msg)
                continue

            feed = feedparser.parse(res.content)
            if not feed.entries:
                source_tracker.record_success(source_name, 0, 0, 0, None)
                log_ingestion_success(source_name, 0, 0, 0)
                continue

            # Process up to 5 items per feed
            for entry in feed.entries[:5]:
                try:
                    entry_dt = None
                    if hasattr(entry, 'published_parsed') and entry.published_parsed:
                        try:
                            entry_dt = datetime(*entry.published_parsed[:6])
                        except Exception:
                            entry_dt = None
                    elif hasattr(entry, 'updated_parsed') and entry.updated_parsed:
                        try:
                            entry_dt = datetime(*entry.updated_parsed[:6])
                        except Exception:
                            entry_dt = None

                    # Freshness guard: only ingest if published within lookback or newer than last run
                    if entry_dt:
                        if entry_dt < cutoff_time or (last_time and entry_dt <= last_time):
                            continue

                    entry_title = entry.get("title", "Threat Disclosure")
                    entry_summary = entry.get("summary", "")
                    source_url = entry.get("link", "")
                    if not source_url or is_test_fixture(source_url=source_url, title=entry_title):
                        continue

                    raw_feed_text = f"{entry_title}: {entry_summary}"
                    content_fp = compute_content_hash(entry_title, entry_summary)

                    existing = db.query(models.ThreatReport).filter(models.ThreatReport.source_url == source_url).first()
                    if not existing:
                        # Check if article is an actionable security threat before calling LLM
                        is_actionable = any(kw in raw_feed_text.lower() for kw in ACTIONABLE_KEYWORDS)
                        
                        report_data = {}
                        stix_data = None

                        if is_actionable:
                            try:
                                pipeline_result = cyber_scribe_orchestrator.invoke({"raw_text": raw_feed_text})
                                report_data = pipeline_result.get("final_report", {})
                                stix_data = pipeline_result.get("stix_bundle")
                                
                                print("[*] [Rate-Limit Buffer] Pausing 3.5s to preserve LLM quota...")
                                time.sleep(3.5)
                            except Exception as err:
                                err_str = str(err)
                                if "429" in err_str or "RESOURCE_EXHAUSTED" in err_str:
                                    wait_match = re.search(r"retry in (\d+)", err_str)
                                    wait_seconds = int(wait_match.group(1)) + 2 if wait_match else 10
                                    print(f"[*] [Quota Throttle] Rate limit encountered. Backing off for {wait_seconds}s...")
                                    time.sleep(wait_seconds)
                                else:
                                    print(f"[-] Orchestrator fallback for {entry_title}: {err}")
                        else:
                            report_data = {
                                "title": entry_title,
                                "summary": entry_summary[:300] if entry_summary else entry_title,
                                "severity": "low",
                                "cve_id": None
                            }

                        if not stix_data:
                            stix_cve = report_data.get("cve_id") or "advisory"
                            stix_data = {
                                "type": "bundle",
                                "id": f"bundle--{stix_cve.lower()}",
                                "spec_version": "2.1",
                                "objects": [
                                    {
                                        "type": "vulnerability",
                                        "spec_version": "2.1",
                                        "id": f"vulnerability--{stix_cve.lower()}",
                                        "name": report_data.get("title") or entry_title,
                                        "description": report_data.get("summary") or entry_summary
                                    }
                                ]
                            }

                        # Defensive sanitization to prevent MySQL DataError 1406
                        clean_title = (report_data.get("title") or entry_title or "Threat Disclosure").strip()[:1000]
                        clean_source_url = (source_url or "").strip()[:768]
                        clean_cve = report_data.get("cve_id")
                        if clean_cve:
                            clean_cve = str(clean_cve).strip()[:255]
                        clean_summary = report_data.get("summary") or entry_summary or ""
                        raw_sev = str(report_data.get("severity") or "medium").lower()
                        clean_sev = raw_sev if raw_sev in ("low", "medium", "high", "critical") else "medium"

                        existing = models.ThreatReport(
                            source_url=clean_source_url,
                            title=clean_title,
                            summary=clean_summary,
                            severity=clean_sev,
                            cve_id=clean_cve,
                            published_at=entry_dt,
                            stix_bundle=stix_data
                        )
                        db.add(existing)
                        db.commit()
                        db.refresh(existing)
                        new_in_feed += 1
                        last_item_in_feed = clean_title
                        log_report_saved(existing.id, existing.title, existing.cve_id)

                        try:
                            add_threat_embedding(
                                threat_id=existing.id,
                                title=existing.title,
                                summary=existing.summary or "",
                                severity=existing.severity,
                                source_url=existing.source_url,
                                cve_id=existing.cve_id,
                                published_at=existing.published_at
                            )
                        except Exception as embed_err:
                            print(f"[-] [ChromaDB Warning] Could not store embedding for feed threat: {embed_err}")
                    else:
                        # Meaningful update detection: check if summary or title changed
                        old_fp = compute_content_hash(existing.title or "", existing.summary or "")
                        if old_fp != content_fp and len(entry_summary.strip()) > len(existing.summary or ""):
                            existing.summary = entry_summary
                            existing.title = entry_title[:1000]
                            existing.updated_at = datetime.now(timezone.utc).replace(tzinfo=None)
                            db.commit()
                            updated_in_feed += 1
                            last_item_in_feed = f"{entry_title} (Updated)"
                            log_report_saved(existing.id, existing.title, existing.cve_id)
                        else:
                            dups_in_feed += 1

                    process_threat_tenant_correlations(db, existing, raw_context=raw_feed_text)
                except Exception as entry_err:
                    db.rollback()
                    print(f"[-] [RSS Entry Error] Failed to process entry '{entry_title}' from {source_name}: {entry_err}")

            if not last_item_in_feed and feed.entries:
                last_item_in_feed = feed.entries[0].get("title", "Threat Disclosure")

            source_tracker.record_success(
                source_name,
                new_count=new_in_feed,
                updated_count=updated_in_feed,
                duplicates_count=dups_in_feed,
                last_item=last_item_in_feed
            )
            log_ingestion_success(source_name, new_count=new_in_feed, updated_count=updated_in_feed, skipped_count=dups_in_feed)

        except Exception as feed_err:
            try:
                db.rollback()
            except Exception:
                pass
            source_tracker.record_failure(source_name, str(feed_err))
            log_ingestion_error(source_name, str(feed_err))
            print(f"[-] [Isolated Source Error] Error scraping {source_name}: {feed_err}")


def evaluate_existing_eligible_threats(db: Session) -> dict:
    """
    Evaluates existing eligible threat records and open threat matches that have not yet reached
    the response workflow. Ensures that existing unmitigated/affected threats automatically reach
    containment and remediation decisions without requiring manual user interaction.
    """
    evaluated_matches = 0
    auto_contained = 0
    auto_patched = 0

    try:
        from app.services.autonomous_response_orchestrator import AutonomousResponseOrchestrator

        # 1. Process open, unmitigated threat matches
        open_matches = db.query(models.ThreatMatch).filter(
            models.ThreatMatch.status.in_(["OPEN", "open", "unmitigated", "active"])
        ).all()

        for match in open_matches:
            tenant = db.query(models.Tenant).filter(models.Tenant.id == match.tenant_id).first()
            report = db.query(models.ThreatReport).filter(models.ThreatReport.id == match.threat_report_id).first()
            if not tenant or not report:
                continue

            reason = match.ai_matching_reason or ""
            is_affected = "[AFFECTED]" in reason.upper() or "satisfies vulnerable constraint" in reason.lower()
            if not is_affected:
                continue

            # Check if this match already has a patch proposal
            has_prop = db.query(models.PatchProposal).filter(
                models.PatchProposal.tenant_id == tenant.id,
                models.PatchProposal.threat_match_id == match.id
            ).first()

            # Check if report contains a malicious IP and whether containment is already staged
            malicious_ip = AutonomousResponseOrchestrator.extract_malicious_ip_from_report(report)
            has_action = None
            if malicious_ip:
                has_action = db.query(models.ContainmentAction).filter(
                    models.ContainmentAction.tenant_id == tenant.id,
                    models.ContainmentAction.threat_match_id == match.id
                ).first()

            # Trigger orchestrator if proposal or containment is missing, or if policy is AUTO_PATCH and not yet executed
            should_evaluate = not has_prop or (malicious_ip and not has_action)
            if not should_evaluate and tenant.remediation_policy == "AUTO_PATCH" and has_prop:
                if has_prop.status not in ("SIMULATED", "EXECUTED", "SUCCESS_VERIFIED_AND_RELEASED", "AUTO_PATCHED_AND_RESOLVED"):
                    should_evaluate = True

            if should_evaluate:
                try:
                    res = AutonomousResponseOrchestrator.correlate_sbom_and_create_incident(
                        db=db,
                        tenant_id=tenant.id,
                        threat_report_id=report.id,
                        supporting_malicious_ip=malicious_ip,
                        force_auto_patch=False
                    )
                    evaluated_matches += 1
                    if res.get("containment") and res["containment"].get("status") in ("SIMULATED", "APPLIED", "VERIFIED"):
                        auto_contained += 1
                    if res.get("status") in ("AUTO_PATCHED_AND_RESOLVED", "AUTO_PATCH_SIMULATED"):
                        auto_patched += 1
                except Exception as eval_e:
                    db.rollback()
                    print(f"[-] Error evaluating existing threat match {match.id}: {eval_e}")

        # 2. Check for recent un-correlated threat reports that have no match for registered tenants
        recent_reports = db.query(models.ThreatReport).order_by(models.ThreatReport.created_at.desc()).limit(30).all()
        for report in recent_reports:
            match_count = db.query(models.ThreatMatch).filter(models.ThreatMatch.threat_report_id == report.id).count()
            if match_count == 0:
                try:
                    process_threat_tenant_correlations(db, report)
                except Exception as corr_e:
                    db.rollback()
                    print(f"[-] Error evaluating un-correlated threat report {report.id}: {corr_e}")

    except Exception as e:
        print(f"[-] evaluate_existing_eligible_threats error: {e}")

    return {
        "status": "COMPLETED",
        "evaluated_matches": evaluated_matches,
        "auto_contained": auto_contained,
        "auto_patched": auto_patched
    }


def run_sync_sweep(lookback_days: int = 30) -> dict:
    """
    Runs both targeted asset checks and broad OSINT sweeps.
    Protected by concurrency lock to prevent overlapping runs from corrupting state or creating duplicates.
    """
    acquired = _sweep_mutex.acquire(blocking=False)
    if not acquired:
        print("[*] [OSINT Ingestion] Synchronizer sweep already in progress. Overlapping run prevented.")
        return {"status": "SKIPPED", "message": "Synchronizer sweep already in progress."}

    try:
        db: Session = SessionLocal()
        try:
            prune_old_threats(db, retention_days=lookback_days)
            fetch_targeted_cves_for_inventory(db, lookback_days=lookback_days)
            fetch_general_osint_feeds(db, lookback_days=lookback_days)

            # Evaluate existing eligible threats and open unmitigated matches
            try:
                evaluate_existing_eligible_threats(db)
            except Exception as eval_err:
                print(f"[-] Existing threats evaluation warning: {eval_err}")

            # Ingest structured C2 indicators (Feodo Tracker) for automatic threat blocking
            try:
                from app.services.structured_indicator_collector import ingest_and_process_structured_indicators
                ingest_and_process_structured_indicators(db)
            except Exception as struct_err:
                print(f"[-] Structured Indicators Ingestion Warning: {struct_err}")

            # Autonomous Containment Action TTL Expiry Sweep
            try:
                from app.services.firewall_adapter import get_containment_adapter
                active_adapter = get_containment_adapter()
                active_adapter.expire_active_containment_actions(db)
            except Exception as exp_err:
                print(f"[-] Containment Expiry Sweep Warning: {exp_err}")
        except Exception as db_err:
            print(f"[-] Sweep Database Error: {db_err}")
        finally:
            db.close()
        return {"status": "SUCCESS", "message": "OSINT and containment sweep finished successfully."}
    finally:
        _sweep_mutex.release()


_scheduler_started = False


async def fetch_and_process_osint():
    """Continuous OSINT ingestion scheduler running on configurable cadence with bounded error isolation."""
    global _scheduler_started
    if _scheduler_started:
        print("[*] [OSINT Ingestion] Scheduler already active in this process. Skipping duplicate initialization.")
        return
    _scheduler_started = True

    print("[*] [OSINT Ingestion] Initialized continuous background scheduler.")
    try:
        while True:
            try:
                print("\n[*] [OSINT Continuous Agent] Starting scheduled dual-engine ingestion sweep...")
                await asyncio.to_thread(run_sync_sweep, 30)
                print(f"[*] [OSINT Continuous Agent] Sweep complete. Sleeping for {DEFAULT_POLL_INTERVAL_SECONDS} seconds...\n")
            except asyncio.CancelledError:
                raise
            except Exception as loop_err:
                print(f"[-] Sweep error caught in background task (server continues running): {loop_err}")
                traceback.print_exc()

            try:
                await asyncio.sleep(DEFAULT_POLL_INTERVAL_SECONDS)
            except asyncio.CancelledError:
                raise
            except Exception as sleep_err:
                print(f"[-] Sleep interrupted: {sleep_err}")
                await asyncio.sleep(5)
    except asyncio.CancelledError:
        print("[*] [OSINT Ingestion] Scheduler cancelled gracefully on shutdown.")
    finally:
        _scheduler_started = False