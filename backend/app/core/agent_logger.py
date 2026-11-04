"""
CyberScribe Agent Logger
------------------------
Provides standardized, emoji-labelled terminal logging for multi-agent workflows,
threat ingestion, evidence validation, ATT&CK mapping, STIX generation, and containment.
Uses Python's standard logging framework with immediate stdout flushing for real-time visibility.
"""

import sys
import logging
from typing import Optional, List, Any

# Root logger for CyberScribe agents
logger = logging.getLogger("CyberScribe")
logger.setLevel(logging.INFO)

# Attach NullHandler so logger works with standard logging hierarchy without default duplicate console output
logger.addHandler(logging.NullHandler())


def log_agent(agent_name: str, message: str, emoji: str = "🤖", level: str = "INFO") -> None:
    """Core structured log message: {emoji} [{AGENT_NAME}] {message}"""
    formatted = f"{emoji} [{agent_name.upper()}] {message}"
    if level == "ERROR":
        logger.error(formatted)
    elif level == "WARNING":
        logger.warning(formatted)
    else:
        logger.info(formatted)
    try:
        print(formatted, flush=True)
    except (UnicodeEncodeError, OSError):
        try:
            enc = sys.stdout.encoding or "utf-8"
            safe_formatted = formatted.encode(enc, errors="replace").decode(enc)
            print(safe_formatted, flush=True)
        except Exception:
            safe_ascii = formatted.encode("ascii", errors="replace").decode("ascii")
            print(safe_ascii, flush=True)


# --- Ingestion Logs ---

def log_ingestion_start(message: str = "Starting threat-feed collection...") -> None:
    log_agent("INGESTION", message, emoji="🔄")


def log_ingestion_success(source_name: str, new_count: int, updated_count: int, skipped_count: int) -> None:
    log_agent(
        "INGESTION",
        f"{source_name} processed: {new_count} new, {updated_count} updated, {skipped_count} skipped.",
        emoji="✅"
    )


def log_ingestion_error(source_name: str, error_msg: str) -> None:
    log_agent(
        "INGESTION",
        f"Feed collection failed for '{source_name}': {error_msg}",
        emoji="❌",
        level="ERROR"
    )


# --- Security Analyst Agent Logs ---

def log_analyst_start(threat_context: str) -> None:
    summary = threat_context.splitlines()[0][:70] if threat_context else "Advisory"
    log_agent("ANALYST", f"Analysing threat intelligence: '{summary}'...", emoji="🔍")


def log_analyst_complete(title: str, severity: str, cve_id: Optional[str] = None) -> None:
    cve_str = f" ({cve_id})" if cve_id else ""
    log_agent(
        "ANALYST",
        f"Draft analysis completed: '{title[:60]}' | Severity: {severity.upper()}{cve_str}",
        emoji="📋"
    )


def log_analyst_retry(iteration: int, max_retries: int, reason: str = "") -> None:
    extra = f": {reason[:80]}" if reason else ""
    log_agent(
        "ANALYST",
        f"Revising analysis draft (attempt {iteration}/{max_retries}){extra}",
        emoji="🔄"
    )


# --- Validator Agent Logs ---

def log_validator_start(title: str) -> None:
    log_agent("VALIDATOR", f"Validating extracted findings for '{title[:60]}'...", emoji="🛡️")


def log_validator_passed(title: str) -> None:
    log_agent("VALIDATOR", f"Findings verified and evidence grounded: '{title[:60]}'", emoji="✅")


def log_validator_needs_review(title: str, reason: str = "") -> None:
    extra = f" Reason: {reason[:100]}" if reason else ""
    log_agent(
        "VALIDATOR",
        f"Finding requires manual review: '{title[:60]}'.{extra}",
        emoji="⚠️",
        level="WARNING"
    )


def log_validator_failed(title: str, errors: List[str]) -> None:
    err_preview = "; ".join(errors[:2]) if errors else "Discrepancies identified"
    log_agent(
        "VALIDATOR",
        f"Validation rejected ungrounded claims for '{title[:50]}': {err_preview}",
        emoji="❌",
        level="WARNING"
    )


# --- MITRE ATT&CK & STIX Logs ---

def log_mitre_mapping(techniques: List[str]) -> None:
    t_str = ", ".join(techniques) if techniques else "None mapped"
    log_agent("ATT&CK", f"Mapping threat behaviours: {t_str}", emoji="🧠")


def log_stix_bundle(bundle_id: str, objects_count: int) -> None:
    log_agent("STIX", f"Generating STIX 2.1 bundle ({objects_count} objects, ID: {bundle_id})...", emoji="📦")


# --- Report & Correlation Logs ---

def log_report_saving(title: str) -> None:
    log_agent("REPORT", f"Generating threat report: '{title[:60]}'...", emoji="📝")


def log_report_saved(report_id: str, title: str, cve_id: Optional[str] = None) -> None:
    cve_str = f" [{cve_id}]" if cve_id else ""
    log_agent("REPORT", f"Report saved successfully: '{title[:50]}'{cve_str} (ID: {report_id[:8]}...)", emoji="✅")


def log_correlation_match(tenant_name: str, outcome: str, component: str) -> None:
    emoji = "🚨" if outcome == "AFFECTED" else "⚠️" if outcome == "NEEDS_REVIEW" else "ℹ️"
    log_agent(
        "CORRELATION",
        f"Tenant '{tenant_name}' matched component '{component}' -> [{outcome}]",
        emoji=emoji
    )


# --- Containment & SOAR Logs ---

def log_containment_eval(indicator: str, decision: str) -> None:
    emoji = "🛡️" if decision == "QUALIFIED" else "🚫"
    log_agent("CONTAINMENT", f"Evaluating indicator '{indicator}' -> Policy: {decision}", emoji=emoji)


def log_containment_action(action_id: str, status: str, details: str = "") -> None:
    emoji = "✅" if status in ("APPLIED", "VERIFIED", "SIMULATED", "ROLLED_BACK") else "❌"
    log_agent("CONTAINMENT", f"Action {action_id} -> Status: {status} ({details})", emoji=emoji)


def log_soar_dispatch(tenant_name: str, playbook_name: str, status: str) -> None:
    emoji = "✅" if status in ("DISPATCHED", "RECEIVED") else "❌"
    log_agent("SOAR", f"Playbook '{playbook_name[:40]}' to '{tenant_name}' -> Status: {status}", emoji=emoji)
