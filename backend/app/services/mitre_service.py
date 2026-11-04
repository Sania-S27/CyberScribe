# backend/app/services/mitre_service.py
import os
import json
import re
import logging
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path

logger = logging.getLogger(__name__)

DATA_DIR = Path(__file__).resolve().parent.parent / "data" / "mitre_attack"
TECHNIQUES_FILE = DATA_DIR / "attack_techniques.json"
METADATA_FILE = DATA_DIR / "metadata.json"

# In-memory cached dataset
_TECHNIQUES_CACHE: Optional[Dict[str, Dict[str, Any]]] = None
_METADATA_CACHE: Optional[Dict[str, Any]] = None

# Curated behavioral pattern rules mapping technical signals to ATT&CK technique IDs
BEHAVIORAL_PATTERNS: List[Tuple[re.Pattern, str, str]] = [
    # Initial Access & Public Exploitation
    (re.compile(r"\b(exploit(ed|ing)?\s+public|remote\s+code\s+execution|unauthenticated\s+rce|public[\s\-_]facing|web\s+server\s+exploit)\b", re.I), "T1190", "Exploit Public-Facing Application"),
    (re.compile(r"\b(spear[\s\-_]?phishing|phishing\s+email|malicious\s+attachment|drive[\s\-_]by)\b", re.I), "T1566", "Phishing"),
    (re.compile(r"\b(valid\s+account|compromised\s+credentials|stolen\s+password|default\s+credentials)\b", re.I), "T1078", "Valid Accounts"),
    (re.compile(r"\b(supply\s+chain|compromised\s+dependency|malicious\s+package|typosquatting)\b", re.I), "T1195", "Supply Chain Compromise"),
    
    # Execution
    (re.compile(r"\b(command\s+injection|command\s+and\s+scripting|powershell|bash|cmd\.exe|executes?\s+arbitrary\s+(commands?|code)|shell\s+command)\b", re.I), "T1059", "Command and Scripting Interpreter"),
    (re.compile(r"\b(exploitation\s+for\s+client\s+execution|malicious\s+document|office\s+macro|buffer\s+overflow\s+in\s+client|client[\s\-_]side\s+execution)\b", re.I), "T1203", "Exploitation for Client Execution"),
    (re.compile(r"\b(windows\s+management\s+instrumentation|wmi\s+execution)\b", re.I), "T1047", "Windows Management Instrumentation"),
    
    # Privilege Escalation
    (re.compile(r"\b(privilege\s+escalation|elevation\s+of\s+privilege|local\s+privilege\s+escalation|lpe|escalates?\s+to\s+root|system\s+privileges)\b", re.I), "T1068", "Exploitation for Privilege Escalation"),
    (re.compile(r"\b(sudo\s+vulnerability|setuid|capabilities\s+abuse)\b", re.I), "T1548", "Abuse Elevation Control Mechanism"),
    
    # Defense Evasion
    (re.compile(r"\b(sandbox\s+escape|container\s+escape|evad(es?|ing)\s+detection|disable\s+security|bypasses?\s+(security|auth|waf|edr))\b", re.I), "T1562", "Impair Defenses"),
    (re.compile(r"\b(masquerading|renamed\s+binary|spoofed\s+process)\b", re.I), "T1036", "Masquerading"),
    (re.compile(r"\b(obfuscation|encoded\s+payload|encrypted\s+script)\b", re.I), "T1027", "Obfuscated Files or Information"),

    # Persistence
    (re.compile(r"\b(web\s*shell|backdoor\s+access|persistent\s+access|implanted\s+webshell)\b", re.I), "T1505.003", "Server Software Component: Web Shell"),
    (re.compile(r"\b(cron\s+job|scheduled\s+task|systemd\s+service\s+persistence)\b", re.I), "T1053", "Scheduled Task/Job"),
    
    # Credential Access
    (re.compile(r"\b(credential\s+dumping|mimikatz|extracts?\s+password|dumping\s+hashes|lsass\s+dump|stolen\s+tokens)\b", re.I), "T1003", "OS Credential Dumping"),
    (re.compile(r"\b(brute[\s\-_]?force|password\s+spraying|credential\s+stuffing)\b", re.I), "T1110", "Brute Force"),
    
    # Discovery & Lateral Movement
    (re.compile(r"\b(network\s+service\s+scanning|port\s+scanning|network\s+discovery)\b", re.I), "T1046", "Network Service Discovery"),
    (re.compile(r"\b(lateral\s+movement|remote\s+services|smb\s+exec|psexec|ssh\s+hijacking)\b", re.I), "T1021", "Remote Services"),
    
    # Command & Control
    (re.compile(r"\b(c2|command\s+and\s+control|c&c|beaconing|reverse\s+shell|covert\s+channel)\b", re.I), "T1071", "Application Layer Protocol"),
    
    # Impact
    (re.compile(r"\b(ransomware|encrypt(ed|s|ing)\s+files|data\s+destruction|wiper|wiping\s+data|denial\s+of\s+service|dos\s+attack)\b", re.I), "T1486", "Data Encrypted for Impact")
]


def load_mitre_knowledge_base() -> Dict[str, Dict[str, Any]]:
    """Loads and caches the official MITRE ATT&CK dataset from the local JSON index."""
    global _TECHNIQUES_CACHE
    if _TECHNIQUES_CACHE is not None:
        return _TECHNIQUES_CACHE

    if not TECHNIQUES_FILE.exists():
        logger.warning(f"[MITRE KB] Dataset index not found at {TECHNIQUES_FILE}. Using empty dataset.")
        _TECHNIQUES_CACHE = {}
        return _TECHNIQUES_CACHE

    try:
        with open(TECHNIQUES_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            _TECHNIQUES_CACHE = data
            logger.info(f"[MITRE KB] Successfully loaded {len(data)} techniques from {TECHNIQUES_FILE}")
            return _TECHNIQUES_CACHE
    except Exception as e:
        logger.error(f"[MITRE KB] Error loading MITRE dataset: {e}", exc_info=True)
        _TECHNIQUES_CACHE = {}
        return _TECHNIQUES_CACHE


def get_dataset_metadata() -> Dict[str, Any]:
    """Returns official dataset metadata, versioning, source URL, and retrieval dates."""
    global _METADATA_CACHE
    if _METADATA_CACHE is not None:
        return _METADATA_CACHE

    if not METADATA_FILE.exists():
        return {
            "dataset_name": "MITRE ATT&CK Enterprise",
            "dataset_version": "v16.1 (Enterprise ATT&CK STIX 2.1)",
            "source_url": "https://github.com/mitre-attack/attack-stix-data",
            "retrieval_date": "2026-10-10",
            "status": "embedded_baseline"
        }

    try:
        with open(METADATA_FILE, "r", encoding="utf-8") as f:
            _METADATA_CACHE = json.load(f)
            return _METADATA_CACHE
    except Exception:
        return {
            "dataset_name": "MITRE ATT&CK Enterprise",
            "dataset_version": "v16.1",
            "source_url": "https://github.com/mitre-attack/attack-stix-data",
            "retrieval_date": "2026-10-10"
        }


def get_technique(technique_id: str, allow_deprecated_or_revoked: bool = False) -> Optional[Dict[str, Any]]:
    """
    Retrieves the authoritative MITRE ATT&CK technique by ID (e.g. 'T1059' or 'T1059.001').
    Excludes revoked and deprecated techniques by default.
    """
    if not technique_id:
        return None

    clean_id = technique_id.strip().upper()
    kb = load_mitre_knowledge_base()
    item = kb.get(clean_id)

    if not item:
        return None

    if not allow_deprecated_or_revoked:
        if item.get("is_revoked") or item.get("is_deprecated"):
            return None

    return item


def is_valid_active_technique(technique_id: str) -> bool:
    """Checks if a technique ID exists and is actively supported (not revoked or deprecated)."""
    return get_technique(technique_id, allow_deprecated_or_revoked=False) is not None


def find_candidate_techniques_for_threat(raw_text: str, top_k: int = 5) -> List[Dict[str, Any]]:
    """
    Analyzes technical text for behavioral signals and returns verified matching candidate techniques from the KB.
    Does NOT map raw vulnerability disclosures lacking adversary behavioral evidence.
    """
    if not raw_text or not raw_text.strip():
        return []

    text_lower = raw_text.lower()
    kb = load_mitre_knowledge_base()
    candidates: List[Dict[str, Any]] = []
    seen_ids = set()

    for pattern, tech_id, default_name in BEHAVIORAL_PATTERNS:
        match = pattern.search(raw_text)
        if match and tech_id not in seen_ids:
            tech_info = kb.get(tech_id)
            if tech_info and not tech_info.get("is_revoked") and not tech_info.get("is_deprecated"):
                seen_ids.add(tech_id)
                evidence_excerpt = match.group(0)
                candidates.append({
                    "technique_id": tech_id,
                    "technique_name": tech_info["name"],
                    "tactic": tech_info.get("primary_tactic", "initial-access"),
                    "matched_evidence": evidence_excerpt,
                    "url": tech_info.get("url", f"https://attack.mitre.org/techniques/{tech_id}")
                })

    return candidates[:top_k]


def format_candidate_techniques_for_prompt(candidates: List[Dict[str, Any]]) -> str:
    """Formats verified candidate techniques into structured guidelines for the Analyst Agent LLM."""
    if not candidates:
        return "No verified MITRE ATT&CK candidate techniques identified from behavioral signals. Do NOT invent technique IDs."

    lines = ["Authoritative Candidate MITRE ATT&CK Techniques (Select ONLY if directly supported by advisory evidence):"]
    for c in candidates:
        lines.append(f"- {c['technique_id']}: {c['technique_name']} (Tactic: {c['tactic']}) [Signal: '{c['matched_evidence']}']")
    return "\n".join(lines)


def validate_and_ground_mitre_mappings(
    raw_text: str,
    proposed_mappings: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """
    Strictly validates proposed MITRE mappings against the authoritative knowledge base.
    1. Validates technique_id exists and is active in official dataset.
    2. Corrects technique_name and tactic to authoritative MITRE catalog values.
    3. Verifies supporting evidence exists in raw_text.
    4. Computes confidence and validation_status ('confirmed' vs 'tentative').
    5. Discards unsupported or hallucinated mappings.
    """
    if not proposed_mappings or not isinstance(proposed_mappings, list):
        return []

    kb = load_mitre_knowledge_base()
    validated_mappings = []
    seen_ids = set()

    raw_lower = (raw_text or "").lower()

    for item in proposed_mappings:
        if not isinstance(item, dict):
            continue

        tech_id = str(item.get("technique_id", "")).strip().upper()
        if not tech_id or tech_id in seen_ids:
            continue

        # Rule 1: Validate against official active MITRE knowledge base
        tech_record = kb.get(tech_id)
        if not tech_record:
            logger.warning(f"[MITRE Validator] Rejected hallucinated/unknown technique ID: {tech_id}")
            continue

        if tech_record.get("is_revoked"):
            logger.warning(f"[MITRE Validator] Rejected revoked technique ID: {tech_id}")
            continue

        if tech_record.get("is_deprecated"):
            logger.warning(f"[MITRE Validator] Rejected deprecated technique ID: {tech_id}")
            continue

        # Rule 2: Enforce authoritative name and primary tactic from MITRE KB
        authoritative_name = tech_record.get("name", "Unknown Technique")
        primary_tactic = tech_record.get("primary_tactic", item.get("tactic", "initial-access"))

        # Rule 3: Search for technical evidence in raw advisory
        supporting_evidence = item.get("evidence") or ""
        confidence = 0.70
        validation_status = "tentative"

        # Check if technical pattern matches advisory text
        matched_patterns = []
        for pattern, pid, _ in BEHAVIORAL_PATTERNS:
            if pid == tech_id or (tech_record.get("is_subtechnique") and tech_id.startswith(pid)):
                p_match = pattern.search(raw_text)
                if p_match:
                    matched_patterns.append(p_match.group(0))

        if matched_patterns:
            supporting_evidence = f"Technical advisory indicates: '{matched_patterns[0]}'"
            confidence = 0.95
            validation_status = "confirmed"
        elif authoritative_name.lower() in raw_lower or tech_id.lower() in raw_lower:
            supporting_evidence = f"Explicit mention of '{authoritative_name}' in advisory text"
            confidence = 0.90
            validation_status = "confirmed"
        else:
            # Fallback check: check if any keyword from technique name appears in text
            name_words = [w for w in re.findall(r"\w+", authoritative_name.lower()) if len(w) > 4]
            name_matches = [w for w in name_words if w in raw_lower]
            if len(name_matches) >= 2:
                supporting_evidence = f"Contextual alignment with keywords: {', '.join(name_matches)}"
                confidence = 0.75
                validation_status = "tentative"
            else:
                # If neither evidence nor behavioral keywords exist, reject ungrounded mapping
                logger.info(f"[MITRE Validator] Discarded ungrounded technique {tech_id} ({authoritative_name}) - insufficient evidence")
                continue

        seen_ids.add(tech_id)
        validated_mappings.append({
            "technique_id": tech_id,
            "technique_name": authoritative_name,
            "tactic": primary_tactic,
            "evidence": supporting_evidence,
            "confidence": confidence,
            "validation_status": validation_status,
            "url": tech_record.get("url", f"https://attack.mitre.org/techniques/{tech_id}")
        })

    return validated_mappings
