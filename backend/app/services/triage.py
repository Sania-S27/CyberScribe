# backend/app/services/triage.py
import re
from typing import Optional

CRITICAL_TERMS = [
    r"\brce\b",
    r"\bremote code execution\b",
    r"\bzero-day\b",
    r"\b0-day\b",
    r"\bunauthenticated\b",
    r"\barbitrary code\b",
    r"\barbitrary command execution\b"
]

HIGH_TERMS = [
    r"\bprivilege escalation\b",
    r"\bauthentication bypass\b",
    r"\bsqli\b",
    r"\bsql injection\b",
    r"\bcommand injection\b",
    r"\bpath traversal\b",
    r"\bssrf\b",
    r"\bserver-side request forgery\b"
]

MEDIUM_TERMS = [
    r"\bdenial of service\b",
    r"\bdos\b",
    r"\bxss\b",
    r"\bcross-site scripting\b",
    r"\binformation disclosure\b",
    r"\bcsrf\b",
    r"\bcross-site request forgery\b"
]

# Prefixes/qualifiers indicating the absence of or mitigation against the threat
NEGATION_PATTERNS = [
    r"\bnot\s+(?:currently\s+)?(?:vulnerable|susceptible|subject|affected|exposed)?(?:\s+(?:to|by))?\b",
    r"\bno\s+(?:known|active|direct)?\b",
    r"\bdoes\s+not\s+(?:allow|permit|lead\s+to|cause|result\s+in|enable|affect)?\b",
    r"\bdoesn\'t\s+(?:allow|permit|lead\s+to|cause|result\s+in|enable|affect)?\b",
    r"\bcannot\s+(?:be\s+used\s+to|lead\s+to|cause|result\s+in|enable)?\b",
    r"\bprevents?\s+(?:any\s+)?\b",
    r"\bmitigates?\s+(?:any\s+)?\b",
    r"\bwithout\s+(?:allowing|permitting|requiring)?\b",
    r"\bneither\s+\b",
]

NEGATION_REGEX = re.compile("|".join(NEGATION_PATTERNS), re.IGNORECASE)


def _is_unnegated_match(text: str, pattern: str) -> bool:
    """Checks whether pattern matches text outside of any immediate negative context."""
    for match in re.finditer(pattern, text, re.IGNORECASE):
        start = match.start()
        # Look back to the start of the current sentence or clause (up to 120 chars)
        last_break = max(text.rfind('.', 0, start), text.rfind(';', 0, start), text.rfind('\n', 0, start))
        clause_start = max(0, last_break + 1, start - 120)
        clause = text[clause_start:start]
        if NEGATION_REGEX.search(clause):
            continue
        return True
    return False


def predict_threat_severity(description: str, trusted_severity: Optional[str] = None) -> str:
    """
    Runs fast, zero-dependency heuristic classification on threat text for preliminary triage.
    
    Guards:
    1. Never silently overrides trusted NVD or validated findings: returns trusted_severity if provided.
    2. Uses strict word boundaries to eliminate false positives on ambiguous substrings (e.g. 'dos' in 'windows').
    3. Handles negation qualifiers (e.g. 'not vulnerable to RCE', 'does not permit denial of service').
    """
    # 1. Authoritative trusted severity guard
    if trusted_severity:
        norm_trusted = str(trusted_severity).strip().lower()
        if norm_trusted in ("critical", "high", "medium", "low"):
            return norm_trusted

    if not description or not str(description).strip():
        return "medium"
    
    text = str(description).lower()
    
    # 2. Critical evaluation
    for pat in CRITICAL_TERMS:
        if _is_unnegated_match(text, pat):
            return "critical"
            
    # 3. High evaluation
    for pat in HIGH_TERMS:
        if _is_unnegated_match(text, pat):
            return "high"
            
    # 4. Medium evaluation
    for pat in MEDIUM_TERMS:
        if _is_unnegated_match(text, pat):
            return "medium"
            
    return "low"