# backend/app/agents/validator.py
import json
import os
import re
from typing import Dict, Any, List, Tuple
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.messages import SystemMessage, HumanMessage
from app.core.config import settings
from app.services.mitre_service import validate_and_ground_mitre_mappings
from app.services.version_matcher import check_product_identity_mismatch


def get_validator_client():
    model_name = os.getenv("model_name") or settings.MODEL_NAME or "gemini-1.5-flash"
    api_key = os.getenv("GOOGLE_API_KEY") or settings.GOOGLE_API_KEY or None
    return ChatGoogleGenerativeAI(
        model=model_name,
        temperature=0.1,
        google_api_key=api_key,
        max_retries=2
    )


def verify_claims_against_evidence(raw_text: Any, analyst_draft: Any) -> Tuple[List[str], List[str]]:
    """
    Independently evaluates threat claims against raw text evidence.
    Returns: (validation_errors, correction_instructions)
    """
    if isinstance(raw_text, dict) and isinstance(analyst_draft, str):
        raw_text, analyst_draft = analyst_draft, raw_text

    errors: List[str] = []
    corrections: List[str] = []

    if not analyst_draft or not isinstance(analyst_draft, dict):
        return ["Analyst draft is empty or invalid."], ["Provide a structured threat analysis draft."]

    # 1. CVE ID Grounding
    cve_id = analyst_draft.get("cve_id")
    if cve_id:
        cve_str = str(cve_id).strip()
        if not re.search(rf"\b{re.escape(cve_str)}\b", raw_text, re.IGNORECASE):
            errors.append(f"Claimed CVE ID '{cve_str}' does not appear in the raw advisory text.")
            corrections.append(f"Remove unevidenced CVE ID '{cve_str}' and set cve_id to null.")

    # 2. Product Identity Verification (strictly distinguish derivative tools e.g. SQLAlchemyDA vs core sqlalchemy)
    claimed_products = [str(p).lower().strip() for p in analyst_draft.get("affected_products", [])]
    draft_title_lower = analyst_draft.get("title", "").lower()
    draft_summary_lower = analyst_draft.get("summary", "").lower()

    for base_pkg in ["sqlalchemy", "fastapi", "react", "django", "requests"]:
        has_base_claim = (
            base_pkg in claimed_products or
            re.search(rf"\b{base_pkg}\b", draft_title_lower) or
            re.search(rf"\b{base_pkg}\b", draft_summary_lower)
        )
        if has_base_claim:
            mismatch = check_product_identity_mismatch(base_pkg, raw_text)
            if mismatch:
                distinct_name, distinct_desc = mismatch
                # Check if draft correctly names the distinct derivative or wrongly targets the base package
                if distinct_name.lower() not in claimed_products and distinct_name.lower() not in draft_title_lower:
                    errors.append(
                        f"Product identity mismatch: Source advisory targets distinct component '{distinct_name}' ({distinct_desc}); mismatch with core '{base_pkg}'."
                    )
                    corrections.append(
                        f"Specify distinct component '{distinct_name}' as the target product. If evaluating against core '{base_pkg}', preserve uncertainty and mark finding as NEEDS_REVIEW."
                    )

    # 3. Version Applicability Verification
    claimed_versions = analyst_draft.get("affected_versions", [])
    for v in claimed_versions:
        v_nums = re.findall(r"\d+(?:\.\d+)+", str(v))
        if v_nums:
            if not any(num in raw_text for num in v_nums):
                errors.append(f"Vulnerable version bound '{v}' is not supported by text evidence in the advisory.")
                corrections.append(f"Remove unsupported version constraint '{v}' or indicate that version bounds are unstated.")

    # 4. MITRE ATT&CK Behavioral Evidence Grounding
    raw_mappings = analyst_draft.get("mitre_mappings", [])
    grounded_mappings = validate_and_ground_mitre_mappings(raw_text, raw_mappings)
    if len(raw_mappings) > len(grounded_mappings):
        dropped_count = len(raw_mappings) - len(grounded_mappings)
        errors.append(f"Discarded {dropped_count} MITRE technique(s) lacking textual evidence of adversary behavior.")
        corrections.append("Only map MITRE ATT&CK techniques when explicit evidence of adversary behavior exists in the text.")

    # 5. Severity Realism Check
    claimed_sev = str(analyst_draft.get("severity", "")).lower()
    text_lower = raw_text.lower()
    if claimed_sev in ["critical", "high"]:
        if "denial of service" in text_lower and not any(w in text_lower for w in ["remote code", "rce", "arbitrary code", "privilege escalation", "critical"]):
            errors.append(f"Severity '{claimed_sev}' is ungrounded: advisory describes denial of service without RCE or privilege escalation.")
            corrections.append("Adjust severity to 'medium' or 'low' to reflect documented technical impact.")

    return errors, corrections


def validate_threat_analysis(
    raw_text: Any,
    analyst_draft: Any,
    iteration: int = 1,
    max_retries: int = 2
) -> dict:
    """
    Phase II: Validator Agent evaluates draft against raw text evidence.
    Enforces evidence grounding, product identity preservation, and bounded feedback loop.
    """
    if isinstance(raw_text, dict) and isinstance(analyst_draft, str):
        raw_text, analyst_draft = analyst_draft, raw_text

    if not analyst_draft or not isinstance(analyst_draft, dict):
        return {
            "title": "Empty Draft",
            "summary": "No draft content provided.",
            "severity": "low",
            "cve_id": None,
            "is_valid": False,
            "validation_status": "FAILED",
            "validation_errors": ["Draft is empty."],
            "revision_instructions": "Provide a complete threat analysis draft.",
            "assessment_outcome": "NEEDS_REVIEW",
            "mitre_mappings": []
        }

    # Step 1: Deterministic Evidence-Based Validation
    errors, corrections = verify_claims_against_evidence(raw_text, analyst_draft)

    # Step 2: LLM Validation Pass (bounded; failure never bypasses deterministic checks)
    try:
        system_prompt = """You are the Senior Cyber Threat Validator Agent. Your job is to prevent AI hallucinations.
Verify whether the analyst draft's claims (CVE ID, affected product, version ranges, severity) are strictly supported by the raw text.
If any claim is hallucinated or unevidenced, identify the exact discrepancy.
Return ONLY a valid JSON object matching:
{
  "is_valid": true|false,
  "errors": ["specific discrepancy"],
  "corrections": ["specific correction instruction"]
}"""
        user_prompt = f"ORIGINAL RAW TEXT:\n{raw_text}\n\nANALYST DRAFT JSON:\n{json.dumps(analyst_draft)}"
        client = get_validator_client()
        response = client.invoke([
            SystemMessage(content=system_prompt),
            HumanMessage(content=user_prompt)
        ])
        content = response.content if hasattr(response, "content") else str(response)
        if isinstance(content, list):
            content = "".join([item.get("text", "") if isinstance(item, dict) else str(item) for item in content])
        text = str(content).strip()
        match = re.search(r"```(?:json)?\s*({.*?})\s*```", text, re.DOTALL)
        if match:
            llm_result = json.loads(match.group(1))
        else:
            brace_match = re.search(r"({.*})", text, re.DOTALL)
            llm_result = json.loads(brace_match.group(1)) if brace_match else {}

        if isinstance(llm_result, dict):
            for err in llm_result.get("errors", []):
                if err and err not in errors:
                    errors.append(err)
            for corr in llm_result.get("corrections", []):
                if corr and corr not in corrections:
                    corrections.append(corr)

    except Exception as llm_err:
        # LLM failure must fail safely without bypassing deterministic verification
        print(f"⚠️ [Validator LLM Pass Warning] LLM validation unavailable ({llm_err}). Deterministic evidence rules active.")

    # Programmatic authoritative grounding for MITRE mappings
    grounded_mappings = validate_and_ground_mitre_mappings(
        raw_text,
        analyst_draft.get("mitre_mappings", [])
    )

    sanitized = dict(analyst_draft)
    sanitized["mitre_mappings"] = grounded_mappings

    # Step 3: Handle Retry Limit / Termination
    if errors:
        if iteration >= max_retries:
            # Reached maximum revision attempts: terminate safely and mark NEEDS_REVIEW
            sanitized["is_valid"] = True
            sanitized["validation_status"] = "NEEDS_REVIEW"
            sanitized["assessment_outcome"] = "NEEDS_REVIEW"
            sanitized["validation_errors"] = errors
            sanitized["revision_instructions"] = ""

            # Neutralize unevidenced claims
            if any("CVE ID" in e for e in errors):
                sanitized["cve_id"] = None
            if any("Product identity" in e for e in errors):
                for base in ["sqlalchemy", "fastapi", "react", "django"]:
                    mismatch = check_product_identity_mismatch(base, raw_text)
                    if mismatch:
                        sanitized["affected_products"] = [mismatch[0]]

            orig_title = sanitized.get("title", "Threat Advisory")
            if not orig_title.upper().startswith("[NEEDS REVIEW]"):
                sanitized["title"] = f"[NEEDS REVIEW] {orig_title}"

            return sanitized

        else:
            # Failed within retry limit: request revision from Analyst
            sanitized["is_valid"] = False
            sanitized["validation_status"] = "FAILED"
            sanitized["validation_errors"] = errors
            sanitized["revision_instructions"] = "\n".join(corrections) if corrections else "Revise claims to strictly match source evidence."
            sanitized["assessment_outcome"] = "FAILED"
            return sanitized

    # Step 4: Successfully Validated
    sanitized["is_valid"] = True
    sanitized["validation_status"] = "PASSED"
    sanitized["validation_errors"] = []
    sanitized["revision_instructions"] = ""

    if "[NEEDS REVIEW]" in sanitized.get("title", "").upper() or sanitized.get("assessment_outcome") == "NEEDS_REVIEW":
        sanitized["assessment_outcome"] = "NEEDS_REVIEW"
    else:
        sanitized["assessment_outcome"] = "CONFIRMED"

    return sanitized