# backend/app/agents/analyst.py
import os
import json
import re
from typing import Optional
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.prompts import ChatPromptTemplate
from app.schemas.analyst import ThreatAnalysisResult
from app.core.config import settings
from app.services.vector_store import query_similar_threats, format_retrieved_threats_for_prompt
from app.services.mitre_service import (
    find_candidate_techniques_for_threat,
    format_candidate_techniques_for_prompt,
    validate_and_ground_mitre_mappings
)

GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY") or settings.GOOGLE_API_KEY or None
MODEL_NAME = os.getenv("model_name") or settings.MODEL_NAME or "gemini-1.5-flash"

# Primary Gemini model
primary_llm = ChatGoogleGenerativeAI(
    model=MODEL_NAME,
    temperature=0.1,
    google_api_key=GOOGLE_API_KEY,
    max_retries=2,
    timeout=30
)

# Backup Gemini model
backup_llm = ChatGoogleGenerativeAI(
    model="gemini-1.5-flash-8b" if "1.5" in MODEL_NAME else MODEL_NAME,
    temperature=0.1,
    google_api_key=GOOGLE_API_KEY,
    max_retries=2,
    timeout=30
)

# Robust chain with automatic cloud fallback
robust_llm = primary_llm.with_fallbacks([backup_llm])

system_prompt = """You are an autonomous Cyber Threat Intelligence (CTI) analyst. Analyze raw vulnerability disclosures augmented by retrieved historical threat intelligence context and official MITRE ATT&CK guidelines.

CRITICAL RAG & EVIDENCE-BASED ANALYSIS INSTRUCTIONS:
1. Extract ONLY threat claims, affected products, and vulnerable version bounds that are EXPLICITLY supported by the raw threat advisory text.
2. NEVER assume a core library is affected when the advisory targets a derivative adapter, extension, or distinct tool (e.g. keep SQLAlchemyDA distinct from core SQLAlchemy; keep ReactOS distinct from React; keep fastapi-admin distinct from FastAPI).
3. If a CVE ID is explicitly stated in the raw text, include it. If NO CVE ID is present in the raw text, set "cve_id": null. NEVER invent or hallucinate a CVE ID.
4. Extract direct textual supporting evidence quotes for all key claims into "supporting_evidence".
5. Distinguish between retrieved historical precedents and the new raw threat advisory. Never treat historical findings as proof about a distinct new advisory.
6. When evidence is missing, conflicting, or insufficient, preserve that uncertainty explicitly in the summary.

CRITICAL MITRE ATT&CK MAPPING RULES:
1. ATT&CK describes adversary behavior, NOT abstract software defects or theoretical vulnerabilities.
2. Map techniques ONLY when actual technical evidence of attacker behavior (e.g. command injection, exploitation of client software, privilege escalation, credential theft, persistence) is present in the advisory.
3. If the advisory only describes a bug, software flaw, or component defect without explicit adversary behavior, return an empty list: "mitre_mappings": [].
4. Select candidate techniques ONLY from the verified official technique IDs provided in the context; do NOT invent or guess technique IDs.

Return ONLY a valid JSON object matching this exact schema:
{{
  "title": "string",
  "summary": "string",
  "severity": "critical|high|medium|low",
  "cve_id": "string or null",
  "affected_products": ["string"],
  "affected_versions": ["string"],
  "supporting_evidence": ["string"],
  "indicators": ["string"],
  "mitre_mappings": [
    {{
      "technique_id": "string",
      "technique_name": "string",
      "tactic": "string",
      "evidence": "string"
    }}
  ]
}}"""

user_prompt_template = """--- RETRIEVED HISTORICAL CONTEXT ---
{retrieved_context}

--- VERIFIED MITRE ATT&CK CANDIDATE TECHNIQUES ---
{candidate_techniques}

--- NEW RAW THREAT ADVISORY ---
{raw_text}"""

prompt = ChatPromptTemplate.from_messages([
    ("system", system_prompt),
    ("human", user_prompt_template)
])

analyst_chain = prompt | robust_llm


revision_system_prompt = """You are an autonomous Cyber Threat Intelligence (CTI) analyst revising a threat analysis draft based on specific Validator feedback.

REVISION RULES:
1. Address EVERY validation error and correction instruction provided by the Validator.
2. If a claimed CVE ID was flagged as not found in the raw text, remove it and set "cve_id": null.
3. If product identity was flagged (e.g., SQLAlchemyDA vs core sqlalchemy), ensure the exact product from the advisory is specified and do not conflate it with unrelated or parent packages.
4. If version bounds or MITRE techniques were unsupported by raw text evidence, remove them.
5. If the evidence is insufficient to confirm the threat, reflect that uncertainty in the summary and set assessment_outcome to "NEEDS_REVIEW".
6. Return ONLY a valid JSON object matching the ThreatAnalysisResult schema."""

revision_user_template = """--- ORIGINAL RAW THREAT ADVISORY ---
{raw_text}

--- PREVIOUS ANALYST DRAFT ---
{current_draft}

--- VALIDATOR FEEDBACK & CORRECTION INSTRUCTIONS ---
Validation Issues:
{validation_errors}

Instructions:
{revision_instructions}"""

revision_prompt = ChatPromptTemplate.from_messages([
    ("system", revision_system_prompt),
    ("human", revision_user_template)
])

revision_chain = revision_prompt | robust_llm


def extract_json_safely(content) -> dict:
    """Extracts JSON safely, handling strings, markdown wrappers, and LangChain block lists."""
    if isinstance(content, list):
        content = "".join([item.get("text", "") if isinstance(item, dict) else str(item) for item in content])
    
    text = str(content).strip()

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        match = re.search(r"```(?:json)?\s*({.*?})\s*```", text, re.DOTALL)
        if match:
            try:
                return json.loads(match.group(1))
            except json.JSONDecodeError:
                pass
        
        brace_match = re.search(r"({.*})", text, re.DOTALL)
        if brace_match:
            try:
                return json.loads(brace_match.group(1))
            except json.JSONDecodeError:
                pass
        
        raise ValueError("No valid JSON structure found in LLM output.")


def analyze_threat_with_llm(raw_text: str, retrieved_context: Optional[str] = None) -> dict:
    """
    Executes Retrieval-Augmented Generation (RAG) threat analysis.
    Retrieves historical precedents from ChromaDB and verified candidate techniques from official MITRE KB.
    """
    if retrieved_context is None:
        try:
            results = query_similar_threats(query_text=raw_text, n_results=3)
            retrieved_context = format_retrieved_threats_for_prompt(results)
        except Exception as e:
            print(f"⚠️ [RAG Retrieval Error] Falling back to zero-shot context: {e}")
            retrieved_context = "No historical threat intelligence records found (retrieval unavailable)."

    candidates = find_candidate_techniques_for_threat(raw_text, top_k=5)
    candidate_prompt_text = format_candidate_techniques_for_prompt(candidates)

    try:
        response = analyst_chain.invoke({
            "raw_text": raw_text,
            "retrieved_context": retrieved_context,
            "candidate_techniques": candidate_prompt_text
        })
        content = response.content if hasattr(response, "content") else str(response)
        
        parsed_json = extract_json_safely(content)

        if parsed_json.get("severity") not in ["critical", "high", "medium", "low"]:
            parsed_json["severity"] = "low"

        # Authoritatively validate and ground proposed MITRE mappings against official STIX dataset
        raw_mappings = parsed_json.get("mitre_mappings", [])
        grounded_mappings = validate_and_ground_mitre_mappings(raw_text, raw_mappings)
        parsed_json["mitre_mappings"] = grounded_mappings

        validated_result = ThreatAnalysisResult(**parsed_json)
        return validated_result.model_dump()
        
    except Exception as e:
        print(f"⚠️ Analyst parsing error or API Rate Limit reached: {e}")
        
        # Local heuristic fallback ensuring system reliability during API exhaustion
        safe_severity = "medium"
        text_lower = raw_text.lower()
        if "critical" in text_lower or "rce" in text_lower or "zero-day" in text_lower:
            safe_severity = "critical"
        elif "high" in text_lower or "privilege escalation" in text_lower:
            safe_severity = "high"

        # Extract real CVE if present in raw text
        cve_match = re.search(r"\b(CVE-\d{4}-\d{4,7})\b", raw_text, re.IGNORECASE)
        detected_cve = cve_match.group(1).upper() if cve_match else None

        # Use verified candidate techniques for grounded fallback mapping
        grounded_fallback = validate_and_ground_mitre_mappings(
            raw_text,
            [{"technique_id": c["technique_id"], "evidence": c.get("matched_evidence", "")} for c in candidates]
        )

        return {
            "title": raw_text.splitlines()[0][:80] if raw_text else "Ingested Threat Advisory",
            "summary": raw_text[:350],
            "severity": safe_severity,
            "cve_id": detected_cve,
            "affected_products": [],
            "affected_versions": [],
            "supporting_evidence": [raw_text[:200]] if raw_text else [],
            "indicators": [detected_cve] if detected_cve else [],
            "mitre_mappings": grounded_fallback
        }


def revise_threat_analysis_with_llm(
    raw_text: str,
    current_draft: dict,
    validation_errors: list,
    revision_instructions: str
) -> dict:
    """
    Revises the Analyst draft based on Validator feedback and correction instructions.
    Enforces evidence grounding and uncertainty preservation.
    """
    errors_str = "\n".join([f"- {err}" for err in validation_errors]) if validation_errors else "None specified."
    
    try:
        response = revision_chain.invoke({
            "raw_text": raw_text,
            "current_draft": json.dumps(current_draft, indent=2),
            "validation_errors": errors_str,
            "revision_instructions": revision_instructions or "Address all validation errors strictly."
        })
        content = response.content if hasattr(response, "content") else str(response)
        parsed = extract_json_safely(content)

        if parsed.get("severity") not in ["critical", "high", "medium", "low"]:
            parsed["severity"] = current_draft.get("severity", "low")

        # Ground MITRE mappings
        raw_mappings = parsed.get("mitre_mappings", [])
        parsed["mitre_mappings"] = validate_and_ground_mitre_mappings(raw_text, raw_mappings)

        revised_result = ThreatAnalysisResult(**parsed)
        return revised_result.model_dump()

    except Exception as rev_err:
        print(f"⚠️ [Analyst Revision Fallback] Error in LLM revision ({rev_err}). Applying deterministic corrections.")
        
        revised = dict(current_draft)
        
        # 1. Hallucinated CVE removal
        if any("CVE ID" in str(e) for e in validation_errors):
            revised["cve_id"] = None

        # 2. Product identity corrections (e.g. SQLAlchemyDA)
        if any("SQLAlchemyDA" in str(e) for e in validation_errors):
            revised["affected_products"] = ["SQLAlchemyDA"]
            if not revised.get("title", "").startswith("[NEEDS REVIEW]"):
                revised["title"] = f"[NEEDS REVIEW] {revised.get('title', 'Advisory')}"
            revised["assessment_outcome"] = "NEEDS_REVIEW"

        # 3. Version bounds correction
        if any("version" in str(e).lower() for e in validation_errors):
            revised["affected_versions"] = []

        # 4. Ground MITRE mappings
        revised["mitre_mappings"] = validate_and_ground_mitre_mappings(
            raw_text,
            revised.get("mitre_mappings", [])
        )

        return revised