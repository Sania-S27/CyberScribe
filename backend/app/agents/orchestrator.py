from typing import TypedDict, Dict, Any, List, Optional
from langgraph.graph import StateGraph, END
from app.agents.analyst import analyze_threat_with_llm, revise_threat_analysis_with_llm
from app.agents.validator import validate_threat_analysis
from app.agents.reporter import generate_stix_report
from app.schemas.analyst import ThreatAnalysisResult
from app.core.agent_logger import (
    log_analyst_start,
    log_analyst_complete,
    log_analyst_retry,
    log_validator_start,
    log_validator_passed,
    log_validator_needs_review,
    log_validator_failed,
    log_mitre_mapping,
    log_stix_bundle,
    log_report_saving
)

class ThreatState(TypedDict):
    raw_text: str
    retrieved_context: Optional[str]
    analyst_draft: Dict[str, Any]
    validation_status: str       # "PASSED", "FAILED", "NEEDS_REVIEW"
    validation_errors: List[str]
    revision_instructions: Optional[str]
    iteration_count: int         # revision attempt counter
    max_retries: int             # finite retry limit (default: 2)
    final_report: Dict[str, Any]
    stix_bundle: Dict[str, Any]

def security_analyst_node(state: ThreatState):
    iteration = state.get("iteration_count", 0)
    validation_errors = state.get("validation_errors", [])
    revision_instructions = state.get("revision_instructions")

    if iteration > 0 and (validation_errors or revision_instructions):
        err_str = "; ".join(validation_errors[:2]) if validation_errors else "Revision requested"
        log_analyst_retry(iteration, state.get("max_retries", 2), err_str)
        draft = revise_threat_analysis_with_llm(
            raw_text=state["raw_text"],
            current_draft=state.get("analyst_draft", {}),
            validation_errors=validation_errors,
            revision_instructions=revision_instructions or "Address validation errors strictly."
        )
    else:
        log_analyst_start(state["raw_text"])
        draft = analyze_threat_with_llm(
            raw_text=state["raw_text"],
            retrieved_context=state.get("retrieved_context")
        )

    log_analyst_complete(
        title=draft.get("title", "Threat Advisory"),
        severity=draft.get("severity", "medium"),
        cve_id=draft.get("cve_id")
    )

    return {
        "analyst_draft": draft,
        "iteration_count": iteration + 1
    }

def validator_node(state: ThreatState):
    iteration = state.get("iteration_count", 1)
    max_retries = state.get("max_retries", 2)
    draft_title = state.get("analyst_draft", {}).get("title", "Threat Finding")

    log_validator_start(draft_title)

    validated = validate_threat_analysis(
        raw_text=state["raw_text"],
        analyst_draft=state.get("analyst_draft", {}),
        iteration=iteration,
        max_retries=max_retries
    )

    val_status = validated.get("validation_status", "PASSED")
    val_errors = validated.get("validation_errors", [])
    rev_instructions = validated.get("revision_instructions", "")

    val_title = validated.get("title", draft_title)
    if val_status == "PASSED":
        log_validator_passed(val_title)
    elif val_status == "NEEDS_REVIEW":
        log_validator_needs_review(val_title, "; ".join(val_errors) if val_errors else "Human review required")
    else:
        log_validator_failed(val_title, val_errors)

    return {
        "final_report": validated,
        "validation_status": val_status,
        "validation_errors": val_errors,
        "revision_instructions": rev_instructions
    }

def should_continue(state: ThreatState) -> str:
    """
    Evaluates validation outcome and enforces finite retry limit.
    Transitions to Tech Writer Agent on PASSED or NEEDS_REVIEW,
    or loops back to Analyst Agent if FAILED and retries remain.
    """
    status = (
        state.get("validation_status") or
        (state.get("final_report", {}) if isinstance(state.get("final_report"), dict) else {}).get("validation_status") or
        (state.get("analyst_draft", {}) if isinstance(state.get("analyst_draft"), dict) else {}).get("validation_status") or
        "PASSED"
    )
    iteration = state.get("iteration_count") if state.get("iteration_count") is not None else state.get("iteration", 1)
    max_retries = state.get("max_retries", 2)

    # Validated claims or bounded termination -> proceed to reporting
    if status in ["PASSED", "NEEDS_REVIEW"]:
        return "Tech Writer Agent"

    # Validation failed and within retry budget -> request revision
    if iteration <= max_retries:
        return "Security Analyst Agent"

    # Finite retry limit exceeded -> terminate safely to Tech Writer Agent
    return "Tech Writer Agent"

def tech_writer_reporter_node(state: ThreatState):
    report_dict = state.get("final_report") or state.get("analyst_draft", {})
    try:
        analysis_obj = ThreatAnalysisResult(**report_dict)
    except Exception:
        # Fallback to minimal valid schema if validation fails
        analysis_obj = ThreatAnalysisResult(
            title=report_dict.get("title", "Threat Advisory"),
            summary=report_dict.get("summary", "Summary not available"),
            severity=report_dict.get("severity", "medium"),
            cve_id=report_dict.get("cve_id"),
            mitre_mappings=[]
        )

    # Log MITRE ATT&CK mapping stage
    mappings = getattr(analysis_obj, "mitre_mappings", []) or []
    if mappings:
        technique_ids = [getattr(m, "technique_id", str(m)) for m in mappings]
        log_mitre_mapping(technique_ids)

    log_report_saving(analysis_obj.title)
    stix_bundle = generate_stix_report(analysis_obj)

    bundle_id = getattr(stix_bundle, "id", "bundle")
    objects_count = len(getattr(stix_bundle, "objects", []))
    log_stix_bundle(str(bundle_id)[:18], objects_count)

    return {"stix_bundle": stix_bundle.model_dump()}

# LangGraph Multi-Agent Orchestration with Bounded Validation Feedback Loop
workflow = StateGraph(ThreatState)

workflow.add_node("Security Analyst Agent", security_analyst_node)
workflow.add_node("Validator Agent", validator_node)
workflow.add_node("Tech Writer Agent", tech_writer_reporter_node)

workflow.set_entry_point("Security Analyst Agent")
workflow.add_edge("Security Analyst Agent", "Validator Agent")
workflow.add_conditional_edges(
    "Validator Agent",
    should_continue,
    {
        "Security Analyst Agent": "Security Analyst Agent",
        "Tech Writer Agent": "Tech Writer Agent"
    }
)
workflow.add_edge("Tech Writer Agent", END)

cyber_scribe_orchestrator = workflow.compile()