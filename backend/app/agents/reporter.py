from app.schemas.analyst import ThreatAnalysisResult
from app.schemas.reporter import StixBundle, VulnerabilityObject, AttackPatternObject, get_stix_id

def generate_stix_report(analysis: ThreatAnalysisResult) -> StixBundle:
    """Phase IV: Converts analyzed threat intelligence into a standardized STIX 2.1 JSON bundle."""
    stix_objects = []

    is_needs_review = (
        getattr(analysis, "assessment_outcome", "") == "NEEDS_REVIEW" or
        getattr(analysis, "validation_status", "") == "NEEDS_REVIEW" or
        "[NEEDS REVIEW]" in (analysis.title or "").upper()
    )

    # 1. Core Vulnerability Object (Preserves uncertainty explicitly)
    report_title = analysis.title
    if is_needs_review and not report_title.upper().startswith("[NEEDS REVIEW]"):
        report_title = f"[NEEDS REVIEW] {report_title}"

    report_desc = analysis.summary
    if is_needs_review and not report_desc.startswith("[UNCERTAIN FINDING"):
        report_desc = f"[UNCERTAIN FINDING - NEEDS SOC REVIEW] {report_desc}"

    vuln = VulnerabilityObject(
        id=get_stix_id("vulnerability"),
        name=f"Threat Report: {report_title}",
        description=report_desc
    )
    stix_objects.append(vuln.model_dump())

    # 2. Attack Pattern Objects for MITRE mappings
    for mapping in analysis.mitre_mappings:
        description_parts = [f"Maps to MITRE ATT&CK Tactic: {mapping.tactic}"]
        if getattr(mapping, "evidence", None):
            description_parts.append(f"Evidence: {mapping.evidence}")

        conf_score = mapping.confidence if getattr(mapping, "confidence", None) is not None else 0.90
        val_status = mapping.validation_status or "confirmed"

        # If overall report is uncertain, cap confidence and denote unverified status
        if is_needs_review:
            conf_score = min(conf_score, 0.50)
            val_status = "unverified"

        description_parts.append(f"Confidence: {conf_score:.2f}")
        description_parts.append(f"Status: {val_status}")

        attack_pattern = AttackPatternObject(
            id=get_stix_id("attack-pattern"),
            name=mapping.technique_name,
            description=" | ".join(description_parts),
            external_references=[
                {
                    "source_name": "mitre-attack",
                    "external_id": mapping.technique_id,
                    "url": getattr(mapping, "url", None) or f"https://attack.mitre.org/techniques/{mapping.technique_id}"
                }
            ]
        )
        stix_objects.append(attack_pattern.model_dump())

    return StixBundle(objects=stix_objects)