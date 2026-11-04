# backend/app/schemas/analyst.py
from typing import List, Optional, Any
from pydantic import BaseModel, Field, field_validator

class MitreMapping(BaseModel):
    technique_id: str = Field(default="T1059", description="Authoritative MITRE ATT&CK Technique ID")
    technique_name: str = Field(default="Command and Scripting Interpreter", description="Authoritative MITRE Technique Name")
    tactic: str = Field(default="execution", description="Associated MITRE ATT&CK Tactic name")
    evidence: Optional[str] = Field(default=None, description="Direct textual evidence excerpt supporting this mapping")
    confidence: Optional[float] = Field(default=0.90, description="Confidence score (0.0 to 1.0) for this mapping")
    validation_status: Optional[str] = Field(default="confirmed", description="Validation status: confirmed, tentative, unverified")
    url: Optional[str] = Field(default=None, description="Official MITRE ATT&CK technique URL")

class ThreatAnalysisResult(BaseModel):
    title: str = Field(description="Descriptive vulnerability advisory title")
    summary: str = Field(description="Executive technical summary of the threat")
    severity: str = Field(default="medium", description="Severity rating: critical, high, medium, or low")
    cve_id: Optional[str] = Field(default=None, description="Associated CVE ID")
    affected_products: List[str] = Field(default_factory=list, description="Affected software products identified in the advisory")
    affected_versions: List[str] = Field(default_factory=list, description="Vulnerable version bounds explicitly supported by evidence")
    supporting_evidence: List[str] = Field(default_factory=list, description="Direct textual evidence excerpts supporting threat claims")
    indicators: List[str] = Field(default_factory=list, description="Network or file indicators extracted from advisory")
    assessment_outcome: str = Field(default="CONFIRMED", description="Assessment outcome: CONFIRMED or NEEDS_REVIEW")
    validation_status: str = Field(default="PASSED", description="Validation status: PASSED, FAILED, or NEEDS_REVIEW")
    validation_errors: List[str] = Field(default_factory=list, description="Issues identified during validation")
    mitre_mappings: List[MitreMapping] = Field(default_factory=list, description="List of mapped MITRE ATT&CK techniques")

    @field_validator("mitre_mappings", mode="before")
    @classmethod
    def parse_mitre_mappings(cls, v: Any):
        if not isinstance(v, list):
            return []
        cleaned = []
        for item in v:
            if isinstance(item, str):
                cleaned.append({"technique_id": item, "technique_name": item, "tactic": "initial-access"})
            elif isinstance(item, dict):
                # Ensure 'tactic' key exists to prevent missing attribute errors
                if "tactic" not in item:
                    item["tactic"] = "initial-access"
                cleaned.append(item)
            elif isinstance(item, MitreMapping):
                cleaned.append(item.model_dump())
            elif hasattr(item, "model_dump"):
                cleaned.append(item.model_dump())
        return cleaned