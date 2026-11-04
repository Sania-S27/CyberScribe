from pydantic import BaseModel
from typing import Optional, Any, Dict
from datetime import datetime

class ThreatReportBase(BaseModel):
    title: str
    summary: str
    severity: str
    cve_id: Optional[str] = None
    source_url: Optional[str] = None
    published_at: Optional[datetime] = None

class ThreatReportResponse(ThreatReportBase):
    id: str
    stix_bundle: Optional[Dict[str, Any]] = None
    created_at: datetime

    class Config:
        from_attributes = True

class ThreatMatchResponse(BaseModel):
    id: str
    threat_id: str
    threat_title: Optional[str] = None
    cve_id: Optional[str] = None
    severity: str
    summary: Optional[str] = None
    ai_confidence_score: float
    ai_matching_reason: Optional[str] = None
    status: str
    published_at: Optional[datetime] = None
    created_at: Optional[datetime] = None

    class Config:
        from_attributes = True