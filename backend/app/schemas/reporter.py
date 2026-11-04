import uuid
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field

def get_stix_id(object_type: str) -> str:
    return f"{object_type}--{uuid.uuid4()}"

class VulnerabilityObject(BaseModel):
    type: str = "vulnerability"
    spec_version: str = "2.1"
    id: str
    name: str
    description: str

class AttackPatternObject(BaseModel):
    type: str = "attack-pattern"
    spec_version: str = "2.1"
    id: str
    name: str
    description: str
    external_references: List[Dict[str, Any]] = []

class StixBundle(BaseModel):
    type: str = "bundle"
    id: str = Field(default_factory=lambda: f"bundle--{uuid.uuid4()}")
    objects: List[Dict[str, Any]]