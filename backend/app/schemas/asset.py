# backend/app/schemas/asset.py
from pydantic import BaseModel
from typing import Optional

class AssetCreate(BaseModel):
    software_name: str
    software_version: str
    environment: Optional[str] = "production"

class AssetResponse(BaseModel):
    id: str
    software_name: str
    software_version: str
    environment: str

    class Config:
        from_attributes = True