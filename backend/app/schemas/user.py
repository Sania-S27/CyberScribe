from pydantic import BaseModel, EmailStr, HttpUrl
from typing import Optional

class UserRegister(BaseModel):
    company_name: str
    email: EmailStr
    password: str
    webhook_url: Optional[str] = None
    auth_token: Optional[str] = None

class TechStackUpdate(BaseModel):
    tech_stack: str
    webhook_url: Optional[str] = None
    auth_token: Optional[str] = None