# app/schemas/auth.py
from pydantic import BaseModel, EmailStr

class TenantRegister(BaseModel):
    company_name: str
    email: EmailStr
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str
    