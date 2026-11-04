# backend/app/api/auth.py
from datetime import datetime, timedelta
from typing import Optional, Dict, Any

from fastapi import APIRouter, Depends, HTTPException, status, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import verify_password, get_password_hash, create_access_token
from app.api.deps import get_current_user_or_admin, get_current_user
from app import models

router = APIRouter(prefix="/auth", tags=["Authentication"])

class UserRegisterRequest(BaseModel):
    company_name: str
    email: str
    password: str

class UserLoginRequest(BaseModel):
    email: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None

@router.post("/register")
def register_tenant(payload: UserRegisterRequest, db: Session = Depends(get_db)):
    clean_email = payload.email.strip().lower()
    existing_user = db.query(models.User).filter(models.User.email == clean_email).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="User with this email already exists")

    new_tenant = models.Tenant(company_name=payload.company_name, tech_stack="")
    db.add(new_tenant)
    db.commit()
    db.refresh(new_tenant)

    hashed = get_password_hash(payload.password)
    new_user = models.User(
        email=clean_email,
        password_hash=hashed,
        role="tenant_admin",
        tenant_id=new_tenant.id
    )
    db.add(new_user)
    db.commit()

    return {"status": "success", "message": "Tenant registered successfully"}

@router.post("/login")
async def login(request: Request, db: Session = Depends(get_db)):
    email = None
    password = None

    try:
        json_data = await request.json()
        email = json_data.get("email") or json_data.get("username")
        password = json_data.get("password")
    except Exception:
        try:
            form_data = await request.form()
            email = form_data.get("email") or form_data.get("username")
            password = form_data.get("password")
        except Exception:
            pass

    if not email or not password:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Both email and password are required"
        )

    clean_email = email.strip().lower()
    clean_password = password.strip()

    # 1. Look up in Admin table
    admin = db.query(models.Admin).filter(models.Admin.email == clean_email).first()
    if admin and admin.password_hash and verify_password(clean_password, admin.password_hash):
        token = create_access_token(data={"sub": admin.email, "role": "super_admin", "admin_id": admin.id})
        return {"access_token": token, "token_type": "bearer", "role": "super_admin"}

    # 2. Look up in Standard Users table
    user = db.query(models.User).filter(models.User.email == clean_email).first()
    if user and user.password_hash and verify_password(clean_password, user.password_hash):
        token = create_access_token(data={"sub": user.email, "role": user.role, "tenant_id": user.tenant_id})
        return {"access_token": token, "token_type": "bearer", "role": user.role}

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid email or password"
    )

@router.get("/me")
def get_session_profile(
    auth_ctx: dict = Depends(get_current_user_or_admin),
    db: Session = Depends(get_db)
):
    role = auth_ctx["role"]
    entity = auth_ctx["entity"]

    if role == "super_admin":
        return {
            "id": entity.id,
            "email": entity.email,
            "role": "super_admin",
            "company_name": "Platform Operations"
        }

    tenant = db.query(models.Tenant).filter(models.Tenant.id == entity.tenant_id).first()
    return {
        "id": entity.id,
        "email": entity.email,
        "role": entity.role,
        "tenant_id": entity.tenant_id,
        "company_name": tenant.company_name if tenant else "Configured Tenant",
        "tech_stack": tenant.tech_stack if tenant and tenant.tech_stack else ""
    }