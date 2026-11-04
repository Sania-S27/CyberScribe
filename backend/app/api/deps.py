# backend/app/api/deps.py
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError
from sqlalchemy.orm import Session
from sqlalchemy import text
from typing import Dict, Any

from app.core.database import get_db
from app.core.security import SECRET_KEY, ALGORITHM
from app import models

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

def get_current_user_or_admin(
    token: str = Depends(oauth2_scheme), 
    db: Session = Depends(get_db)
) -> Dict[str, Any]:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        role: str = payload.get("role")
        if email is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    # 1. Check Super Admin
    if role == "super_admin":
        admin = db.query(models.Admin).filter(models.Admin.email == email).first()
        if admin:
            return {"entity": admin, "role": "super_admin", "is_admin": True}

    # 2. Check Standard Tenant User
    user = db.query(models.User).filter(models.User.email == email).first()
    if user:
        if user.tenant_id:
            try:
                db.execute(text("SET @current_tenant_id = :tenant_id;"), {"tenant_id": str(user.tenant_id)})
            except Exception:
                pass
        return {"entity": user, "role": user.role, "is_admin": False}

    raise credentials_exception

def get_current_user(
    token: str = Depends(oauth2_scheme), 
    db: Session = Depends(get_db)
) -> models.User:
    auth_ctx = get_current_user_or_admin(token=token, db=db)
    if auth_ctx.get("is_admin"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access forbidden for this tenant endpoint"
        )
    return auth_ctx["entity"]

def require_super_admin(
    token: str = Depends(oauth2_scheme), 
    db: Session = Depends(get_db)
) -> Dict[str, Any]:
    auth_ctx = get_current_user_or_admin(token=token, db=db)
    if not auth_ctx.get("is_admin") or auth_ctx.get("role") != "super_admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required: Administrative privileges required"
        )
    return auth_ctx