from __future__ import annotations

import secrets

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.auth import User
from app.schemas.auth import LoginRequest
from app.security import CSRF_COOKIE, SESSION_COOKIE, generate_token, token_hash, validate_csrf_tokens, verify_password
from app.services.audit_service import record_audit_event
from app.services.auth_service import (
    account_is_locked,
    create_session,
    ip_is_rate_limited,
    register_failed_login,
    register_successful_login,
    resolve_session,
    revoke_session,
)

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


def _client_ip(request: Request) -> str:
    if request.client is None:
        return "unknown"
    return request.client.host


def _require_double_submit_csrf(request: Request) -> str:
    cookie_token = request.cookies.get(CSRF_COOKIE)
    header_token = request.headers.get("X-CSRF-Token")
    if not validate_csrf_tokens(cookie_token, header_token):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="CSRF validation failed")
    return header_token


@router.get("/csrf")
def csrf_token(response: Response) -> dict[str, str]:
    token = generate_token()
    response.set_cookie(CSRF_COOKIE, token, secure=True, httponly=False, samesite="lax", path="/")
    return {"csrf_token": token}


@router.post("/login")
def login(payload: LoginRequest, request: Request, response: Response, db: Session = Depends(get_db)) -> dict[str, object]:
    csrf = _require_double_submit_csrf(request)
    ip = _client_ip(request)
    if ip_is_rate_limited(db, ip):
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Too many failed login attempts")

    user = db.scalar(select(User).where(User.username == payload.username))
    if user is None or not user.is_active:
        register_failed_login(db, None, ip, username=payload.username)
        record_audit_event(db, username=payload.username, action="LOGIN_FAILED", source_ip=ip, user_agent=request.headers.get("user-agent"), status="failed", error_message="Invalid credentials")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    if account_is_locked(user):
        raise HTTPException(status_code=status.HTTP_423_LOCKED, detail="Account temporarily locked")
    if not verify_password(user.password_hash, payload.password):
        register_failed_login(db, user, ip)
        record_audit_event(db, user=user, action="LOGIN_FAILED", source_ip=ip, user_agent=request.headers.get("user-agent"), status="failed", error_message="Invalid credentials")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    register_successful_login(db, user, ip)
    record_audit_event(db, user=user, action="LOGIN_SUCCESS", source_ip=ip, user_agent=request.headers.get("user-agent"))
    raw_session = create_session(db, user, csrf)
    response.set_cookie(SESSION_COOKIE, raw_session, secure=True, httponly=True, samesite="lax", path="/", max_age=8 * 60 * 60)
    return {"success": True, "user": {"id": user.id, "username": user.username}}


@router.post("/logout")
def logout(request: Request, response: Response, db: Session = Depends(get_db)) -> dict[str, bool]:
    _require_double_submit_csrf(request)
    raw_session = request.cookies.get(SESSION_COOKIE)
    if raw_session:
        revoke_session(db, raw_session)
    response.delete_cookie(SESSION_COOKIE, path="/", secure=True, httponly=True, samesite="lax")
    return {"success": True}


@router.get("/me")
def me(request: Request, db: Session = Depends(get_db)) -> dict[str, object]:
    raw_session = request.cookies.get(SESSION_COOKIE)
    if not raw_session:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")
    session = resolve_session(db, raw_session)
    if session is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")
    user = db.get(User, session.user_id)
    if user is None or not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account is disabled")
    return {"id": user.id, "username": user.username, "role": user.role.name}
