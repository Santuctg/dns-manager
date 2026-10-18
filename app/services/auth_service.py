from __future__ import annotations

from datetime import datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.auth import LoginAttempt, Permission, Role, User, UserSession
from app.security import (
    ACCOUNT_LOCK_DURATION,
    IP_RATE_LIMIT,
    IP_RATE_WINDOW,
    SESSION_IDLE_TIMEOUT,
    SESSION_LIFETIME,
    generate_token,
    normalize_datetime,
    token_hash,
    utcnow,
)

ALL_PERMISSIONS = {
    "mapping.view", "mapping.create", "mapping.update", "mapping.delete",
    "config.apply", "config.rollback",
    "user.view", "user.create", "user.update", "user.delete",
    "role.view", "role.manage", "audit.view", "system.view", "system.manage",
    "backup.create", "backup.restore", "firewall.manage",
}
ADMIN_PERMISSIONS = {
    "mapping.view", "mapping.create", "mapping.update", "mapping.delete",
    "config.apply", "audit.view", "system.view",
    "user.view", "user.create", "user.update", "user.delete", "role.view",
}
VIEWER_PERMISSIONS = {"mapping.view", "audit.view", "system.view"}


def has_permission(user: User, permission_name: str) -> bool:
    if not user.is_active or user.role is None:
        return False
    return any(permission.name == permission_name for permission in user.role.permissions)


def seed_default_rbac(db: Session) -> None:
    permission_rows: dict[str, Permission] = {}
    for name in sorted(ALL_PERMISSIONS):
        row = db.scalar(select(Permission).where(Permission.name == name))
        if row is None:
            row = Permission(name=name)
            db.add(row)
        permission_rows[name] = row
    db.flush()

    role_map = {
        "super_admin": ALL_PERMISSIONS,
        "admin": ADMIN_PERMISSIONS,
        "viewer": VIEWER_PERMISSIONS,
    }
    for role_name, names in role_map.items():
        role = db.scalar(select(Role).where(Role.name == role_name))
        if role is None:
            role = Role(name=role_name, description=role_name.replace("_", " ").title())
            db.add(role)
        role.permissions = [permission_rows[name] for name in sorted(names)]
    db.commit()


def ip_is_rate_limited(db: Session, ip_address: str, *, now: datetime | None = None) -> bool:
    now = now or utcnow()
    cutoff = now - IP_RATE_WINDOW
    count = db.scalar(
        select(func.count(LoginAttempt.id)).where(
            LoginAttempt.ip_address == ip_address,
            LoginAttempt.success.is_(False),
            LoginAttempt.created_at >= cutoff,
        )
    ) or 0
    return count >= IP_RATE_LIMIT


def register_failed_login(db: Session, user: User | None, ip_address: str, *, username: str | None = None, now: datetime | None = None) -> None:
    now = now or utcnow()
    db.add(LoginAttempt(ip_address=ip_address, username=username or (user.username if user else ""), success=False, created_at=now))
    if user is not None:
        user.failed_login_count += 1
        if user.failed_login_count >= 10:
            user.locked_until = now + ACCOUNT_LOCK_DURATION
    db.commit()


def register_successful_login(db: Session, user: User, ip_address: str, *, now: datetime | None = None) -> None:
    now = now or utcnow()
    db.add(LoginAttempt(ip_address=ip_address, username=user.username, success=True, created_at=now))
    user.failed_login_count = 0
    user.locked_until = None
    user.last_login_at = now
    db.commit()


def account_is_locked(user: User, *, now: datetime | None = None) -> bool:
    now = now or utcnow()
    locked_until = normalize_datetime(user.locked_until)
    return locked_until is not None and locked_until > now


def create_session(db: Session, user: User, csrf_token: str, *, now: datetime | None = None) -> str:
    now = now or utcnow()
    raw_token = generate_token()
    db.add(UserSession(
        user_id=user.id,
        token_hash=token_hash(raw_token),
        csrf_hash=token_hash(csrf_token),
        created_at=now,
        last_seen_at=now,
        expires_at=now + SESSION_LIFETIME,
    ))
    db.commit()
    return raw_token


def resolve_session(db: Session, raw_token: str, *, now: datetime | None = None) -> UserSession | None:
    now = now or utcnow()
    session = db.scalar(select(UserSession).where(UserSession.token_hash == token_hash(raw_token)))
    if session is None or session.revoked_at is not None:
        return None
    expires_at = normalize_datetime(session.expires_at)
    last_seen = normalize_datetime(session.last_seen_at)
    if expires_at is None or expires_at <= now or last_seen is None or last_seen + SESSION_IDLE_TIMEOUT <= now:
        return None
    session.last_seen_at = now
    db.commit()
    return session


def revoke_session(db: Session, raw_token: str, *, now: datetime | None = None) -> None:
    session = db.scalar(select(UserSession).where(UserSession.token_hash == token_hash(raw_token)))
    if session is not None and session.revoked_at is None:
        session.revoked_at = now or utcnow()
        db.commit()
