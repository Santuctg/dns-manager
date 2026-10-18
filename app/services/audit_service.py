from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.audit import AuditLog
from app.models.auth import User

SENSITIVE_KEYS = {"password", "password_hash", "session", "session_token", "csrf", "csrf_token", "token", "secret"}


def _sanitize(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _sanitize(v) for k, v in value.items() if k.lower() not in SENSITIVE_KEYS}
    if isinstance(value, (list, tuple)):
        return [_sanitize(v) for v in value]
    if isinstance(value, datetime):
        return value.isoformat()
    return value


def _dump(value: Any | None) -> str | None:
    if value is None:
        return None
    return json.dumps(_sanitize(value), separators=(",", ":"), sort_keys=True, default=str)


def record_audit_event(
    db: Session,
    *,
    action: str,
    user: User | None = None,
    username: str | None = None,
    object_type: str | None = None,
    object_id: str | int | None = None,
    source_ip: str | None = None,
    user_agent: str | None = None,
    old_value: Any | None = None,
    new_value: Any | None = None,
    status: str = "success",
    error_message: str | None = None,
) -> AuditLog:
    row = AuditLog(
        user_id=user.id if user else None,
        username=user.username if user else username,
        action=action,
        object_type=object_type,
        object_id=str(object_id) if object_id is not None else None,
        source_ip=source_ip,
        user_agent=user_agent,
        old_value=_dump(old_value),
        new_value=_dump(new_value),
        status=status,
        error_message=error_message,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def query_audit_events(
    db: Session,
    *,
    username: str | None = None,
    action: str | None = None,
    object_type: str | None = None,
    status: str | None = None,
    source_ip: str | None = None,
    created_after: datetime | None = None,
    created_before: datetime | None = None,
    limit: int = 100,
    offset: int = 0,
) -> list[AuditLog]:
    stmt = select(AuditLog)
    if username:
        stmt = stmt.where(AuditLog.username == username)
    if action:
        stmt = stmt.where(AuditLog.action == action)
    if object_type:
        stmt = stmt.where(AuditLog.object_type == object_type)
    if status:
        stmt = stmt.where(AuditLog.status == status)
    if source_ip:
        stmt = stmt.where(AuditLog.source_ip == source_ip)
    if created_after:
        stmt = stmt.where(AuditLog.created_at >= created_after)
    if created_before:
        stmt = stmt.where(AuditLog.created_at <= created_before)
    stmt = stmt.order_by(AuditLog.created_at.desc(), AuditLog.id.desc()).offset(offset).limit(min(max(limit, 1), 500))
    return list(db.scalars(stmt).all())
