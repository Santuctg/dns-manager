from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.database import get_db
from app.dependencies import require_permission
from app.models.auth import User
from app.services.audit_service import query_audit_events

router = APIRouter(prefix="/api/v1/audit", tags=["audit"])


@router.get("")
def index(
    username: str | None = None,
    action: str | None = None,
    object_type: str | None = None,
    status: str | None = None,
    source_ip: str | None = None,
    created_after: datetime | None = None,
    created_before: datetime | None = None,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    _user: User = Depends(require_permission("audit.view")),
):
    rows = query_audit_events(
        db,
        username=username,
        action=action,
        object_type=object_type,
        status=status,
        source_ip=source_ip,
        created_after=created_after,
        created_before=created_before,
        limit=limit,
        offset=offset,
    )
    return [
        {
            "id": row.id,
            "user_id": row.user_id,
            "username": row.username,
            "action": row.action,
            "object_type": row.object_type,
            "object_id": row.object_id,
            "source_ip": row.source_ip,
            "user_agent": row.user_agent,
            "old_value": row.old_value,
            "new_value": row.new_value,
            "status": row.status,
            "error_message": row.error_message,
            "created_at": row.created_at,
        }
        for row in rows
    ]
