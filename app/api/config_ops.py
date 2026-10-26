from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.database import get_db
from app.dependencies import require_permission
from app.models.auth import User
from app.security import CSRF_COOKIE, SESSION_COOKIE, token_hash, validate_csrf_tokens
from app.services.apply_service import (
    ConfigLockedError,
    apply_pending_config,
    preview_config,
    rollback_revision,
    validate_pending_config,
)
from app.services.audit_service import record_audit_event
from app.services.auth_service import resolve_session
from app.services.revision_service import (
    get_active_revision,
    get_pending_change_count,
    get_pending_domains,
    list_revisions,
)

router = APIRouter(prefix="/api/v1/config", tags=["configuration"])


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _require_csrf(request: Request, db: Session) -> None:
    cookie = request.cookies.get(CSRF_COOKIE)
    submitted = request.headers.get("X-CSRF-Token")
    if not validate_csrf_tokens(cookie, submitted):
        raise HTTPException(status_code=403, detail="CSRF validation failed")
    raw_session = request.cookies.get(SESSION_COOKIE)
    session = resolve_session(db, raw_session) if raw_session else None
    if session is None or session.csrf_hash != token_hash(submitted):
        raise HTTPException(status_code=403, detail="CSRF validation failed")


def _internal_proxy_ip() -> str:
    value = get_settings().internal_proxy_ip
    if not value:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="DNS_MANAGER_INTERNAL_PROXY_IP is not configured",
        )
    return value


@router.get("/preview")
def preview(
    db: Session = Depends(get_db),
    _user: User = Depends(require_permission("config.apply")),
):
    result = preview_config(db, internal_proxy_ip=_internal_proxy_ip())
    active = get_active_revision(db)
    return {
        **result,
        "pending_change_count": get_pending_change_count(db),
        "active_revision_id": active.id if active else None,
        "active_revision": active.revision if active else None,
        "active_dnsmasq_config": active.dnsmasq_config if active else None,
        "active_nginx_config": active.nginx_config if active else None,
    }


@router.get("/pending")
def pending(
    db: Session = Depends(get_db),
    _user: User = Depends(require_permission("mapping.view")),
):
    domains = get_pending_domains(db)
    return {"count": len(domains), "domains": domains}


@router.get("/revisions")
def revisions(
    page: int = 1,
    db: Session = Depends(get_db),
    _user: User = Depends(require_permission("config.rollback")),
):
    rows, total = list_revisions(db, page=page, per_page=50)
    creator_ids = {row.created_by for row in rows if row.created_by is not None}
    usernames = {
        user_id: username
        for user_id, username in db.execute(
            select(User.id, User.username).where(User.id.in_(creator_ids))
        ).all()
    } if creator_ids else {}
    return {
        "items": [
            {
                "id": row.id,
                "revision": row.revision,
                "created_at": row.created_at,
                "created_by": row.created_by,
                "created_by_username": usernames.get(row.created_by),
                "status": row.status,
            }
            for row in rows
        ],
        "total": total,
        "page": max(int(page), 1),
        "per_page": 50,
    }


@router.post("/validate")
def validate(
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("config.apply")),
):
    _require_csrf(request, db)
    try:
        revision = validate_pending_config(
            db,
            internal_proxy_ip=_internal_proxy_ip(),
            created_by=user.id,
        )
    except ConfigLockedError:
        raise HTTPException(status_code=409, detail="CONFIG_LOCKED")
    except Exception as exc:
        record_audit_event(
            db, user=user, action="CONFIG_VALIDATE_FAILED", object_type="config_revision",
            source_ip=_client_ip(request), user_agent=request.headers.get("user-agent"),
            status="failed", error_message=str(exc),
        )
        raise HTTPException(status_code=422, detail=str(exc))
    record_audit_event(
        db, user=user, action="CONFIG_VALIDATED", object_type="config_revision",
        object_id=revision.id, source_ip=_client_ip(request), user_agent=request.headers.get("user-agent"),
        new_value={"revision": revision.revision, "status": revision.status},
    )
    return {"revision_id": revision.id, "revision": revision.revision, "status": revision.status}


@router.post("/apply")
def apply(
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("config.apply")),
):
    _require_csrf(request, db)
    ssl_sync: dict = {"updated": [], "failed": []}
    try:
        revision = apply_pending_config(
            db,
            internal_proxy_ip=_internal_proxy_ip(),
            created_by=user.id,
            user=user,
            ssl_sync_out=ssl_sync,
        )
    except ConfigLockedError:
        raise HTTPException(status_code=409, detail="CONFIG_LOCKED")
    except Exception as exc:
        record_audit_event(
            db, user=user, action="CONFIG_APPLY_FAILED", object_type="config_revision",
            source_ip=_client_ip(request), user_agent=request.headers.get("user-agent"),
            status="failed", error_message=str(exc),
        )
        raise HTTPException(status_code=500, detail="Configuration apply failed")
    record_audit_event(
        db, user=user, action="CONFIG_APPLIED", object_type="config_revision",
        object_id=revision.id, source_ip=_client_ip(request), user_agent=request.headers.get("user-agent"),
        new_value={"revision": revision.revision, "status": revision.status},
    )
    return {
        "revision_id": revision.id,
        "revision": revision.revision,
        "status": revision.status,
        "ssl_sync": ssl_sync,
    }


@router.post("/rollback/{revision_id}")
def rollback(
    revision_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("config.rollback")),
):
    _require_csrf(request, db)
    try:
        restored = rollback_revision(db, revision_id=revision_id)
    except ConfigLockedError:
        raise HTTPException(status_code=409, detail="CONFIG_LOCKED")
    except (LookupError, ValueError) as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    except Exception as exc:
        record_audit_event(
            db, user=user, action="CONFIG_ROLLBACK_FAILED", object_type="config_revision",
            object_id=revision_id, source_ip=_client_ip(request), user_agent=request.headers.get("user-agent"),
            status="failed", error_message=str(exc),
        )
        raise HTTPException(status_code=500, detail="Configuration rollback failed")
    record_audit_event(
        db, user=user, action="CONFIG_ROLLED_BACK", object_type="config_revision",
        object_id=revision_id, source_ip=_client_ip(request), user_agent=request.headers.get("user-agent"),
        new_value={"restored_revision": restored.revision},
    )
    return {"restored_revision_id": restored.id, "restored_revision": restored.revision, "status": restored.status}
