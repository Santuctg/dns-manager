from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.dependencies import require_permission
from app.models.auth import User
from app.schemas.mapping import MappingCreate, MappingRead, MappingUpdate
from app.security import CSRF_COOKIE, SESSION_COOKIE, token_hash, validate_csrf_tokens
from app.services.auth_service import resolve_session
from app.services.audit_service import record_audit_event
from app.services.mapping_service import (
    MappingConflictError,
    MappingNotFoundError,
    create_mapping,
    delete_mapping,
    get_mapping,
    list_mappings,
    update_mapping,
)

router = APIRouter(prefix="/api/v1/mappings", tags=["mappings"])


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _snapshot(row) -> dict[str, object]:
    return {
        "id": row.id, "domain": row.domain, "upstream_scheme": row.upstream_scheme,
        "upstream_host": row.upstream_host, "upstream_port": row.upstream_port,
        "enabled": row.enabled, "websocket_enabled": row.websocket_enabled,
        "preserve_host": row.preserve_host, "tls_verify": row.tls_verify,
        "custom_timeout": row.custom_timeout, "description": row.description,
        "version": row.version,
    }


def _require_csrf(request: Request, db: Session) -> None:
    cookie = request.cookies.get(CSRF_COOKIE)
    submitted = request.headers.get("X-CSRF-Token")
    if not validate_csrf_tokens(cookie, submitted):
        raise HTTPException(status_code=403, detail="CSRF validation failed")
    raw_session = request.cookies.get(SESSION_COOKIE)
    session = resolve_session(db, raw_session) if raw_session else None
    if session is None or session.csrf_hash != token_hash(submitted):
        raise HTTPException(status_code=403, detail="CSRF validation failed")


def _translate(exc: Exception) -> HTTPException:
    if isinstance(exc, MappingNotFoundError):
        return HTTPException(status_code=404, detail="Mapping not found")
    return HTTPException(status_code=409, detail=str(exc))


@router.get("", response_model=list[MappingRead])
def index(
    db: Session = Depends(get_db),
    _user: User = Depends(require_permission("mapping.view")),
):
    return list_mappings(db)


@router.get("/{mapping_id}", response_model=MappingRead)
def show(
    mapping_id: int,
    db: Session = Depends(get_db),
    _user: User = Depends(require_permission("mapping.view")),
):
    try:
        return get_mapping(db, mapping_id)
    except MappingNotFoundError as exc:
        raise _translate(exc)


@router.post("", response_model=MappingRead, status_code=status.HTTP_201_CREATED)
def create(
    payload: MappingCreate,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("mapping.create")),
):
    _require_csrf(request, db)
    try:
        row = create_mapping(db, payload, user.id)
        record_audit_event(db, user=user, action="MAPPING_CREATED", object_type="mapping", object_id=row.id, source_ip=_client_ip(request), user_agent=request.headers.get("user-agent"), new_value=_snapshot(row))
        return row
    except MappingConflictError as exc:
        raise _translate(exc)


@router.put("/{mapping_id}", response_model=MappingRead)
def update(
    mapping_id: int,
    payload: MappingUpdate,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("mapping.update")),
):
    _require_csrf(request, db)
    try:
        before = _snapshot(get_mapping(db, mapping_id))
        row = update_mapping(db, mapping_id, payload, user.id)
        record_audit_event(db, user=user, action="MAPPING_UPDATED", object_type="mapping", object_id=row.id, source_ip=_client_ip(request), user_agent=request.headers.get("user-agent"), old_value=before, new_value=_snapshot(row))
        return row
    except (MappingConflictError, MappingNotFoundError) as exc:
        raise _translate(exc)


@router.delete("/{mapping_id}", status_code=status.HTTP_204_NO_CONTENT)
def remove(
    mapping_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("mapping.delete")),
):
    _require_csrf(request, db)
    try:
        row = get_mapping(db, mapping_id)
        before = _snapshot(row)
        delete_mapping(db, mapping_id)
        record_audit_event(db, user=user, action="MAPPING_DELETED", object_type="mapping", object_id=mapping_id, source_ip=_client_ip(request), user_agent=request.headers.get("user-agent"), old_value=before)
    except MappingNotFoundError as exc:
        raise _translate(exc)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
