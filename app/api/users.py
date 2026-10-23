from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, selectinload

from app.database import get_db
from app.dependencies import require_permission
from app.models.auth import Role, User, UserSession
from app.schemas.user import PasswordReset, PasswordResetResult, UserCreate, UserRead, UserUpdate
from app.security import CSRF_COOKIE, SESSION_COOKIE, hash_password, token_hash, validate_csrf_tokens
from app.services.auth_service import resolve_session
from app.services.audit_service import record_audit_event

router = APIRouter(prefix='/api/v1/users', tags=['users'])


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else 'unknown'


def _require_csrf(request: Request, db: Session) -> None:
    cookie = request.cookies.get(CSRF_COOKIE)
    submitted = request.headers.get('X-CSRF-Token')
    if not validate_csrf_tokens(cookie, submitted):
        raise HTTPException(status_code=403, detail='CSRF validation failed')
    raw_session = request.cookies.get(SESSION_COOKIE)
    session = resolve_session(db, raw_session) if raw_session else None
    if session is None or session.csrf_hash != token_hash(submitted):
        raise HTTPException(status_code=403, detail='CSRF validation failed')


def _get_user(db: Session, user_id: int) -> User:
    row = db.scalar(select(User).options(selectinload(User.role)).where(User.id == user_id))
    if row is None:
        raise HTTPException(status_code=404, detail='User not found')
    return row


def _get_role(db: Session, role_id: int) -> Role:
    row = db.get(Role, role_id)
    if row is None:
        raise HTTPException(status_code=404, detail='Role not found')
    return row


def _is_super_admin(user: User) -> bool:
    return user.role is not None and user.role.name == 'super_admin'


def _protect_target(actor: User, target: User) -> None:
    if _is_super_admin(target) and not _is_super_admin(actor):
        raise HTTPException(status_code=403, detail='Only Super Admin can manage Super Admin accounts')


def _permission_names(role: Role | None) -> set[str]:
    return {permission.name for permission in role.permissions} if role is not None else set()


def _within_actor_permissions(actor: User, role: Role | None) -> bool:
    return _is_super_admin(actor) or _permission_names(role) <= _permission_names(actor.role)


def _protect_assignment(actor: User, role: Role) -> None:
    if role.name == 'super_admin' and not _is_super_admin(actor):
        raise HTTPException(status_code=403, detail='Only Super Admin can assign Super Admin role')
    if not _within_actor_permissions(actor, role):
        raise HTTPException(status_code=403, detail='Cannot assign a role with permissions you do not have')


def _protect_privileged_target(actor: User, target: User) -> None:
    # Changing or resetting a more privileged account would let the actor take it over.
    _protect_target(actor, target)
    if not _within_actor_permissions(actor, target.role):
        raise HTTPException(status_code=403, detail='Cannot manage a user whose role has permissions you do not have')


def _snapshot(user: User) -> dict[str, object]:
    return {
        'id': user.id, 'username': user.username, 'email': user.email,
        'is_active': user.is_active, 'role': user.role.name if user.role else None,
    }


def _revoke_user_sessions(db: Session, user_id: int) -> None:
    now = datetime.now(timezone.utc)
    sessions = list(db.scalars(select(UserSession).where(UserSession.user_id == user_id, UserSession.revoked_at.is_(None))).all())
    for session in sessions:
        session.revoked_at = now


def _would_remove_last_active_super_admin(db: Session, target: User, new_role: Role | None, new_active: bool | None) -> bool:
    if not _is_super_admin(target) or not target.is_active:
        return False
    removes = (new_role is not None and new_role.name != 'super_admin') or new_active is False
    if not removes:
        return False
    count = db.scalar(select(func.count(User.id)).join(Role).where(Role.name == 'super_admin', User.is_active.is_(True))) or 0
    return count <= 1


@router.get('', response_model=list[UserRead])
def index(db: Session = Depends(get_db), _actor: User = Depends(require_permission('user.view'))):
    return list(db.scalars(select(User).options(selectinload(User.role)).order_by(User.username)).all())


@router.get('/{user_id}', response_model=UserRead)
def show(user_id: int, db: Session = Depends(get_db), actor: User = Depends(require_permission('user.view'))):
    target = _get_user(db, user_id)
    _protect_target(actor, target)
    return target


@router.post('', response_model=UserRead, status_code=status.HTTP_201_CREATED)
def create(payload: UserCreate, request: Request, db: Session = Depends(get_db), actor: User = Depends(require_permission('user.create'))):
    _require_csrf(request, db)
    role = _get_role(db, payload.role_id)
    _protect_assignment(actor, role)
    row = User(username=payload.username, email=payload.email, password_hash=hash_password(payload.password), role=role, is_active=True)
    db.add(row)
    try:
        db.commit(); db.refresh(row)
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail='Username or email already exists')
    row = _get_user(db, row.id)
    record_audit_event(db, user=actor, action='USER_CREATED', object_type='user', object_id=row.id, source_ip=_client_ip(request), user_agent=request.headers.get('user-agent'), new_value=_snapshot(row))
    return row


@router.put('/{user_id}', response_model=UserRead)
def update(user_id: int, payload: UserUpdate, request: Request, db: Session = Depends(get_db), actor: User = Depends(require_permission('user.update'))):
    _require_csrf(request, db)
    target = _get_user(db, user_id)
    _protect_privileged_target(actor, target)
    role = _get_role(db, payload.role_id) if payload.role_id is not None else None
    if role is not None:
        _protect_assignment(actor, role)
    if actor.id == target.id:
        if payload.is_active is False:
            raise HTTPException(status_code=409, detail='Cannot deactivate your own account')
        if role is not None and role.id != target.role_id:
            raise HTTPException(status_code=409, detail='Cannot change your own role')
    if _would_remove_last_active_super_admin(db, target, role, payload.is_active):
        raise HTTPException(status_code=409, detail='Cannot remove the last active Super Admin')

    before = _snapshot(target)
    if payload.username is not None: target.username = payload.username
    if 'email' in payload.model_fields_set: target.email = payload.email
    if role is not None: target.role = role
    if payload.is_active is not None:
        target.is_active = payload.is_active
        if not target.is_active:
            _revoke_user_sessions(db, target.id)
    try:
        db.commit(); db.refresh(target)
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail='Username or email already exists')
    target = _get_user(db, target.id)
    record_audit_event(db, user=actor, action='USER_UPDATED', object_type='user', object_id=target.id, source_ip=_client_ip(request), user_agent=request.headers.get('user-agent'), old_value=before, new_value=_snapshot(target))
    return target


@router.post('/{user_id}/reset-password', response_model=PasswordResetResult)
def reset_password(user_id: int, payload: PasswordReset, request: Request, db: Session = Depends(get_db), actor: User = Depends(require_permission('user.update'))):
    _require_csrf(request, db)
    target = _get_user(db, user_id)
    _protect_privileged_target(actor, target)
    target.password_hash = hash_password(payload.password)
    target.failed_login_count = 0
    target.locked_until = None
    _revoke_user_sessions(db, target.id)
    db.commit()
    record_audit_event(db, user=actor, action='USER_PASSWORD_RESET', object_type='user', object_id=target.id, source_ip=_client_ip(request), user_agent=request.headers.get('user-agent'))
    return PasswordResetResult()


@router.delete('/{user_id}', status_code=status.HTTP_204_NO_CONTENT)
def deactivate(user_id: int, request: Request, db: Session = Depends(get_db), actor: User = Depends(require_permission('user.delete'))):
    _require_csrf(request, db)
    target = _get_user(db, user_id)
    _protect_privileged_target(actor, target)
    if actor.id == target.id:
        raise HTTPException(status_code=409, detail='Cannot deactivate your own account')
    if _would_remove_last_active_super_admin(db, target, None, False):
        raise HTTPException(status_code=409, detail='Cannot remove the last active Super Admin')
    before = _snapshot(target)
    target.is_active = False
    _revoke_user_sessions(db, target.id)
    db.commit()
    target = _get_user(db, target.id)
    record_audit_event(db, user=actor, action='USER_DEACTIVATED', object_type='user', object_id=target.id, source_ip=_client_ip(request), user_agent=request.headers.get('user-agent'), old_value=before, new_value=_snapshot(target))
    return Response(status_code=status.HTTP_204_NO_CONTENT)
