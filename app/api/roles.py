from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from app.database import get_db
from app.dependencies import require_permission
from app.models.auth import Permission, Role, User
from app.schemas.user import RoleCreate, RolePermissionsUpdate, RoleRead
from app.security import CSRF_COOKIE, SESSION_COOKIE, token_hash, validate_csrf_tokens
from app.services.auth_service import resolve_session
from app.services.audit_service import record_audit_event

router = APIRouter(prefix='/api/v1/roles', tags=['roles'])


def _require_csrf(request: Request, db: Session) -> None:
    cookie = request.cookies.get(CSRF_COOKIE)
    submitted = request.headers.get('X-CSRF-Token')
    if not validate_csrf_tokens(cookie, submitted):
        raise HTTPException(status_code=403, detail='CSRF validation failed')
    raw_session = request.cookies.get(SESSION_COOKIE)
    session = resolve_session(db, raw_session) if raw_session else None
    if session is None or session.csrf_hash != token_hash(submitted):
        raise HTTPException(status_code=403, detail='CSRF validation failed')


def _get_role(db: Session, role_id: int) -> Role:
    role = db.scalar(select(Role).options(selectinload(Role.permissions)).where(Role.id == role_id))
    if role is None:
        raise HTTPException(status_code=404, detail='Role not found')
    return role


def _view(role: Role) -> RoleRead:
    return RoleRead(id=role.id, name=role.name, description=role.description, permissions=sorted(p.name for p in role.permissions))


@router.get('', response_model=list[RoleRead])
def index(db: Session = Depends(get_db), _actor: User = Depends(require_permission('role.view'))):
    roles = db.scalars(select(Role).options(selectinload(Role.permissions)).order_by(Role.name)).all()
    return [_view(role) for role in roles]



@router.post('', response_model=RoleRead, status_code=201)
def create_role(payload: RoleCreate, request: Request, db: Session = Depends(get_db), actor: User = Depends(require_permission('role.manage'))):
    _require_csrf(request, db)
    name = payload.name.strip().lower()
    if name in {'super_admin', 'admin', 'viewer'}:
        raise HTTPException(status_code=409, detail='Built-in role names are reserved')
    if db.scalar(select(Role.id).where(Role.name == name)) is not None:
        raise HTTPException(status_code=409, detail='Role already exists')
    requested = sorted(set(payload.permissions))
    rows = list(db.scalars(select(Permission).where(Permission.name.in_(requested))).all())
    found = {p.name for p in rows}
    missing = sorted(set(requested) - found)
    if missing:
        raise HTTPException(status_code=400, detail={'unknown_permissions': missing})
    role = Role(name=name, description=(payload.description.strip() if payload.description else None), permissions=sorted(rows, key=lambda p: p.name))
    db.add(role)
    db.commit()
    role = _get_role(db, role.id)
    record_audit_event(db, user=actor, action='ROLE_CREATED', object_type='role', object_id=role.id, source_ip=request.client.host if request.client else 'unknown', user_agent=request.headers.get('user-agent'), new_value={'name': role.name, 'description': role.description, 'permissions': sorted(p.name for p in role.permissions)})
    return _view(role)



@router.delete('/{role_id}', status_code=204)
def delete_role(role_id: int, request: Request, db: Session = Depends(get_db), actor: User = Depends(require_permission('role.manage'))):
    _require_csrf(request, db)
    role = _get_role(db, role_id)
    if role.name in {'super_admin', 'admin', 'viewer'}:
        raise HTTPException(status_code=409, detail='Built-in roles cannot be deleted')
    assigned_users = db.scalar(select(func.count(User.id)).where(User.role_id == role.id)) or 0
    if assigned_users:
        noun = 'user' if assigned_users == 1 else 'users'
        raise HTTPException(status_code=409, detail=f'Role is assigned to {assigned_users} {noun}; reassign those users before deleting the role')
    before = {
        'name': role.name,
        'description': role.description,
        'permissions': sorted(p.name for p in role.permissions),
    }
    db.delete(role)
    db.commit()
    record_audit_event(
        db,
        user=actor,
        action='ROLE_DELETED',
        object_type='role',
        object_id=role_id,
        source_ip=request.client.host if request.client else 'unknown',
        user_agent=request.headers.get('user-agent'),
        old_value=before,
    )
    return None

@router.get('/{role_id}', response_model=RoleRead)
def show(role_id: int, db: Session = Depends(get_db), _actor: User = Depends(require_permission('role.view'))):
    return _view(_get_role(db, role_id))


@router.put('/{role_id}/permissions', response_model=RoleRead)
def update_permissions(role_id: int, payload: RolePermissionsUpdate, request: Request, db: Session = Depends(get_db), actor: User = Depends(require_permission('role.manage'))):
    _require_csrf(request, db)
    role = _get_role(db, role_id)
    if role.name == 'super_admin':
        raise HTTPException(status_code=409, detail='Super Admin permissions are immutable')
    requested = sorted(set(payload.permissions))
    rows = list(db.scalars(select(Permission).where(Permission.name.in_(requested))).all())
    found = {p.name for p in rows}
    missing = sorted(set(requested) - found)
    if missing:
        raise HTTPException(status_code=400, detail={'unknown_permissions': missing})
    before = sorted(p.name for p in role.permissions)
    role.permissions = sorted(rows, key=lambda p: p.name)
    db.commit()
    role = _get_role(db, role.id)
    record_audit_event(db, user=actor, action='ROLE_PERMISSIONS_UPDATED', object_type='role', object_id=role.id, source_ip=request.client.host if request.client else 'unknown', user_agent=request.headers.get('user-agent'), old_value={'permissions': before}, new_value={'permissions': sorted(p.name for p in role.permissions)})
    return _view(role)
