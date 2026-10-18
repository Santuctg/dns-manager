from __future__ import annotations

from pathlib import Path
from urllib.parse import quote

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.database import get_db
from app.models.auth import Role, User
from app.security import SESSION_COOKIE
from app.services.auth_service import ALL_PERMISSIONS, has_permission, resolve_session

BASE_DIR = Path(__file__).resolve().parent
TEMPLATES = Jinja2Templates(directory=str(BASE_DIR / "templates"))
router = APIRouter(include_in_schema=False)

PAGE_TITLES = {
    "dashboard": "Dashboard",
    "mappings": "Mappings",
    "users": "Users",
    "roles": "Roles",
    "audit": "Audit",
    "system": "System",
}


def _load_user(request: Request, db: Session) -> User | None:
    raw_session = request.cookies.get(SESSION_COOKIE)
    if not raw_session:
        return None
    session = resolve_session(db, raw_session)
    if session is None:
        return None
    user = db.scalar(
        select(User)
        .options(selectinload(User.role).selectinload(Role.permissions))
        .where(User.id == session.user_id)
    )
    if user is None or not user.is_active:
        return None
    return user


def _permissions(user: User) -> set[str]:
    return {permission.name for permission in user.role.permissions} if user.role else set()


def _context(request: Request, user: User, page: str) -> dict[str, object]:
    permissions = _permissions(user)
    return {
        "request": request,
        "user": user,
        "role_name": user.role.name if user.role else "",
        "permissions": permissions,
        "all_permissions": sorted(ALL_PERMISSIONS),
        "page": page,
        "page_title": PAGE_TITLES[page],
        "can_mapping_create": "mapping.create" in permissions,
        "can_mapping_update": "mapping.update" in permissions,
        "can_mapping_delete": "mapping.delete" in permissions,
        "can_config_apply": "config.apply" in permissions,
        "can_config_rollback": "config.rollback" in permissions,
        "can_user_view": "user.view" in permissions,
        "can_user_create": "user.create" in permissions,
        "can_user_update": "user.update" in permissions,
        "can_user_delete": "user.delete" in permissions,
        "can_role_view": "role.view" in permissions,
        "can_role_manage": "role.manage" in permissions,
        "can_backup_create": "backup.create" in permissions,
        "can_backup_restore": "backup.restore" in permissions,
        "can_firewall_manage": "firewall.manage" in permissions,
    }


def _login_redirect(request: Request) -> RedirectResponse:
    path = request.url.path
    return RedirectResponse(url=f"/login?next={quote(path, safe='/')}", status_code=303)


@router.get("/", response_class=HTMLResponse)
def root(request: Request, db: Session = Depends(get_db)):
    user = _load_user(request, db)
    return RedirectResponse(url="/app/dashboard" if user else "/login", status_code=303)


@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request, db: Session = Depends(get_db)):
    if _load_user(request, db):
        return RedirectResponse(url="/app/dashboard", status_code=303)
    next_path = request.query_params.get("next", "/app/dashboard")
    if not next_path.startswith("/app/"):
        next_path = "/app/dashboard"
    return TEMPLATES.TemplateResponse(
        request=request,
        name="login.html",
        context={"next_path": next_path},
    )


@router.get("/app/{page}", response_class=HTMLResponse)
def app_page(page: str, request: Request, db: Session = Depends(get_db)):
    if page not in PAGE_TITLES:
        return RedirectResponse(url="/app/dashboard", status_code=303)
    user = _load_user(request, db)
    if user is None:
        return _login_redirect(request)

    required = {
        "dashboard": "system.view",
        "mappings": "mapping.view",
        "users": "user.view",
        "roles": "role.view",
        "audit": "audit.view",
        "system": "system.view",
    }[page]
    if not has_permission(user, required):
        return RedirectResponse(url="/app/dashboard?error=permission", status_code=303)
    return TEMPLATES.TemplateResponse(
        request=request,
        name=f"{page}.html",
        context=_context(request, user, page),
    )
