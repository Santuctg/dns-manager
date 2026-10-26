from __future__ import annotations

import json
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

LANG_COOKIE = "dns_manager_lang"
THEME_COOKIE = "dns_manager_theme"
SUPPORTED_LANGS = ("en", "bn")
SUPPORTED_THEMES = ("dark", "light")
DEFAULT_LANG = "en"
DEFAULT_THEME = "dark"
I18N_DIR = BASE_DIR / "static" / "i18n"

TRANSLATIONS: dict[str, dict[str, str]] = {
    lang: json.loads((I18N_DIR / f"{lang}.json").read_text(encoding="utf-8"))
    for lang in SUPPORTED_LANGS
}

PAGE_TITLES = {
    "dashboard": "nav.dashboard",
    "mappings": "nav.mappings",
    "firewall": "nav.firewall",
    "ssl": "nav.ssl",
    "system": "nav.system",
    "backups": "nav.backups",
    "users": "nav.users",
    "roles": "nav.roles",
    "audit": "nav.audit",
}

PAGE_PERMISSIONS: dict[str, str | None] = {
    "dashboard": "system.view",
    "mappings": "mapping.view",
    "firewall": "firewall.manage",
    "ssl": None,
    "system": "system.view",
    "backups": "backup.create",
    "users": "user.view",
    "roles": "role.view",
    "audit": "audit.view",
}

NAV_GROUPS = (
    ("nav.group.overview", (("dashboard", "icon-dashboard"),)),
    ("nav.group.routing", (("mappings", "icon-mappings"),)),
    (
        "nav.group.security",
        (("firewall", "icon-firewall"), ("ssl", "icon-ssl")),
    ),
    (
        "nav.group.operations",
        (("system", "icon-system"), ("backups", "icon-backups")),
    ),
    (
        "nav.group.admin",
        (("users", "icon-users"), ("roles", "icon-roles"), ("audit", "icon-audit")),
    ),
)

MOBILE_TABS = ("dashboard", "mappings", "system")


def translate(lang: str, key: str, params: dict[str, object] | None = None) -> str:
    text = TRANSLATIONS.get(lang, {}).get(key)
    if text is None:
        text = TRANSLATIONS[DEFAULT_LANG].get(key, key)
    if params:
        for name, value in params.items():
            text = text.replace("{" + name + "}", str(value))
    return text


def _requested_lang(request: Request) -> str:
    cookie = (request.cookies.get(LANG_COOKIE) or "").strip().lower()
    if cookie in SUPPORTED_LANGS:
        return cookie
    header = request.headers.get("accept-language", "")
    for part in header.split(","):
        tag = part.split(";")[0].strip().lower()
        if tag.startswith("bn"):
            return "bn"
        if tag.startswith("en"):
            return "en"
    return DEFAULT_LANG


def _requested_theme(request: Request) -> str:
    cookie = (request.cookies.get(THEME_COOKIE) or "").strip().lower()
    return cookie if cookie in SUPPORTED_THEMES else DEFAULT_THEME


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


def _is_super_admin(user: User) -> bool:
    return bool(user.role and user.role.name == "super_admin")


def _can_view_page(user: User, page: str) -> bool:
    required = PAGE_PERMISSIONS.get(page)
    if required is None:
        return _is_super_admin(user)
    return has_permission(user, required)


def _nav_groups(user: User, lang: str) -> list[dict[str, object]]:
    groups: list[dict[str, object]] = []
    for label_key, items in NAV_GROUPS:
        visible = [
            {
                "page": page,
                "href": f"/app/{page}",
                "label": translate(lang, PAGE_TITLES[page]),
                "icon": icon,
            }
            for page, icon in items
            if _can_view_page(user, page)
        ]
        if visible:
            groups.append({"label": translate(lang, label_key), "items": visible})
    return groups


def _base_context(request: Request, lang: str, theme: str) -> dict[str, object]:
    return {
        "request": request,
        "lang": lang,
        "theme": theme,
        "i18n": TRANSLATIONS[lang],
        "lang_cookie": LANG_COOKIE,
        "theme_cookie": THEME_COOKIE,
        "t": lambda key, **params: translate(lang, key, params),
    }


def _context(request: Request, user: User, page: str) -> dict[str, object]:
    permissions = _permissions(user)
    lang = _requested_lang(request)
    theme = _requested_theme(request)
    super_admin = _is_super_admin(user)
    context = _base_context(request, lang, theme)
    nav_groups = _nav_groups(user, lang)
    context.update(
        {
            "user": user,
            "role_name": user.role.name if user.role else "",
            "role_label": (user.role.name.replace("_", " ").title() if user.role else ""),
            "permissions": permissions,
            "all_permissions": sorted(ALL_PERMISSIONS),
            "page": page,
            "page_title": translate(lang, PAGE_TITLES[page]),
            "nav_groups": nav_groups,
            "mobile_tabs": [
                {
                    "page": tab,
                    "href": f"/app/{tab}",
                    "label": translate(lang, PAGE_TITLES[tab]),
                    "icon": dict(
                        (name, icon) for _, items in NAV_GROUPS for name, icon in items
                    )[tab],
                }
                for tab in MOBILE_TABS
                if _can_view_page(user, tab)
            ],
            "more_pages": [
                {
                    "page": item["page"],
                    "href": item["href"],
                    "label": item["label"],
                    "icon": item["icon"],
                }
                for group in nav_groups
                for item in group["items"]
                if item["page"] not in MOBILE_TABS
            ],
            "is_super_admin": super_admin,
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
            "can_ssl_manage": super_admin,
        }
    )
    return context


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
    lang = _requested_lang(request)
    theme = _requested_theme(request)
    context = _base_context(request, lang, theme)
    context.update({"next_path": next_path, "page_title": translate(lang, "login.title")})
    return TEMPLATES.TemplateResponse(request=request, name="login.html", context=context)


@router.get("/app/{page}", response_class=HTMLResponse)
def app_page(page: str, request: Request, db: Session = Depends(get_db)):
    if page not in PAGE_TITLES:
        return RedirectResponse(url="/app/dashboard", status_code=303)
    user = _load_user(request, db)
    if user is None:
        return _login_redirect(request)
    if not _can_view_page(user, page):
        return RedirectResponse(url="/app/dashboard?error=permission", status_code=303)
    return TEMPLATES.TemplateResponse(
        request=request,
        name=f"{page}.html",
        context=_context(request, user, page),
    )
