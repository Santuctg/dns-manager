"""Console shell, page routing and permission contracts for the 0.7.1 UI."""

import json
from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.database import Base, get_db
from app.main import app
from app.models.auth import Permission, Role, User
from app.security import hash_password
from app.services.auth_service import ALL_PERMISSIONS, ADMIN_PERMISSIONS, VIEWER_PERMISSIONS, create_session

ROOT = Path(__file__).resolve().parents[2]

PAGES = {
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


def make_web_env(role_name: str | None = None):
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    raw_session = None
    user_id = None
    with Session(engine) as db:
        perms = {name: Permission(name=name) for name in sorted(ALL_PERMISSIONS)}
        db.add_all(perms.values())
        roles = {
            "super_admin": Role(name="super_admin", permissions=[perms[n] for n in sorted(ALL_PERMISSIONS)]),
            "admin": Role(name="admin", permissions=[perms[n] for n in sorted(ADMIN_PERMISSIONS)]),
            "viewer": Role(name="viewer", permissions=[perms[n] for n in sorted(VIEWER_PERMISSIONS)]),
        }
        db.add_all(roles.values())
        db.flush()
        if role_name:
            user = User(
                username=f"{role_name}-user",
                email=f"{role_name}@example.com",
                password_hash=hash_password("very-secure-password"),
                role=roles[role_name],
            )
            db.add(user)
            db.commit()
            user_id = user.id
            raw_session = create_session(db, user, "csrf-token")
        else:
            db.commit()

    def override_db():
        with Session(engine) as db:
            yield db

    app.dependency_overrides[get_db] = override_db
    client = TestClient(app, base_url="https://testserver", follow_redirects=False)
    if raw_session:
        client.cookies.set("dns_manager_session", raw_session)
        client.cookies.set("dns_manager_csrf", "csrf-token")
    client.engine = engine
    client.user_id = user_id
    return client


def cleanup():
    app.dependency_overrides.clear()


def test_public_login_page_uses_local_console_assets_only():
    client = make_web_env()
    try:
        root = client.get("/")
        assert root.status_code == 303
        assert root.headers["location"] == "/login"

        login = client.get("/login")
        assert login.status_code == 200
        html = login.text
        assert 'data-page="login"' in html
        assert 'class="login-shell"' in html
        for asset in ("tokens.css", "base.css", "components.css", "pages.css"):
            assert f"/static/css/{asset}" in html
        assert "/static/js/core.js" in html
        assert "/static/js/pages/login.js" in html
        assert "/static/app.js" not in html
        assert "/static/app.css" not in html
        assert 'id="i18n-data"' in html
        assert "data-lang-switch" in html
        assert "data-theme-switch" in html
        assert "https://" not in html
        assert "http://" not in html
    finally:
        cleanup()


def test_unauthenticated_app_page_redirects_to_login_with_next():
    client = make_web_env()
    try:
        response = client.get("/app/dashboard")
        assert response.status_code == 303
        assert response.headers["location"] == "/login?next=/app/dashboard"
    finally:
        cleanup()


def test_every_console_page_renders_for_super_admin():
    client = make_web_env("super_admin")
    try:
        for page in PAGES:
            response = client.get(f"/app/{page}")
            assert response.status_code == 200, page
            html = response.text
            assert f'data-page="{page}"' in html
            assert "/static/js/core.js" in html
            assert f"/static/js/pages/{page}.js" in html
            assert 'class="app-shell"' in html
            assert "data-pending-banner" in html
            assert "data-mobile-sheet" in html
            assert "/static/app.js" not in html
            assert "/static/app.css" not in html
    finally:
        cleanup()


def test_unknown_app_page_redirects_to_dashboard():
    client = make_web_env("super_admin")
    try:
        response = client.get("/app/does-not-exist")
        assert response.status_code == 303
        assert response.headers["location"] == "/app/dashboard"
    finally:
        cleanup()


def test_viewer_navigation_is_read_only_and_hides_admin_pages():
    client = make_web_env("viewer")
    try:
        response = client.get("/app/mappings")
        assert response.status_code == 200
        html = response.text
        assert 'href="/app/mappings"' in html
        assert 'href="/app/audit"' in html
        assert 'href="/app/users"' not in html
        assert 'href="/app/roles"' not in html
        assert "data-mapping-create" not in html
        assert 'data-can-apply="false"' in html
        assert 'data-can-mapping-create="false"' in html

        for page in ("firewall", "ssl", "backups", "users", "roles"):
            denied = client.get(f"/app/{page}")
            assert denied.status_code == 303, page
            assert denied.headers["location"] == "/app/dashboard?error=permission"
    finally:
        cleanup()


def test_admin_sees_mapping_and_user_controls_but_not_role_or_ssl_admin():
    client = make_web_env("admin")
    try:
        mappings = client.get("/app/mappings")
        assert mappings.status_code == 200
        assert "data-mapping-create" in mappings.text
        assert 'data-can-apply="true"' in mappings.text
        assert "/app/ssl" not in mappings.text

        users = client.get("/app/users")
        assert users.status_code == 200
        assert "data-user-add" in users.text

        roles = client.get("/app/roles")
        assert roles.status_code == 200
        assert "data-role-form" not in roles.text

        assert client.get("/app/ssl").status_code == 303
        assert client.get("/app/backups").status_code == 303
        assert client.get("/app/firewall").status_code == 303
    finally:
        cleanup()


def test_super_admin_sees_every_group_and_ssl_controls():
    client = make_web_env("super_admin")
    try:
        response = client.get("/app/roles")
        assert response.status_code == 200
        html = response.text
        for page in PAGES:
            assert f'href="/app/{page}"' in html
        for group in ("Overview", "Routing", "Security", "Operations", "Admin"):
            assert group in html
        assert "data-role-form" in html
        assert 'data-can-rollback="true"' in html

        ssl = client.get("/app/ssl")
        assert ssl.status_code == 200
        assert "data-ssl-table" in ssl.text
        assert "data-ssl-add" in ssl.text
    finally:
        cleanup()


def test_page_specific_hooks_exist():
    client = make_web_env("super_admin")
    try:
        dashboard = client.get("/app/dashboard").text
        assert "data-summary-services" in dashboard
        assert "data-summary-mappings" in dashboard
        assert "data-summary-certificates" in dashboard
        assert "data-attention-list" in dashboard
        assert "data-recent-events" in dashboard
        assert 'data-chart="cpu-memory"' in dashboard
        assert 'data-chart="network"' in dashboard
        assert 'data-chart-legend="cpu"' in dashboard
        assert 'data-chart-legend="output"' in dashboard

        mappings = client.get("/app/mappings").text
        for hook in (
            "data-mapping-form",
            "data-mapping-panel",
            "data-mapping-detail-panel",
            "data-mappings-table",
            "data-mapping-filter",
            "data-mapping-search",
        ):
            assert hook in mappings

        system = client.get("/app/system").text
        for hook in (
            "data-configuration",
            "data-diff-dnsmasq",
            "data-diff-nginx",
            "data-revisions-table",
            "data-services-grid",
            "data-system=\"dns_safety\"",
            "data-system=\"dns_bind\"",
            "data-monitor-interfaces",
        ):
            assert hook in system
    finally:
        cleanup()


def test_firewall_page_has_confirmation_bar_and_no_raw_command_input():
    client = make_web_env("super_admin")
    try:
        html = client.get("/app/firewall").text
        for hook in (
            "data-firewall-rules",
            "data-firewall-panel",
            "data-firewall-source-list",
            "data-firewall-source-add",
            "data-firewall-confirm-bar",
            "data-firewall-countdown",
            "data-firewall-confirm",
            "data-firewall-rollback-now",
        ):
            assert hook in html
        assert 'name="command"' not in html
        assert "never accepts raw shell commands" in html
    finally:
        cleanup()


def test_backups_page_has_typed_restore_confirmation():
    client = make_web_env("super_admin")
    try:
        html = client.get("/app/backups").text
        for hook in (
            "data-backups-table",
            "data-backup-create",
            "data-backup-upload",
            "data-backup-upload-dialog",
            "data-backup-restore-panel",
            "data-backup-restore-confirm",
        ):
            assert hook in html
        assert 'accept=".tar.gz,.tgz,application/gzip"' in html
    finally:
        cleanup()


def test_ssl_page_has_primary_action_table_and_manual_panel():
    client = make_web_env("super_admin")
    try:
        html = client.get("/app/ssl").text
        for hook in (
            "data-ssl-table",
            "data-ssl-add",
            "data-ssl-panel",
            "data-ssl-form",
            "data-ssl-manual-panel",
            "data-ssl-token-field",
        ):
            assert hook in html
        assert 'type="password"' in html
    finally:
        cleanup()


def test_global_modal_controls_never_submit_and_support_focus_handling():
    client = make_web_env("super_admin")
    try:
        for path in ("/app/mappings", "/app/users", "/app/roles", "/app/firewall"):
            html = client.get(path).text
            assert 'value="cancel"' not in html
            assert 'type="button" data-panel-close' in html
        base = client.get("/app/dashboard").text
        assert 'aria-labelledby="action-modal-title"' in base
        assert 'aria-describedby="action-modal-description"' in base
        assert "data-action-modal-confirm" in base
        assert "data-action-modal-spinner" in base
    finally:
        cleanup()


def test_language_theme_and_accept_language_render_on_the_server():
    client = make_web_env()
    try:
        english = client.get("/login")
        assert '<html lang="en" data-theme="dark">' in english.text

        client.cookies.set("dns_manager_lang", "bn")
        client.cookies.set("dns_manager_theme", "light")
        bengali = client.get("/login")
        assert '<html lang="bn" data-theme="light">' in bengali.text
        assert "সাইন ইন" in bengali.text or "লগ ইন" in bengali.text
        assert 'aria-pressed="true" data-lang-switch="bn"' in bengali.text or 'data-lang-switch="bn" aria-pressed="true"' in bengali.text

        client.cookies.clear()
        header = client.get("/login", headers={"accept-language": "bn-BD,bn;q=0.9,en;q=0.5"})
        assert '<html lang="bn" data-theme="dark">' in header.text

        english_header = client.get("/login", headers={"accept-language": "fr-FR,en;q=0.8"})
        assert '<html lang="en" data-theme="dark">' in english_header.text
    finally:
        cleanup()


def test_server_embeds_only_the_active_dictionary():
    client = make_web_env("super_admin")
    try:
        en = client.get("/app/dashboard").text
        en_blob = en.split('id="i18n-data">', 1)[1].split("</script>", 1)[0]
        en_dict = json.loads(en_blob)
        assert en_dict["nav.dashboard"] == "Dashboard"

        client.cookies.set("dns_manager_lang", "bn")
        bn = client.get("/app/dashboard").text
        bn_blob = bn.split('id="i18n-data">', 1)[1].split("</script>", 1)[0]
        bn_dict = json.loads(bn_blob)
        assert bn_dict["nav.dashboard"] != "Dashboard"
        assert set(en_dict) == set(bn_dict)
    finally:
        cleanup()


def test_static_console_assets_are_served_offline():
    client = make_web_env()
    try:
        assets = [
            "/static/css/tokens.css",
            "/static/css/base.css",
            "/static/css/components.css",
            "/static/css/pages.css",
            "/static/js/core.js",
            "/static/icons.svg",
            "/static/i18n/en.json",
            "/static/i18n/bn.json",
            "/static/fonts/IBMPlexSans-400.woff2",
            "/static/fonts/IBMPlexSans-600.woff2",
            "/static/fonts/IBMPlexMono-400.woff2",
            "/static/fonts/IBMPlexMono-600.woff2",
            "/static/fonts/NotoSansBengali-400.woff2",
            "/static/fonts/NotoSansBengali-600.woff2",
            "/static/fonts/LICENSE-IBMPlex.txt",
            "/static/fonts/LICENSE-NotoSansBengali.txt",
        ]
        assets.extend(f"/static/js/pages/{page}.js" for page in PAGES)
        for asset in assets:
            response = client.get(asset)
            assert response.status_code == 200, asset

        for asset in ("/static/css/base.css", "/static/js/core.js", "/static/js/pages/mappings.js"):
            body = client.get(asset).text
            assert "//cdn." not in body.lower(), asset
            assert "https://cdn" not in body.lower(), asset
            assert 'src="http' not in body, asset
            assert 'href="http' not in body, asset
            assert "from \"http" not in body and "from 'http" not in body, asset
    finally:
        cleanup()


def test_removed_legacy_assets_are_not_referenced_anywhere():
    templates = list((ROOT / "app" / "templates").glob("*.html"))
    scripts = list((ROOT / "app" / "static" / "js").rglob("*.js"))
    for path in templates + scripts:
        text = path.read_text(encoding="utf-8")
        assert "/static/app.js" not in text, path
        assert "/static/app.css" not in text, path


def test_mobile_navigation_lists_only_permitted_pages():
    viewer = make_web_env("viewer")
    try:
        html = viewer.get("/app/dashboard").text
        tabbar = html.split('class="tabbar"', 1)[1].split("</nav>", 1)[0]
        assert 'href="/app/dashboard"' in tabbar
        assert 'href="/app/mappings"' in tabbar
        assert 'href="/app/system"' in tabbar
        assert 'href="/app/audit"' not in tabbar
        assert "data-mobile-more" in tabbar
    finally:
        cleanup()
