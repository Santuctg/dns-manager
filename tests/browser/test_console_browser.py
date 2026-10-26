"""Browser smoke test for the 0.7.0 console (requires Playwright + Chromium).

Run with:

    pip install playwright
    playwright install chromium
    pytest -m browser

The module skips when Playwright or a usable Chromium is not installed, so the
normal suite stays green on hosts that only run the API/unit tests.
"""

from __future__ import annotations

import os
import re
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

import pytest

playwright_api = pytest.importorskip("playwright.sync_api")
from playwright.sync_api import Error as PlaywrightError  # noqa: E402
from playwright.sync_api import sync_playwright  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
PASSWORD = "Browser-Smoke-Password-2026!"
USERNAME = "smoke_admin"
INTERNAL_IP = "127.0.0.1"

PAGES = ["dashboard", "mappings", "firewall", "ssl", "system", "backups", "users", "roles", "audit"]
VIEWPORTS = [(1440, 1000), (390, 844)]
THEMES = ["dark", "light"]
LANGS = ["en", "bn"]

# Prefixes used by the translation dictionary. Their presence in rendered text
# means a key was not translated.
RAW_KEY_PREFIXES = (
    "nav", "common", "dashboard", "mappings", "system", "firewall", "ssl",
    "backups", "users", "roles", "audit", "login", "status", "pending",
)
RAW_KEY_RE = re.compile(r"\b(?:" + "|".join(RAW_KEY_PREFIXES) + r")\.[a-z][a-z0-9_]*\b")


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _seed_database(path: Path) -> None:
    from datetime import datetime, timedelta, timezone

    from sqlalchemy import select
    from sqlalchemy.orm import Session

    import app.models  # noqa: F401  (register tables)
    from app.database import Base, build_engine
    from app.models.auth import Role, User
    from app.models.mapping import Mapping
    from app.models.ssl import SslCertificate
    from app.security import hash_password
    from app.services.auth_service import seed_default_rbac

    engine = build_engine(str(path))
    Base.metadata.create_all(engine)
    now = datetime.now(timezone.utc)
    with Session(engine) as db:
        seed_default_rbac(db)
        roles = {role.name: role for role in db.scalars(select(Role)).all()}
        db.add(
            User(
                username=USERNAME,
                email="smoke@example.com",
                password_hash=hash_password(PASSWORD),
                role=roles["super_admin"],
            )
        )
        db.add(
            Mapping(
                domain="smoke.example.com",
                upstream_scheme="http",
                upstream_host="127.0.0.1",
                upstream_port=1,
                enabled=True,
                websocket_enabled=True,
                preserve_host=True,
            )
        )
        db.add(
            SslCertificate(
                domain="smoke.example.com",
                provider="manual",
                auto_renew=False,
                redirect_http=True,
                status="ISSUED",
                issuer="Smoke Test",
                expires_at=now + timedelta(days=30),
            )
        )
        db.commit()
    engine.dispose()


def _wait_for_health(base_url: str, process: subprocess.Popen, timeout: float = 20.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("uvicorn exited before the smoke test could start")
        try:
            with urllib.request.urlopen(f"{base_url}/health", timeout=1) as response:
                if response.status == 200:
                    return
        except OSError:
            time.sleep(0.2)
    raise RuntimeError("timed out waiting for the console server")


@pytest.fixture(scope="session")
def live_console(tmp_path_factory: pytest.TempPathFactory):
    tmp = tmp_path_factory.mktemp("browser-console")
    database = tmp / "ui.db"
    _seed_database(database)
    port = _free_port()
    base_url = f"http://localhost:{port}"
    env = dict(os.environ)
    env.update(
        {
            "DNS_MANAGER_DATABASE_PATH": str(database),
            "DNS_MANAGER_INTERNAL_PROXY_IP": INTERNAL_IP,
            "DNS_MANAGER_BIND_PORT": str(port),
        }
    )
    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "app.main:app",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            "--log-level",
            "warning",
        ],
        cwd=ROOT,
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.STDOUT,
    )
    try:
        _wait_for_health(base_url, process)
        yield base_url
    finally:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def _watch_errors(page, errors: list[str]) -> None:
    page.on(
        "console",
        lambda message: errors.append(
            f"{message.type}: {message.text} @ {(message.location or {}).get('url', '')}"
        )
        if message.type == "error"
        else None,
    )
    page.on("pageerror", lambda error: errors.append(f"pageerror: {error}"))


@pytest.fixture(scope="session")
def console_page(live_console: str):
    with sync_playwright() as playwright:
        try:
            browser = playwright.chromium.launch()
        except PlaywrightError as exc:  # pragma: no cover - depends on the host
            pytest.skip(f"Chromium is not available: {exc}")
        context = browser.new_context(base_url=live_console)
        page = context.new_page()
        errors: list[str] = []
        _watch_errors(page, errors)
        page.goto("/login")
        page.fill("#login-username", USERNAME)
        page.fill("#login-password", PASSWORD)
        page.click("[data-login-submit]")
        page.wait_for_url("**/app/dashboard", timeout=15000)
        try:
            yield page, context, errors
        finally:
            browser.close()


def _set_preference(context, base_url: str, name: str, value: str) -> None:
    context.add_cookies([{"name": name, "value": value, "url": base_url}])


def _visit(page, context, errors: list[str], *, base_url: str, page_name: str, width: int, height: int, theme: str, lang: str, path: str | None = None) -> list[str]:
    _set_preference(context, base_url, "dns_manager_theme", theme)
    _set_preference(context, base_url, "dns_manager_lang", lang)
    page.set_viewport_size({"width": width, "height": height})
    errors.clear()
    page.goto(path or f"/app/{page_name}", wait_until="domcontentloaded")
    page.wait_for_load_state("load")
    page.evaluate("() => document.fonts.ready.then(() => true)")
    page.wait_for_timeout(500)

    state = page.evaluate(
        """() => {
            // Permission identifiers such as ``audit.view`` are API data and
            // stay in English, so skip the chips and checkboxes that show them.
            const skip = (node) => node.closest('.permission-list, script, style, template, noscript, label:has(input[name="permissions"])');
            const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
            const parts = [];
            let length = 0;
            while (walker.nextNode() && length < 40000) {
                const node = walker.currentNode;
                if (skip(node.parentElement)) continue;
                const text = node.textContent.trim();
                if (!text) continue;
                parts.push(text);
                length += text.length;
            }
            return {
                page: document.body.dataset.page || '',
                lang: document.documentElement.lang,
                theme: document.documentElement.dataset.theme,
                overflow: Math.max(
                    document.documentElement.scrollWidth - document.documentElement.clientWidth,
                    document.body.scrollWidth - document.body.clientWidth
                ),
                plexSans: document.fonts.check('400 16px "IBM Plex Sans"'),
                bengali: document.fonts.check('400 16px "Noto Sans Bengali"'),
                text: parts.join('\\n'),
            };
        }"""
    )

    label = f"{page_name} {width}px {theme} {lang}"
    problems: list[str] = []
    if state["page"] != page_name:
        problems.append(f"{label}: rendered page marker {state['page']!r}")
    if state["lang"] != lang:
        problems.append(f"{label}: html lang {state['lang']!r}, expected {lang!r}")
    if state["theme"] != theme:
        problems.append(f"{label}: html theme {state['theme']!r}, expected {theme!r}")
    if state["overflow"] > 1:
        problems.append(f"{label}: horizontal overflow {state['overflow']}px")
    if not state["plexSans"]:
        problems.append(f"{label}: IBM Plex Sans did not load")
    if lang == "bn" and not state["bengali"]:
        problems.append(f"{label}: Noto Sans Bengali did not load")

    for prefix in RAW_KEY_PREFIXES:
        match = RAW_KEY_RE.search(state["text"])
        if match:
            problems.append(f"{label}: untranslated key {match.group(0)!r}")
            break

    for error in errors:
        # The metrics endpoint returns 503 on hosts without /proc; the console
        # deliberately renders an unavailable state instead of failing.
        if "/api/v1/system/metrics" in error:
            continue
        problems.append(f"{label}: console error: {error}")
    return problems


def _run_matrix(page, context, errors, base_url: str, page_name: str, *, path: str | None = None) -> list[str]:
    problems: list[str] = []
    for width, height in VIEWPORTS:
        for theme in THEMES:
            for lang in LANGS:
                problems.extend(
                    _visit(
                        page,
                        context,
                        errors,
                        base_url=base_url,
                        page_name=page_name,
                        width=width,
                        height=height,
                        theme=theme,
                        lang=lang,
                        path=path,
                    )
                )
    return problems


@pytest.mark.browser
@pytest.mark.parametrize("page_name", PAGES)
def test_console_page_smoke(console_page, live_console: str, page_name: str) -> None:
    page, context, errors = console_page
    problems = _run_matrix(page, context, errors, live_console, page_name)
    assert not problems, "\n".join(problems)


@pytest.mark.browser
def test_login_page_smoke(console_page, live_console: str) -> None:
    _page, context, _errors = console_page
    browser = context.browser
    assert browser is not None
    login_context = browser.new_context(base_url=live_console)
    page = login_context.new_page()
    errors: list[str] = []
    _watch_errors(page, errors)
    try:
        problems = _run_matrix(page, login_context, errors, live_console, "login", path="/login")
    finally:
        login_context.close()
    assert not problems, "\n".join(problems)
