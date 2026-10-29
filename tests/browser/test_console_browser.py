"""Browser smoke test for the 0.7.11 console (requires Playwright + Chromium).

Run with:

    pip install playwright
    playwright install chromium
    pytest -m browser

The module skips when Playwright or a usable Chromium is not installed, so the
normal suite stays green on hosts that only run the API/unit tests.
"""

from __future__ import annotations

import os
import json
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
            const vw = document.documentElement.clientWidth;
            const isVisible = (element) => {
                const style = getComputedStyle(element);
                if (style.display === 'none' || style.visibility === 'hidden' || Number(style.opacity) === 0) return false;
                return !(element.closest('details:not([open])') && element.tagName !== 'SUMMARY');
            };
            const insideScroller = (element) => {
                for (let parent = element.parentElement; parent && parent !== document.body; parent = parent.parentElement) {
                    if (/(auto|scroll)/.test(getComputedStyle(parent).overflowX)) return true;
                }
                return false;
            };
            const offscreen = [];
            document.querySelectorAll('main *').forEach((element) => {
                if (!isVisible(element) || insideScroller(element)) return;
                const rect = element.getBoundingClientRect();
                if (!rect.width || !rect.height) return;
                if (rect.right > vw + 2 || rect.left < -2) {
                    offscreen.push(`${element.tagName}.${String(element.className)} ${Math.round(rect.left)}..${Math.round(rect.right)}`);
                }
            });
            const strayDialogs = [];
            document.querySelectorAll('dialog').forEach((element) => {
                if (element.open) return;
                const style = getComputedStyle(element);
                if (style.display !== 'none') {
                    strayDialogs.push(`${element.className || 'dialog'} display:${style.display}`);
                }
            });
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
                offscreen: offscreen.slice(0, 5),
                strayDialogs,
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
    for element in state["offscreen"]:
        problems.append(f"{label}: element outside the viewport: {element}")
    for dialog in state["strayDialogs"]:
        problems.append(f"{label}: closed dialog is still rendered: {dialog}")

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


@pytest.mark.browser
def test_implicit_text_inputs_match_other_form_controls(console_page, live_console: str) -> None:
    _page, context, _errors = console_page
    browser = context.browser
    assert browser is not None
    login_context = browser.new_context(base_url=live_console)
    page = login_context.new_page()
    try:
        page.goto(f"{live_console}/login", wait_until="load")
        styles = page.evaluate("""() => {
            const properties = ['width', 'minHeight', 'padding', 'borderRadius', 'backgroundColor', 'fontSize'];
            return ['#login-username', '#login-password'].map(selector => {
                const style = getComputedStyle(document.querySelector(selector));
                return Object.fromEntries(properties.map(property => [property, style[property]]));
            });
        }""")
    finally:
        login_context.close()
    assert styles[0] == styles[1]


@pytest.mark.browser
def test_firewall_policy_controls_are_readable_and_responsive(console_page, live_console: str) -> None:
    page, _context, _errors = console_page
    for width in (1280, 390):
        page.set_viewport_size({"width": width, "height": 800})
        page.goto(f"{live_console}/app/firewall", wait_until="load")
        incoming = page.locator('#firewall-incoming').bounding_box()
        outgoing = page.locator('#firewall-outgoing').bounding_box()
        assert incoming and outgoing
        assert incoming['width'] >= 140 and outgoing['width'] >= 140
        if width < 560:
            assert outgoing['y'] >= incoming['y'] + incoming['height']
        else:
            assert abs(incoming['width'] - outgoing['width']) <= 1
            assert incoming['width'] <= 260 and outgoing['width'] <= 260
            centers = page.evaluate("""() => ['[data-firewall-enabled]', '#firewall-incoming',
                '[data-firewall-policy-form] button[type="submit"]'].map(selector => {
                    const rect = document.querySelector(selector).getBoundingClientRect();
                    return rect.top + rect.height / 2;
                })""")
            assert abs(centers[0] - centers[1]) <= 2
            assert abs(centers[2] - centers[1]) <= 2


@pytest.mark.browser
def test_sidebar_toggle_is_fully_visible_and_operable(console_page, live_console: str) -> None:
    page, _context, _errors = console_page
    page.set_viewport_size({"width": 1280, "height": 800})
    page.goto(f"{live_console}/app/dashboard", wait_until="load")
    toggle = page.locator('[data-sidebar-toggle]')
    for _ in range(2):
        geometry = toggle.evaluate("""el => {
            const button = el.getBoundingClientRect();
            const sidebar = el.closest('.sidebar').getBoundingClientRect();
            return {left: button.left, right: button.right, sidebarLeft: sidebar.left, sidebarRight: sidebar.right};
        }""")
        assert geometry['left'] >= geometry['sidebarLeft'] - 1, geometry
        assert geometry['right'] <= geometry['sidebarRight'] + 1, geometry
        toggle.click()
        page.wait_for_timeout(250)


@pytest.mark.browser
def test_dynamic_action_icons_reference_existing_sprite_symbols(console_page, live_console: str) -> None:
    page, _context, _errors = console_page
    page.goto(f"{live_console}/app/ssl", wait_until="load")
    page.wait_for_selector('summary[aria-label] use[href*="icons.svg"]', state="attached")
    result = page.evaluate("""async () => {
        const sprite = new DOMParser().parseFromString(await (await fetch('/static/icons.svg')).text(), 'image/svg+xml');
        const uses = [...document.querySelectorAll('summary[aria-label] use[href*="icons.svg"]')];
        return uses.map(use => ({href: use.getAttribute('href'),
            found: !!sprite.getElementById(use.getAttribute('href').split('#')[1])}));
    }""")
    assert result and all(item['found'] for item in result), result


@pytest.mark.browser
def test_side_panel_actions_stay_reachable_on_short_screens(console_page, live_console: str) -> None:
    """Drawers must keep their footer button on screen and scroll their body."""
    page, _context, _errors = console_page
    problems: list[str] = []
    for width, height in ((1280, 600), (390, 560)):
        page.set_viewport_size({"width": width, "height": height})
        for name in ("mappings", "firewall", "ssl", "users", "roles"):
            page.goto(f"{live_console}/app/{name}", wait_until="load")
            page.wait_for_timeout(400)
            issues = page.evaluate(
                """() => {
                    const out = [];
                    document.querySelectorAll('dialog.side-panel').forEach((dialog) => {
                        dialog.showModal();
                        const vh = window.innerHeight;
                        const body = dialog.querySelector('.side-panel-body');
                        const foot = dialog.querySelector('.side-panel-foot');
                        const footVisible = !foot || foot.getBoundingClientRect().bottom <= vh + 1;
                        const needsScroll = body && body.scrollHeight > body.clientHeight + 1;
                        const bodyScrolls = !needsScroll || /(auto|scroll)/.test(getComputedStyle(body).overflowY);
                        const rect = dialog.getBoundingClientRect();
                        const fillsHeight = Math.abs(rect.top) <= 1 && rect.bottom >= vh - 1;
                        if (!footVisible || !bodyScrolls || !fillsHeight) {
                            out.push(`${dialog.className} footer=${footVisible} bodyScrolls=${bodyScrolls} fills=${fillsHeight}`);
                        }
                        dialog.close();
                    });
                    return out;
                }"""
            )
            problems.extend(f"{name} {width}x{height}: {issue}" for issue in issues)
    assert not problems, "\n".join(problems)


@pytest.mark.browser
def test_mobile_sheet_scrolls_instead_of_clipping(console_page, live_console: str) -> None:
    """The phone 'More pages' sheet must reach the bottom and scroll its content."""
    page, _context, _errors = console_page
    page.set_viewport_size({"width": 390, "height": 500})
    page.goto(f"{live_console}/app/dashboard", wait_until="load")
    page.wait_for_timeout(400)
    state = page.evaluate(
        """() => {
            const sheet = document.querySelector('dialog.mobile-sheet');
            if (!sheet) return {missing: true};
            sheet.showModal();
            const rect = sheet.getBoundingClientRect();
            const inner = sheet.querySelector('.mobile-sheet-inner');
            const overflow = inner.scrollHeight - inner.clientHeight;
            const scrollable = /(auto|scroll)/.test(getComputedStyle(inner).overflowY);
            const out = {
                missing: false,
                top: rect.top,
                bottomGap: window.innerHeight - rect.bottom,
                overflow,
                scrollable,
            };
            sheet.close();
            return out;
        }"""
    )
    assert not state["missing"], "mobile sheet not rendered"
    assert state["bottomGap"] <= 1, f"sheet does not reach the bottom ({state})"
    assert state["top"] >= 0, f"sheet starts above the viewport ({state})"
    assert state["overflow"] <= 1 or state["scrollable"], f"sheet content is clipped ({state})"


@pytest.mark.browser
def test_dashboard_summary_is_not_blocked_by_backend_probes(console_page, live_console: str) -> None:
    """Slow backend probes must not delay the rest of the dashboard."""
    _page, context, _errors = console_page
    page = context.new_page()
    page.add_init_script(
        """
        const realFetch = window.fetch.bind(window);
        window.fetch = (input, init) => {
            const url = typeof input === 'string' ? input : input.url;
            if (url.includes('/api/v1/system/backends')) return new Promise(() => {});
            return realFetch(input, init);
        };
        """
    )
    try:
        page.goto(f"{live_console}/app/dashboard", wait_until="domcontentloaded")
        page.wait_for_function(
            "() => !document.querySelector('[data-summary-mappings] .skeleton')",
            timeout=3000,
        )
        state = page.evaluate(
            """() => ({
                mappings: document.querySelector('[data-summary-mappings]').textContent.trim(),
                detail: document.querySelector('[data-summary-mappings-detail]').textContent.trim(),
                pending: document.querySelector('[data-summary-pending]').textContent.trim(),
            })"""
        )
    finally:
        page.close()
    assert state["mappings"] == "1"
    assert "1" in state["detail"]
    assert state["pending"] != ""


@pytest.mark.browser
def test_dashboard_metrics_failures_back_off(console_page, live_console: str) -> None:
    """A permanently unavailable metrics endpoint must not be polled every second."""
    _page, context, _errors = console_page
    page = context.new_page()
    calls: list[str] = []
    page.route(
        "**/api/v1/system/metrics",
        lambda route: (
            calls.append(route.request.url),
            route.fulfill(
                status=503,
                content_type="application/json",
                body='{"detail": "System metrics unavailable"}',
            ),
        ),
    )
    try:
        page.goto(f"{live_console}/app/dashboard", wait_until="domcontentloaded")
        page.wait_for_timeout(5200)
    finally:
        page.close()
    assert len(calls) <= 3, f"metrics endpoint was polled {len(calls)} times in 5s"


@pytest.mark.browser
def test_dashboard_renders_combined_monitoring_charts(console_page, live_console: str) -> None:
    """The dashboard shows two combined charts (CPU & Memory, Network) with axes, lines and a live legend."""
    _page, context, _errors = console_page
    page = context.new_page()
    counters = {"rx": 1_000_000, "tx": 2_000_000}

    def _metrics(route):
        counters["rx"] += 250_000
        counters["tx"] += 500_000
        route.fulfill(
            status=200,
            content_type="application/json",
            body=(
                '{"cpu":{"usage_percent":14.3,"load_1":0.5},'
                '"memory":{"usage_percent":19.7,"used_bytes":2000000000,"total_bytes":10000000000},'
                f'"network":{{"interfaces":[{{"rx_bytes":{counters["rx"]},"tx_bytes":{counters["tx"]}}}]}},'
                f'"sampled_at_ms":{int(time.time() * 1000)}}}'
            ),
        )

    page.route("**/api/v1/system/metrics", _metrics)
    try:
        page.goto(f"{live_console}/app/dashboard", wait_until="domcontentloaded")
        # Wait past the ~5s downsample boundary so each chart records >=2 points and draws a line.
        page.wait_for_function(
            """() => {
                const cpu = document.querySelector('[data-chart="cpu-memory"]');
                const net = document.querySelector('[data-chart="network"]');
                return cpu && net
                    && cpu.querySelectorAll('polyline.chart-line').length >= 1
                    && net.querySelectorAll('polyline.chart-line').length >= 1;
            }""",
            timeout=9000,
        )
        state = page.evaluate(
            """() => ({
                cpuGrid: document.querySelectorAll('[data-chart="cpu-memory"] line.chart-grid').length,
                netGrid: document.querySelectorAll('[data-chart="network"] line.chart-grid').length,
                cpuLines: document.querySelectorAll('[data-chart="cpu-memory"] polyline.chart-line').length,
                netLines: document.querySelectorAll('[data-chart="network"] polyline.chart-line').length,
                cpuLegend: document.querySelector('[data-chart-legend="cpu"]').textContent.trim(),
                memLegend: document.querySelector('[data-chart-legend="memory"]').textContent.trim(),
                inLegend: document.querySelector('[data-chart-legend="input"]').textContent.trim(),
                outLegend: document.querySelector('[data-chart-legend="output"]').textContent.trim(),
                cpuAxisLabels: document.querySelectorAll('[data-chart="cpu-memory"] text.chart-axis').length,
            })"""
        )
    finally:
        page.close()
    assert state["cpuGrid"] >= 2, "CPU & Memory chart is missing gridlines"
    assert state["netGrid"] >= 2, "Network chart is missing gridlines"
    assert state["cpuLines"] >= 2, "CPU & Memory chart should plot both CPU and Memory lines"
    assert state["netLines"] >= 2, "Network chart should plot both Input and Output lines"
    assert state["cpuAxisLabels"] >= 2, "CPU & Memory chart is missing y-axis labels"
    assert "14" in state["cpuLegend"], f"CPU legend not showing value: {state['cpuLegend']!r}"
    assert "19" in state["memLegend"], f"Memory legend not showing value: {state['memLegend']!r}"
    assert state["inLegend"] and state["inLegend"] != "—", "Input legend not populated"
    assert state["outLegend"] and state["outLegend"] != "—", "Output legend not populated"


@pytest.mark.browser
def test_dashboard_network_values_are_rounded_to_two_decimals(console_page, live_console: str) -> None:
    """Network legend and axis values always render with exactly two decimals (e.g. '100.21 KB/s')."""
    _page, context, _errors = console_page
    page = context.new_page()
    counters = {"rx": 1_000, "tx": 2_000}

    def _metrics(route):
        # Small deltas -> raw rates with long fractional tails (e.g. 499.5004... B/s).
        counters["rx"] += 300
        counters["tx"] += 600
        route.fulfill(
            status=200,
            content_type="application/json",
            body=(
                '{"cpu":{"usage_percent":14.3,"load_1":0.5},'
                '"memory":{"usage_percent":19.7,"used_bytes":2000000000,"total_bytes":10000000000},'
                f'"network":{{"interfaces":[{{"rx_bytes":{counters["rx"]},"tx_bytes":{counters["tx"]}}}]}},'
                f'"sampled_at_ms":{int(time.time() * 1000)}}}'
            ),
        )

    page.route("**/api/v1/system/metrics", _metrics)
    try:
        page.goto(f"{live_console}/app/dashboard", wait_until="domcontentloaded")
        page.wait_for_function(
            """() => document.querySelector('[data-chart-legend="input"]').textContent.trim().length > 5""",
            timeout=9000,
        )
        state = page.evaluate(
            """() => ({
                legends: ['input', 'output'].map((k) =>
                    document.querySelector(`[data-chart-legend="${k}"]`).textContent.trim()),
                axis: [...document.querySelectorAll('[data-chart="network"] text.chart-axis-y')]
                    .map((n) => n.textContent.trim()),
            })"""
        )
    finally:
        page.close()
    value_pattern = re.compile(r"^\d+\.\d{2} (B|KB|MB|GiB)/s$")
    legend_pattern = re.compile(r"^\S+ \d+\.\d{2} (B|KB|MB|GiB)/s$")
    for legend in state["legends"]:
        assert legend_pattern.match(legend), f"network legend is not rounded to 2 decimals: {legend!r}"
    for label in state["axis"]:
        assert value_pattern.match(label), f"network axis label is not rounded to 2 decimals: {label!r}"


@pytest.mark.browser
def test_dashboard_chart_history_survives_reload(console_page, live_console: str) -> None:
    """Chart history is persisted so reloading the dashboard restores recorded points immediately."""
    _page, context, _errors = console_page
    page = context.new_page()
    counters = {"rx": 1_000_000, "tx": 2_000_000}

    def _metrics(route):
        counters["rx"] += 250_000
        counters["tx"] += 500_000
        route.fulfill(
            status=200,
            content_type="application/json",
            body=(
                '{"cpu":{"usage_percent":14.3,"load_1":0.5},'
                '"memory":{"usage_percent":19.7,"used_bytes":2000000000,"total_bytes":10000000000},'
                f'"network":{{"interfaces":[{{"rx_bytes":{counters["rx"]},"tx_bytes":{counters["tx"]}}}]}},'
                f'"sampled_at_ms":{int(time.time() * 1000)}}}'
            ),
        )

    page.route("**/api/v1/system/metrics", _metrics)
    try:
        page.goto(f"{live_console}/app/dashboard", wait_until="domcontentloaded")
        # Accumulate >=2 recorded points per chart so a line is drawn (2 charts x 2 series).
        page.wait_for_function(
            """() => {
                const lines = [...document.querySelectorAll('[data-chart] polyline.chart-line')];
                return lines.length >= 4
                    && lines.every((n) => n.getAttribute('points').split(' ').length >= 2);
            }""",
            timeout=9000,
        )
        page.reload(wait_until="domcontentloaded")
        # Within <5s of reload the downsample interval cannot have recorded two
        # fresh points, so any two-point line must come from restored history.
        page.wait_for_function(
            """() => {
                const lines = [...document.querySelectorAll('[data-chart] polyline.chart-line')];
                return lines.length >= 4
                    && lines.every((n) => n.getAttribute('points').split(' ').length >= 2);
            }""",
            timeout=3500,
        )
        restored = page.evaluate(
            """() => [...document.querySelectorAll('[data-chart] polyline.chart-line')]
                    .map((n) => n.getAttribute('points').split(' ').length)"""
        )
    finally:
        page.close()
    assert all(count >= 2 for count in restored), (
        f"chart lines disappeared after reload instead of restoring history: {restored}"
    )


@pytest.mark.browser
def test_dashboard_seeds_charts_from_server_history(console_page, live_console: str) -> None:
    """Charts render recorded points immediately from /metrics/history, before live sampling."""
    _page, context, _errors = console_page
    page = context.new_page()
    now = int(time.time() * 1000)
    samples = [
        {"t": now - 10_000, "cpu": 10.0, "mem": 40.0, "input": 1024.0, "output": 2048.0},
        {"t": now - 5_000, "cpu": 20.0, "mem": 50.0, "input": 2048.0, "output": 3072.0},
        {"t": now, "cpu": 30.0, "mem": 60.0, "input": 3072.0, "output": 4096.0},
    ]

    def _history(route):
        route.fulfill(status=200, content_type="application/json", body=json.dumps(samples))

    counters = {"rx": 1_000_000, "tx": 2_000_000}

    def _metrics(route):
        # cpu/mem match the newest server row so the legend assertion is stable
        # regardless of whether replay or live set it last; decreasing counters
        # make the live rate guard skip pushes, leaving the network legend on
        # the replayed value.
        counters["rx"] -= 1_000
        counters["tx"] -= 1_000
        route.fulfill(
            status=200,
            content_type="application/json",
            body=(
                '{"cpu":{"usage_percent":30.0,"load_1":0.5},'
                '"memory":{"usage_percent":60.0,"used_bytes":2000000000,"total_bytes":10000000000},'
                f'"network":{{"interfaces":[{{"rx_bytes":{counters["rx"]},"tx_bytes":{counters["tx"]}}}]}},'
                f'"sampled_at_ms":{int(time.time() * 1000)}}}'
            ),
        )

    page.route("**/api/v1/system/metrics/history", _history)
    page.route("**/api/v1/system/metrics", _metrics)
    try:
        page.goto(f"{live_console}/app/dashboard", wait_until="domcontentloaded")
        page.wait_for_function(
            """() => {
                const lines = [...document.querySelectorAll('[data-chart] polyline.chart-line')];
                return lines.length >= 4
                    && lines.every((n) => n.getAttribute('points').split(' ').length >= 3);
            }""",
            timeout=3500,  # well under the 5s live downsample: replay must be immediate
        )
        state = page.evaluate(
            """() => ({
                cpuLegend: document.querySelector('[data-chart-legend="cpu"]').textContent.trim(),
                inLegend: document.querySelector('[data-chart-legend="input"]').textContent.trim(),
            })"""
        )
    finally:
        page.close()
    assert "30" in state["cpuLegend"], f"CPU legend should show the newest server value: {state['cpuLegend']!r}"
    assert "3.00 KB/s" in state["inLegend"], (
        f"Input legend should show the newest server rate: {state['inLegend']!r}"
    )


@pytest.mark.browser
def test_dashboard_history_failure_still_renders_charts(console_page, live_console: str) -> None:
    """When /metrics/history is unreachable the dashboard falls back to localStorage history."""
    _page, context, _errors = console_page
    page = context.new_page()
    counters = {"rx": 1_000_000, "tx": 2_000_000}

    def _metrics(route):
        counters["rx"] += 250_000
        counters["tx"] += 500_000
        route.fulfill(
            status=200,
            content_type="application/json",
            body=(
                '{"cpu":{"usage_percent":14.3,"load_1":0.5},'
                '"memory":{"usage_percent":19.7,"used_bytes":2000000000,"total_bytes":10000000000},'
                f'"network":{{"interfaces":[{{"rx_bytes":{counters["rx"]},"tx_bytes":{counters["tx"]}}}]}},'
                f'"sampled_at_ms":{int(time.time() * 1000)}}}'
            ),
        )

    page.route("**/api/v1/system/metrics/history", lambda route: route.abort("failed"))
    page.route("**/api/v1/system/metrics", _metrics)
    try:
        page.goto(f"{live_console}/app/dashboard", wait_until="domcontentloaded")
        # Charts must still draw from live sampling after the failed history fetch.
        page.wait_for_function(
            """() => [...document.querySelectorAll('[data-chart] polyline.chart-line')].length >= 4""",
            timeout=9000,
        )
        problems = [error for error in _errors if "pageerror" in error]
    finally:
        page.close()
    assert not problems, f"history failure caused page errors: {problems}"


@pytest.mark.browser
def test_dashboard_charts_are_separated_centered_and_undistorted(console_page, live_console: str) -> None:
    """Each chart sits in its own visible card, bottom legend is centered, and chart
    text is not horizontally stretched (viewBox must match the rendered size)."""
    _page, context, _errors = console_page
    page = context.new_page()
    counters = {"rx": 1_000_000, "tx": 2_000_000}

    def _metrics(route):
        counters["rx"] += 250_000
        counters["tx"] += 500_000
        route.fulfill(
            status=200,
            content_type="application/json",
            body=(
                '{"cpu":{"usage_percent":14.3,"load_1":0.5},'
                '"memory":{"usage_percent":19.7,"used_bytes":2000000000,"total_bytes":10000000000},'
                f'"network":{{"interfaces":[{{"rx_bytes":{counters["rx"]},"tx_bytes":{counters["tx"]}}}]}},'
                f'"sampled_at_ms":{int(time.time() * 1000)}}}'
            ),
        )

    page.route("**/api/v1/system/metrics", _metrics)
    try:
        page.goto(f"{live_console}/app/dashboard", wait_until="domcontentloaded")
        page.wait_for_function(
            """() => document.querySelectorAll('[data-chart="cpu-memory"] polyline.chart-line').length >= 1""",
            timeout=9000,
        )
        state = page.evaluate(
            """() => ({
                svgs: [...document.querySelectorAll('[data-chart]')].map((svg) => {
                    const rect = svg.getBoundingClientRect();
                    const vb = svg.viewBox.baseVal;
                    return { w: rect.width, vbW: vb.width, h: rect.height, vbH: vb.height,
                             par: svg.getAttribute('preserveAspectRatio') };
                }),
                legendJustify: getComputedStyle(document.querySelector('.chart-legend')).justifyContent,
                cardBorders: [...document.querySelectorAll('.chart-card')]
                    .map((n) => getComputedStyle(n).borderTopWidth),
                cardBackgrounds: [...document.querySelectorAll('.chart-card')]
                    .map((n) => getComputedStyle(n).backgroundColor),
            })"""
        )
    finally:
        page.close()
    for i, svg in enumerate(state["svgs"]):
        assert svg["par"] != "none", (
            f"chart {i}: preserveAspectRatio='none' stretches the text horizontally"
        )
        assert abs(svg["vbW"] - svg["w"]) <= 2, (
            f"chart {i}: viewBox width {svg['vbW']} != rendered width {svg['w']} — axis text will look distorted"
        )
        assert abs(svg["vbH"] - svg["h"]) <= 2, (
            f"chart {i}: viewBox height {svg['vbH']} != rendered height {svg['h']}"
        )
    assert state["legendJustify"] == "center", (
        f"chart legend row should be centered, got justify-content: {state['legendJustify']}"
    )
    for i, (border, background) in enumerate(zip(state["cardBorders"], state["cardBackgrounds"])):
        assert border not in ("", "0px"), f"chart card {i} has no border — the two charts don't read as separate cards"
        assert background not in ("", "rgba(0, 0, 0, 0)", "transparent"), (
            f"chart card {i} has no background — the two charts don't read as separate cards"
        )
