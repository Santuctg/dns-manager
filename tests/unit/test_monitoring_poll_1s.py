"""The shared poller keeps the 1-second cadence, backs off, and pauses when hidden."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_poller_uses_one_second_success_interval_and_dynamic_backoff():
    source = (ROOT / "app" / "static" / "js" / "core.js").read_text(encoding="utf-8")
    section = source.split("export function poll(", 1)[1].split("// ------------------------------------------------------------------ shell chrome", 1)[0]
    assert "intervalMs = 1000" in section
    assert "maxBackoff = 30000" in section
    assert "document.hidden" in section
    assert "setTimeout" in section
    assert "clearTimeout" in section
    assert "Math.min(" in section


def test_every_page_uses_the_shared_poller():
    pages = ROOT / "app" / "static" / "js" / "pages"
    dashboard = (pages / "dashboard.js").read_text(encoding="utf-8")
    system = (pages / "system.js").read_text(encoding="utf-8")
    firewall = (pages / "firewall.js").read_text(encoding="utf-8")
    assert "poll(" in dashboard
    assert "poll(" in system
    assert "setInterval" not in dashboard or "poll(" in dashboard
    assert "refreshMetrics" in system
    assert "countdown" in firewall


def test_version_is_the_console_release():
    assert (ROOT / "VERSION").read_text(encoding="utf-8").strip() == "0.7.11"
