"""Layout contracts for the dense Console pages and their phone card mode."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def css(name: str) -> str:
    return (ROOT / "app" / "static" / "css" / name).read_text(encoding="utf-8")


def test_monitoring_cards_keep_safe_spacing():
    pages = css("pages.css")
    assert ".monitor-details {" in pages
    assert ".monitor-detail-panel {" in pages
    assert ".resource-metrics .metric-card { padding: var(--space-5); }" in pages


def test_system_monitoring_detail_sections_are_individually_contained():
    system = (ROOT / "app" / "templates" / "system.html").read_text(encoding="utf-8")
    assert system.count('class="monitor-detail-panel"') == 3
    assert "data-monitor-interfaces" in system
    assert "data-monitor-disks" in system
    assert "data-monitor-services" in system
    assert 'class="monitor-detail-panel"' not in (
        ROOT / "app" / "templates" / "dashboard.html"
    ).read_text(encoding="utf-8")


def test_tables_become_cards_without_page_overflow():
    components = css("components.css")
    assert ".table-wrap {" in components
    assert "overflow-x: auto" in components
    assert "@media (max-width: 767px)" in components
    assert "display: block" in components
    assert "content: attr(data-label)" in components
    assert "min-width: 0" in css("base.css")


def test_long_machine_values_wrap_or_scroll_instead_of_widening_the_page():
    components = css("components.css")
    assert "overflow-wrap: anywhere" in components
    assert ".cell-mono" in components
    assert "font-variant-numeric: tabular-nums" in components
    assert "max-width: 100%" in components
