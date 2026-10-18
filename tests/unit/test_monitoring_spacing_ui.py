from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_monitoring_section_has_safe_separation_and_card_spacing():
    css = (ROOT / 'app/static/app.css').read_text()
    assert '[data-host-monitoring]{margin-bottom:var(--space-6)}' in css
    assert '.resource-metrics .metric-card{padding:var(--space-5)' in css
    assert '.monitor-details{display:grid;gap:var(--space-4)' in css


def test_system_monitoring_detail_sections_are_individually_contained():
    system = (ROOT / 'app/templates/system.html').read_text()
    assert system.count('class="monitor-detail-panel"') == 3
    assert 'data-monitor-interfaces' in system
    assert 'data-monitor-disks' in system
    assert 'data-monitor-services' in system
    assert 'class="monitor-detail-panel"' not in (ROOT / 'app/templates/dashboard.html').read_text()


def test_monitoring_panels_have_responsive_padding():
    css = (ROOT / 'app/static/app.css').read_text()
    assert '.monitor-detail-panel{min-width:0;padding:var(--space-5)' in css
    assert '@media(max-width:640px){.resource-metrics' in css
