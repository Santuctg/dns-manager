"""Regression for API preview keys consumed by System and Mappings UI."""
from pathlib import Path

JS = Path(__file__).resolve().parents[2] / 'app' / 'static' / 'app.js'


def test_system_and_mappings_previews_use_backend_config_fields():
    source = JS.read_text()
    assert source.count('renderConfigPreview(p)') == 2
    assert 'dnsmasq_config' in source
    assert 'nginx_config' in source
    assert 'textContent=p.dnsmasq;' not in source
    assert 'textContent=p.nginx;' not in source


def test_missing_preview_payload_is_not_silently_empty():
    source = JS.read_text()
    assert 'Configuration preview is missing' in source
    assert 'No dnsmasq configuration generated.' in source
    assert 'No Nginx configuration generated.' in source
