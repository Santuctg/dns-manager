"""The System and Mappings preview panels must read the backend preview keys."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_system_diff_uses_the_backend_config_fields():
    source = read("app/static/js/pages/system.js")
    assert "preview.dnsmasq_config" in source
    assert "preview.nginx_config" in source
    assert "preview.active_dnsmasq_config" in source
    assert "preview.active_nginx_config" in source
    assert "textContent=p.dnsmasq" not in source
    assert "textContent=p.nginx" not in source


def test_mapping_detail_uses_both_http_and_https_preview_blocks():
    source = read("app/static/js/pages/mappings.js")
    assert "nginx_config" in source
    assert "ssl_vhosts" in source
    assert "state.preview" in source
    assert "preview_permission" in source


def test_missing_preview_payload_is_not_silently_empty():
    system = read("app/static/js/pages/system.js")
    mappings = read("app/static/js/pages/mappings.js")
    assert "no_http_block" in mappings
    assert "no_https_block" in mappings
    assert "diff-empty" in system
    assert "no_changes" in system


def test_preview_api_documents_every_consumed_key():
    api = read("app/api/config_ops.py")
    service = read("app/services/apply_service.py")
    for key in ("dnsmasq_config", "nginx_config", "ssl_vhosts"):
        assert key in service
    for key in (
        "active_dnsmasq_config",
        "active_nginx_config",
        "pending_change_count",
        "active_revision",
    ):
        assert key in api
