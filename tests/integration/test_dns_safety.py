from pathlib import Path

import pytest


def test_safe_base_config_requires_exact_private_listen_bind_no_resolv_and_upstream():
    from app.services.dns_safety import validate_base_config

    text = """
listen-address=192.168.128.2
bind-interfaces
no-resolv
server=127.0.0.53
"""
    result = validate_base_config(text, "192.168.128.2")
    assert result["safe"] is True
    assert result["issues"] == []


@pytest.mark.parametrize(
    "text, expected_issue",
    [
        ("listen-address=0.0.0.0\nbind-interfaces\nno-resolv\nserver=127.0.0.53\n", "listen-address"),
        ("listen-address=8.8.8.8\nbind-interfaces\nno-resolv\nserver=127.0.0.53\n", "listen-address"),
        ("listen-address=192.168.128.2\nno-resolv\nserver=127.0.0.53\n", "bind-interfaces"),
        ("listen-address=192.168.128.2\nbind-interfaces\nserver=127.0.0.53\n", "no-resolv"),
        ("listen-address=192.168.128.2\nbind-interfaces\nno-resolv\n", "server="),
        ("listen-address=192.168.128.2\nlisten-address=192.168.128.1\nbind-interfaces\nno-resolv\nserver=127.0.0.53\n", "unexpected listen-address"),
    ],
)
def test_unsafe_base_config_is_rejected(text, expected_issue):
    from app.services.dns_safety import validate_base_config

    result = validate_base_config(text, "192.168.128.2")
    assert result["safe"] is False
    assert any(expected_issue in issue for issue in result["issues"])


def test_expected_dns_ip_may_be_public_unicast_when_exactly_configured():
    from app.services.dns_safety import validate_base_config

    result = validate_base_config(
        "listen-address=8.8.8.8\nbind-interfaces\nno-resolv\nserver=1.1.1.1\n",
        "8.8.8.8",
    )
    assert result["safe"] is True
    assert result["issues"] == []


def test_runtime_bindings_allow_expected_ip_and_loopback_stubs_only():
    from app.services.dns_safety import validate_runtime_bindings

    output = """
UNCONN 0 0 192.168.128.2:53 0.0.0.0:*
LISTEN 0 32 192.168.128.2:53 0.0.0.0:*
UNCONN 0 0 127.0.0.53%lo:53 0.0.0.0:*
LISTEN 0 4096 127.0.0.53%lo:53 0.0.0.0:*
"""
    result = validate_runtime_bindings(output, "192.168.128.2")
    assert result["safe"] is True
    assert "192.168.128.2" in result["bindings"]


def test_runtime_bindings_reject_wildcard_or_other_non_loopback_bind():
    from app.services.dns_safety import validate_runtime_bindings

    output = """
UNCONN 0 0 0.0.0.0:53 0.0.0.0:*
LISTEN 0 32 10.0.0.2:53 0.0.0.0:*
"""
    result = validate_runtime_bindings(output, "192.168.128.2")
    assert result["safe"] is False
    assert result["issues"]


def test_runtime_bindings_require_expected_ip():
    from app.services.dns_safety import validate_runtime_bindings

    result = validate_runtime_bindings(
        "UNCONN 0 0 127.0.0.53%lo:53 0.0.0.0:*\n",
        "192.168.128.2",
    )
    assert result["safe"] is False
    assert any("not bound" in issue for issue in result["issues"])


def test_system_status_requires_dns_safety(monkeypatch):
    import app.services.health_service as health

    monkeypatch.setattr(health, "database_health", lambda: "ok")
    monkeypatch.setattr(health, "_port_open", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(
        health,
        "get_dns_safety_status",
        lambda: {"safe": False, "config_safe": True, "runtime_safe": False, "issues": ["wildcard bind"]},
    )

    class Helper:
        def status(self):
            return {"dnsmasq": "active", "nginx": "active"}

    result = health.get_system_status(helper=Helper())
    assert result["status"] == "not_ready"
    assert result["dns_safety"]["safe"] is False


def test_installer_runs_dns_safety_validation_before_starting_services():
    root = Path(__file__).resolve().parents[2]
    installer = (root / "packaging" / "install.sh").read_text()
    assert "00-dns-manager-base.conf" in installer
    assert "app.services.dns_safety" in installer
    assert installer.index("app.services.dns_safety") < installer.index("systemctl enable --now dns-manager.service")


def test_system_page_exposes_dns_safety_badge_and_expected_bind_address():
    root = Path(__file__).resolve().parents[2]
    template = (root / "app" / "templates" / "system.html").read_text()
    javascript = (root / "app" / "static" / "app.js").read_text()
    assert 'data-system="dns_safety"' in template
    assert 'data-system="dns_bind"' in template
    assert 's.dns_safety' in javascript


def test_public_unicast_expected_dns_ip_is_allowed_when_exactly_bound():
    from app.services.dns_safety import validate_base_config

    text = """
listen-address=157.15.20.132
bind-interfaces
no-resolv
server=127.0.0.53
"""
    result = validate_base_config(text, "157.15.20.132")
    assert result["safe"] is True
    assert result["issues"] == []


def test_expected_dns_ip_rejects_non_unicast_special_addresses():
    from app.services.dns_safety import validate_base_config

    for value in ("0.0.0.0", "127.0.0.1", "169.254.1.2", "224.0.0.1"):
        result = validate_base_config(
            f"listen-address={value}\nbind-interfaces\nno-resolv\nserver=1.1.1.1\n",
            value,
        )
        assert result["safe"] is False
        assert any("valid unicast" in issue for issue in result["issues"])


def test_reconcile_base_config_changes_only_single_safe_listen_address():
    from app.services.dns_safety import reconcile_base_config

    original = """# DNS Manager base\nlisten-address=192.168.128.2\nbind-interfaces\nno-resolv\nserver=127.0.0.53\n"""
    updated = reconcile_base_config(original, "157.15.20.132")
    assert "listen-address=157.15.20.132" in updated
    assert "listen-address=192.168.128.2" not in updated
    assert "bind-interfaces\nno-resolv\nserver=127.0.0.53" in updated


def test_reconcile_base_config_refuses_ambiguous_or_wildcard_bind():
    from app.services.dns_safety import reconcile_base_config

    with pytest.raises(ValueError):
        reconcile_base_config(
            "listen-address=0.0.0.0\nbind-interfaces\nno-resolv\nserver=127.0.0.53\n",
            "157.15.20.132",
        )
    with pytest.raises(ValueError):
        reconcile_base_config(
            "listen-address=192.168.128.2\nlisten-address=192.168.128.3\nbind-interfaces\nno-resolv\nserver=127.0.0.53\n",
            "157.15.20.132",
        )


def test_installer_persists_explicit_proxy_ip_and_reconciles_dns_base_config():
    root = Path(__file__).resolve().parents[2]
    installer = (root / "packaging" / "install.sh").read_text()
    assert "zz-internal-proxy.conf" in installer
    assert "DNS_MANAGER_INTERNAL_PROXY_IP=$EXPECTED_DNS_IP" in installer
    assert "--reconcile-base" in installer
    assert "systemctl restart dnsmasq" in installer
