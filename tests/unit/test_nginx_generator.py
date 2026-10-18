from types import SimpleNamespace

import pytest

from app.services.nginx_service import render_nginx_config


def mapping(**overrides):
    data = {
        "domain": "panel.example.com",
        "upstream_scheme": "http",
        "upstream_host": "192.168.8.2",
        "upstream_port": 8082,
        "enabled": True,
        "websocket_enabled": True,
        "preserve_host": True,
        "tls_verify": True,
        "custom_timeout": None,
    }
    data.update(overrides)
    return SimpleNamespace(**data)


def test_http_upstream_renders_proxy_pass():
    result = render_nginx_config([mapping()], {})
    assert "server_name panel.example.com;" in result
    assert "proxy_pass http://192.168.8.2:8082;" in result


def test_https_upstream_renders_proxy_pass():
    result = render_nginx_config(
        [mapping(upstream_scheme="https", upstream_host="backend.internal", upstream_port=8443)],
        {},
    )
    assert "proxy_pass https://backend.internal:8443;" in result


def test_websocket_option_renders_upgrade_headers():
    result = render_nginx_config([mapping(websocket_enabled=True)], {})
    assert "proxy_set_header Upgrade $http_upgrade;" in result
    assert 'proxy_set_header Connection "upgrade";' in result


def test_websocket_headers_are_omitted_when_disabled():
    result = render_nginx_config([mapping(websocket_enabled=False)], {})
    assert "proxy_set_header Upgrade $http_upgrade;" not in result
    assert 'proxy_set_header Connection "upgrade";' not in result


def test_preserve_host_renders_host_header():
    result = render_nginx_config([mapping(preserve_host=True)], {})
    assert "proxy_set_header Host $host;" in result


def test_preserve_host_header_is_omitted_when_disabled():
    result = render_nginx_config([mapping(preserve_host=False)], {})
    assert "proxy_set_header Host $host;" not in result


def test_disabled_mapping_is_omitted():
    result = render_nginx_config(
        [mapping(domain="disabled.example.com", enabled=False), mapping(domain="live.example.com")],
        {},
    )
    assert "disabled.example.com" not in result
    assert "server_name live.example.com;" in result


def test_output_is_deterministic_and_sorted_by_domain():
    result = render_nginx_config(
        [mapping(domain="z.example.com"), mapping(domain="a.example.com", upstream_port=8080)],
        {},
    )
    assert result.index("server_name a.example.com;") < result.index("server_name z.example.com;")


@pytest.mark.parametrize(
    "field,value",
    [
        ("domain", "safe.example.com; return 200"),
        ("domain", "safe.example.com\nreturn 200"),
        ("upstream_host", "192.168.8.2;return"),
        ("upstream_host", "backend.internal\nserver{}"),
    ],
)
def test_injection_input_is_rejected(field, value):
    with pytest.raises(ValueError):
        render_nginx_config([mapping(**{field: value})], {})


def test_invalid_scheme_and_port_are_rejected():
    with pytest.raises(ValueError):
        render_nginx_config([mapping(upstream_scheme="ftp")], {})
    with pytest.raises(ValueError):
        render_nginx_config([mapping(upstream_port=70000)], {})

def test_ipv6_upstream_is_bracketed_in_proxy_pass():
    result = render_nginx_config(
        [mapping(upstream_host="2001:db8::10", upstream_port=8082)],
        {},
    )
    assert "proxy_pass http://[2001:db8::10]:8082;" in result


def test_057_skips_http_proxy_for_domains_owned_by_ssl_redirect_vhost():
    result = render_nginx_config(
        [mapping(domain="vm226.connect3.net.bd", upstream_scheme="https", upstream_host="192.168.255.226", upstream_port=443)],
        {},
        skip_http_domains={"vm226.connect3.net.bd"},
    )
    assert "server_name vm226.connect3.net.bd;" not in result
    assert "proxy_pass https://192.168.255.226:443;" not in result


def test_057_keeps_http_proxy_for_non_ssl_mapping():
    result = render_nginx_config(
        [mapping(domain="plain.connect3.net.bd", upstream_host="192.168.255.50", upstream_port=8080)],
        {},
        skip_http_domains={"vm226.connect3.net.bd"},
    )
    assert "server_name plain.connect3.net.bd;" in result
    assert "proxy_pass http://192.168.255.50:8080;" in result
