from pathlib import Path

import pytest

from app.config import load_acme_dns_config
from privileged.acme_dns_helper import AcmeDnsHelperOps


def test_acme_dns_config_defaults_when_file_missing(tmp_path):
    cfg = load_acme_dns_config(tmp_path / "missing.conf")
    assert cfg.enabled is False
    assert cfg.zone == "acme-dns.connect3.net.bd"
    assert cfg.nameserver == "ns1-acme.connect3.net.bd"
    assert cfg.listen_ip is None
    assert cfg.ttl == 30
    assert cfg.listen_port == 53


def test_acme_dns_config_reads_root_owned_style_file(tmp_path):
    path = tmp_path / "acme.conf"
    path.write_text("\n".join([
        "ACME_DNS_ENABLED=true",
        "ACME_DNS_ZONE=ACME-DNS.Example.COM.",
        "ACME_DNS_NS=ns1.example.com.",
        "ACME_DNS_LISTEN_IP=192.0.2.53",
        "ACME_DNS_PORT=5353",
        "ACME_DNS_TTL=30",
    ]))
    cfg = load_acme_dns_config(path)
    assert cfg.enabled is True
    assert cfg.zone == "acme-dns.example.com"
    assert cfg.nameserver == "ns1.example.com"
    assert cfg.listen_ip == "192.0.2.53"
    assert cfg.ttl == 30
    assert cfg.listen_port == 5353


def test_preflight_rejects_missing_listen_ip():
    cfg = load_acme_dns_config(Path("/nonexistent"))
    cfg = cfg.__class__(enabled=True, zone=cfg.zone, nameserver=cfg.nameserver, listen_ip=None, ttl=30)
    ops = AcmeDnsHelperOps(cfg, local_ips=lambda: {"192.0.2.53"}, port_available=lambda ip, port, proto: True)
    with pytest.raises(RuntimeError, match="listen IP is not configured"):
        ops.preflight()


def test_preflight_rejects_ip_not_present_locally():
    cfg = load_acme_dns_config(Path("/nonexistent")).__class__(True, "acme-dns.connect3.net.bd", "ns1-acme.connect3.net.bd", "192.0.2.53", 30)
    ops = AcmeDnsHelperOps(cfg, local_ips=lambda: {"192.0.2.10"}, port_available=lambda ip, port, proto: True)
    with pytest.raises(RuntimeError, match="listen IP is not present locally"):
        ops.preflight()


@pytest.mark.parametrize("proto", ["tcp", "udp"])
def test_preflight_rejects_port_53_collision(proto):
    cfg = load_acme_dns_config(Path("/nonexistent")).__class__(True, "acme-dns.connect3.net.bd", "ns1-acme.connect3.net.bd", "192.0.2.53", 30)
    ops = AcmeDnsHelperOps(
        cfg,
        local_ips=lambda: {"192.0.2.53"},
        port_available=lambda ip, port, candidate: candidate != proto,
    )
    with pytest.raises(RuntimeError, match=f"{proto.upper()} 53 is already in use"):
        ops.preflight()


def test_preflight_and_rendered_knot_config_are_authoritative_only():
    cfg = load_acme_dns_config(Path("/nonexistent")).__class__(True, "acme-dns.connect3.net.bd", "ns1-acme.connect3.net.bd", "192.0.2.53", 30)
    ops = AcmeDnsHelperOps(cfg, local_ips=lambda: {"192.0.2.53"}, port_available=lambda ip, port, proto: True)
    assert ops.preflight() == {"safe": True, "listen_ip": "192.0.2.53", "listen_port": 53, "zone": "acme-dns.connect3.net.bd"}
    text = ops.render_knot_config()
    assert "listen: 192.0.2.53@53" in text
    assert "domain: acme-dns.connect3.net.bd" in text
    assert "storage: /var/lib/dns-manager/acme-dns" in text
    assert "recurs" not in text.lower()


def test_preflight_uses_configured_nonstandard_listen_port():
    cfg = load_acme_dns_config(Path("/nonexistent")).__class__(
        True, "acme-dns.connect3.net.bd", "ns1-acme.connect3.net.bd", "192.0.2.53", 30, 5353
    )
    calls = []
    ops = AcmeDnsHelperOps(
        cfg,
        local_ips=lambda: {"192.0.2.53"},
        port_available=lambda ip, port, proto: calls.append((ip, port, proto)) or True,
    )
    assert ops.preflight() == {
        "safe": True,
        "listen_ip": "192.0.2.53",
        "listen_port": 5353,
        "zone": "acme-dns.connect3.net.bd",
    }
    assert calls == [("192.0.2.53", 5353, "tcp"), ("192.0.2.53", 5353, "udp")]
    assert "listen: 192.0.2.53@5353" in ops.render_knot_config()


def test_preflight_reports_configured_port_collision():
    cfg = load_acme_dns_config(Path("/nonexistent")).__class__(
        True, "acme-dns.connect3.net.bd", "ns1-acme.connect3.net.bd", "192.0.2.53", 30, 5353
    )
    ops = AcmeDnsHelperOps(
        cfg,
        local_ips=lambda: {"192.0.2.53"},
        port_available=lambda ip, port, proto: False if proto == "tcp" else True,
    )
    with pytest.raises(RuntimeError, match="TCP 5353 is already in use"):
        ops.preflight()

class Result:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class Runner:
    def __init__(self, fail_on=None):
        self.calls = []
        self.fail_on = fail_on
    def __call__(self, argv, **kwargs):
        self.calls.append(list(argv))
        if self.fail_on and self.fail_on in argv:
            return Result(1, stderr="knot failed")
        if argv[:3] == ["/usr/bin/systemctl", "is-active", "knot"]:
            return Result(0, stdout="active\n")
        return Result()


def _configured(tmp_path, **kwargs):
    cfg = load_acme_dns_config(Path("/nonexistent")).__class__(
        True, "acme-dns.connect3.net.bd", "ns1-acme.connect3.net.bd", "192.0.2.53", 30
    )
    return AcmeDnsHelperOps(
        cfg,
        local_ips=lambda: {"192.0.2.53"},
        port_available=lambda ip, port, proto: True,
        storage=tmp_path,
        registration_checker=kwargs.pop("registration_checker", lambda host: True),
        runner=kwargs.pop("runner", Runner()),
        **kwargs,
    )


def test_txt_set_rejects_hostname_outside_managed_zone_and_shell_text(tmp_path):
    ops = _configured(tmp_path)
    for hostname in ["dns-a1b2c3d4e5f6.example.com", "dns-a1b2c3d4e5f6.acme-dns.connect3.net.bd\nEVIL"]:
        with pytest.raises(ValueError, match="invalid ACME delegation hostname"):
            ops.txt_set(hostname, "token")


def test_txt_set_rejects_unregistered_delegation(tmp_path):
    ops = _configured(tmp_path, registration_checker=lambda host: False)
    with pytest.raises(ValueError, match="unregistered ACME delegation"):
        ops.txt_set("dns-a1b2c3d4e5f6.acme-dns.connect3.net.bd", "token")


def test_txt_set_atomically_updates_zone_and_reloads_knot(tmp_path):
    runner = Runner()
    ops = _configured(tmp_path, runner=runner)
    result = ops.txt_set("dns-a1b2c3d4e5f6.acme-dns.connect3.net.bd", "validation-token")
    zone = tmp_path / "acme-dns.connect3.net.bd.zone"
    assert result == {"updated": True}
    assert 'TXT "validation-token"' in zone.read_text()
    assert ["/usr/sbin/knotc", "zone-check", "acme-dns.connect3.net.bd"] in runner.calls
    assert ["/usr/sbin/knotc", "zone-reload", "acme-dns.connect3.net.bd"] in runner.calls


def test_txt_update_rolls_back_zone_when_knot_check_fails(tmp_path):
    good_runner = Runner()
    ops = _configured(tmp_path, runner=good_runner)
    ops.txt_set("dns-a1b2c3d4e5f6.acme-dns.connect3.net.bd", "good")
    before = (tmp_path / "acme-dns.connect3.net.bd.zone").read_text()

    bad = _configured(tmp_path, runner=Runner(fail_on="zone-check"))
    with pytest.raises(RuntimeError, match="knot failed"):
        bad.txt_set("dns-a1b2c3d4e5f6.acme-dns.connect3.net.bd", "bad")
    assert (tmp_path / "acme-dns.connect3.net.bd.zone").read_text() == before


def test_acme_dns_status_reports_knot_and_zone(tmp_path):
    runner = Runner()
    ops = _configured(tmp_path, runner=runner)
    status = ops.status()
    assert status["service"] == "active"
    assert status["zone"] == "acme-dns.connect3.net.bd"
    assert status["zone_loaded"] is False


def test_txt_set_is_idempotent_and_supports_multiple_values(tmp_path):
    ops = _configured(tmp_path)
    host = "dns-a1b2c3d4e5f6.acme-dns.connect3.net.bd"
    ops.txt_set(host, "token-one")
    ops.txt_set(host, "token-one")
    ops.txt_set(host, "token-two")
    zone = (tmp_path / "acme-dns.connect3.net.bd.zone").read_text()
    assert zone.count('TXT "token-one"') == 1
    assert zone.count('TXT "token-two"') == 1
    assert ' 30 IN TXT ' in zone


def test_txt_delete_removes_only_matching_value_and_is_idempotent(tmp_path):
    ops = _configured(tmp_path)
    host = "dns-a1b2c3d4e5f6.acme-dns.connect3.net.bd"
    ops.txt_set(host, "token-one")
    ops.txt_set(host, "token-two")
    ops.txt_delete(host, "token-one")
    ops.txt_delete(host, "token-one")
    zone = (tmp_path / "acme-dns.connect3.net.bd.zone").read_text()
    assert 'TXT "token-one"' not in zone
    assert 'TXT "token-two"' in zone
