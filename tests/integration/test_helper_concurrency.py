import socket
import threading
import time

import pytest

import privileged.helper_server as helper_server
from app.services.privileged_helper import PrivilegedHelper


@pytest.fixture
def server(tmp_path):
    path = tmp_path / "helper.sock"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(path))
    listener.listen(8)

    class StatusOps:
        def status(self):
            return {"dnsmasq": "active", "nginx": "active"}

    thread = threading.Thread(
        target=helper_server.serve_forever,
        kwargs={"listener": listener, "ops_factory": StatusOps},
        daemon=True,
    )
    thread.start()
    yield str(path)
    listener.close()


def client(path, timeout=2.0):
    return PrivilegedHelper(socket_path=path, timeout=timeout)


def test_status_answers_while_a_long_certbot_run_is_in_progress(server, monkeypatch):
    started, release = threading.Event(), threading.Event()

    class SlowSsl:
        def ssl_issue(self, domain, provider, token=None):
            started.set()
            release.wait(10)
            return {"issued": True}

    monkeypatch.setattr(helper_server, "SslHelperOps", SlowSsl)
    issue = threading.Thread(
        target=lambda: client(server, timeout=15).ssl_issue(domain="a.example.com", provider="cloudflare", token="t"),
        daemon=True,
    )
    issue.start()
    assert started.wait(5)
    try:
        began = time.monotonic()
        assert client(server).status() == {"dnsmasq": "active", "nginx": "active"}
        assert time.monotonic() - began < 1.0
    finally:
        release.set()
        issue.join(5)


def test_firewall_confirm_is_not_blocked_by_certbot(server, monkeypatch):
    started, release = threading.Event(), threading.Event()

    class SlowSsl:
        def ssl_renew(self, domain, provider, token=None, force=False):
            started.set()
            release.wait(10)
            return {"renewed": True}

    class Firewall:
        def confirm(self, token):
            return {"confirmed": True}

    monkeypatch.setattr(helper_server, "SslHelperOps", SlowSsl)
    monkeypatch.setattr(helper_server, "FirewallHelperOps", Firewall)
    renew = threading.Thread(
        target=lambda: client(server, timeout=15).ssl_renew(domain="a.example.com", provider="cloudflare", token="t"),
        daemon=True,
    )
    renew.start()
    assert started.wait(5)
    try:
        assert client(server).firewall_confirm("0" * 32) == {"confirmed": True}
    finally:
        release.set()
        renew.join(5)


def test_acme_hook_can_call_back_into_the_helper_during_certbot(server, monkeypatch):
    """certbot runs inside ssl_issue and its acme-dns hook calls acme_txt_set on the same socket."""
    records = []

    class Acme:
        def txt_set(self, hostname, value):
            records.append((hostname, value))
            return {"updated": True}

    class HookCallingSsl:
        def ssl_issue(self, domain, provider, token=None):
            # Stand-in for certbot invoking dns-manager-acme-dns-hook auth.
            client(server, timeout=2).acme_txt_set(hostname=f"_acme-challenge.{domain}", value="v")
            return {"issued": True}

    monkeypatch.setattr(helper_server, "AcmeDnsHelperOps", Acme)
    monkeypatch.setattr(helper_server, "SslHelperOps", HookCallingSsl)

    result = client(server, timeout=10).ssl_issue(domain="a.example.com", provider="acme_delegation")
    assert result == {"issued": True}
    assert records == [("_acme-challenge.a.example.com", "v")]


def test_a_client_that_never_sends_a_request_does_not_block_others(server, monkeypatch):
    monkeypatch.setattr(helper_server, "REQUEST_READ_TIMEOUT", 0.5)
    idle = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    idle.connect(server)
    try:
        assert client(server).status()["dnsmasq"] == "active"
    finally:
        idle.close()


def test_idle_client_is_disconnected_after_the_read_timeout(server, monkeypatch):
    monkeypatch.setattr(helper_server, "REQUEST_READ_TIMEOUT", 0.3)
    idle = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    idle.settimeout(3)
    idle.connect(server)
    try:
        assert idle.recv(1) == b""
    finally:
        idle.close()


def test_commands_on_the_same_state_are_still_serialised(server, monkeypatch):
    active, peak = [0], [0]
    guard = threading.Lock()

    class Firewall:
        def apply(self, policy):
            with guard:
                active[0] += 1
                peak[0] = max(peak[0], active[0])
            time.sleep(0.3)
            with guard:
                active[0] -= 1
            return {"applied": True}

    monkeypatch.setattr(helper_server, "FirewallHelperOps", Firewall)
    threads = [
        threading.Thread(target=lambda: client(server, timeout=5).firewall_apply({"revision": 1}), daemon=True)
        for _ in range(3)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(5)
    assert peak[0] == 1


def test_ssl_nginx_changes_share_the_config_lock_but_certbot_does_not():
    locks = helper_server._COMMAND_LOCKS
    assert locks["ssl_apply"] is locks["apply"] is locks["validate"] is locks["rollback"] is locks["ssl_delete"]
    assert locks["ssl_issue"] is not locks["acme_txt_set"]
    assert "status" not in locks and "firewall_status" not in locks and "ssl_status" not in locks
