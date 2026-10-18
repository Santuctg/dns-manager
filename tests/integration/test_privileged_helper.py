import json
from pathlib import Path

import pytest

from app.services.privileged_helper import PrivilegedHelper, PrivilegedHelperError
from privileged.helper_lib import HelperOps, HelperPaths, dispatch


class Result:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class FakeRunner:
    def __init__(self, responses=None):
        self.calls = []
        self.responses = list(responses or [])

    def __call__(self, argv, **kwargs):
        self.calls.append(list(argv))
        if self.responses:
            return self.responses.pop(0)
        return Result()


def make_paths(tmp_path: Path) -> HelperPaths:
    generated = tmp_path / "generated"
    live_dns_dir = tmp_path / "etc" / "dnsmasq.d"
    live_nginx_dir = tmp_path / "etc" / "nginx" / "conf.d"
    known_good = tmp_path / "known-good"
    for directory in (generated, live_dns_dir, live_nginx_dir, known_good):
        directory.mkdir(parents=True, exist_ok=True)
    return HelperPaths(
        staged_dnsmasq=generated / "dnsmasq.conf",
        staged_nginx=generated / "nginx.conf",
        staged_nginx_main=generated / "nginx-test.conf",
        live_dnsmasq=live_dns_dir / "dns-manager.conf",
        live_nginx=live_nginx_dir / "dns-manager.conf",
        known_good_dnsmasq=known_good / "dnsmasq.conf",
        known_good_nginx=known_good / "nginx.conf",
    )


def test_dispatch_rejects_unknown_command_and_extra_arguments(tmp_path):
    ops = HelperOps(paths=make_paths(tmp_path), runner=FakeRunner())

    assert dispatch(["shell"], ops) == 2
    assert dispatch(["validate", "/tmp/evil"], ops) == 2


def test_validate_uses_only_fixed_candidate_paths(tmp_path):
    paths = make_paths(tmp_path)
    paths.staged_dnsmasq.write_text("address=/panel.example.com/192.168.8.10\n")
    paths.staged_nginx.write_text("server { listen 80; }\n")
    paths.staged_nginx_main.write_text("events {} http { include nginx.conf; }\n")
    runner = FakeRunner()
    ops = HelperOps(paths=paths, runner=runner)

    assert dispatch(["validate"], ops) == 0
    assert runner.calls == [
        ["/usr/sbin/dnsmasq", "--test", f"--conf-file={paths.staged_dnsmasq}"],
        [
            "/usr/sbin/nginx",
            "-t",
            "-c",
            str(paths.staged_nginx_main),
            "-g",
            f"pid {paths.staged_nginx_main.parent / 'nginx-test.pid'};",
        ],
    ]


def test_apply_snapshots_previous_live_files_restarts_dnsmasq_and_reloads_nginx(tmp_path):
    paths = make_paths(tmp_path)
    paths.staged_dnsmasq.write_text("new dns\n")
    paths.staged_nginx.write_text("new nginx\n")
    paths.live_dnsmasq.write_text("old dns\n")
    paths.live_nginx.write_text("old nginx\n")
    runner = FakeRunner()
    ops = HelperOps(paths=paths, runner=runner)

    assert dispatch(["apply"], ops) == 0
    assert paths.known_good_dnsmasq.read_text() == "old dns\n"
    assert paths.known_good_nginx.read_text() == "old nginx\n"
    assert paths.live_dnsmasq.read_text() == "new dns\n"
    assert paths.live_nginx.read_text() == "new nginx\n"
    assert not paths.staged_dnsmasq.exists()
    assert not paths.staged_nginx.exists()
    assert not paths.staged_nginx_main.exists()
    assert runner.calls == [
        ["/usr/bin/systemctl", "restart", "dnsmasq"],
        ["/usr/bin/systemctl", "reload", "nginx"],
    ]


def test_rollback_restores_known_good_restarts_dnsmasq_and_reloads_nginx(tmp_path):
    paths = make_paths(tmp_path)
    paths.live_dnsmasq.write_text("broken dns\n")
    paths.live_nginx.write_text("broken nginx\n")
    paths.known_good_dnsmasq.write_text("good dns\n")
    paths.known_good_nginx.write_text("good nginx\n")
    paths.staged_dnsmasq.write_text("stale dns\n")
    paths.staged_nginx.write_text("stale nginx\n")
    paths.staged_nginx_main.write_text("stale main\n")
    runner = FakeRunner()
    ops = HelperOps(paths=paths, runner=runner)

    assert dispatch(["rollback"], ops) == 0
    assert paths.live_dnsmasq.read_text() == "good dns\n"
    assert paths.live_nginx.read_text() == "good nginx\n"
    assert not paths.staged_dnsmasq.exists()
    assert not paths.staged_nginx.exists()
    assert not paths.staged_nginx_main.exists()
    assert runner.calls == [
        ["/usr/bin/systemctl", "restart", "dnsmasq"],
        ["/usr/bin/systemctl", "reload", "nginx"],
    ]


def test_status_returns_machine_readable_json(tmp_path, capsys):
    paths = make_paths(tmp_path)
    paths.staged_dnsmasq.write_text("candidate")
    paths.staged_nginx.write_text("candidate")
    runner = FakeRunner(
        [Result(stdout="active\n"), Result(stdout="inactive\n")]
    )
    ops = HelperOps(paths=paths, runner=runner)

    assert dispatch(["status"], ops) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload == {
        "dnsmasq": "active",
        "nginx": "inactive",
        "staged_dnsmasq": True,
        "staged_nginx": True,
    }


def test_python_wrapper_uses_fixed_unix_socket_protocol():
    import socket

    client, server = socket.socketpair()
    helper = PrivilegedHelper(connector=lambda path, timeout: client)
    server.sendall(b'{"ok":true,"dnsmasq":"active"}\n')

    payload = helper.status()
    request = server.recv(128)
    server.close()

    assert payload["dnsmasq"] == "active"
    assert request == b"status\n"


def test_python_wrapper_raises_on_helper_failure():
    import socket

    client, server = socket.socketpair()
    helper = PrivilegedHelper(connector=lambda path, timeout: client)
    server.sendall(b'{"ok":false,"error":"nginx validation failed"}\n')

    with pytest.raises(PrivilegedHelperError, match="nginx validation failed"):
        helper.validate()
    server.close()


def test_installed_helper_bootstraps_project_import_path(tmp_path):
    import shutil
    import subprocess

    installed = tmp_path / "dns-manager-helper"
    script = Path("privileged/dns-manager-helper").read_text()
    script = script.replace(
        "/opt/dns-manager/dns-manager",
        str(Path.cwd()),
    )
    installed.write_text(script)
    installed.chmod(0o755)
    result = subprocess.run(
        [str(installed), "shell"],
        cwd=tmp_path,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 2
    assert "ModuleNotFoundError" not in result.stderr


def test_legacy_sudoers_policy_is_not_shipped():
    assert not Path("privileged/dns-manager.sudoers").exists()


def test_apply_creates_empty_known_good_when_managed_live_file_did_not_exist(tmp_path):
    from privileged.helper_lib import HelperOps, HelperPaths

    staged_dns = tmp_path / "staged" / "dns.conf"
    staged_nginx = tmp_path / "staged" / "nginx.conf"
    staged_main = tmp_path / "staged" / "nginx-test.conf"
    live_dns = tmp_path / "live" / "dns.conf"
    live_nginx = tmp_path / "live" / "nginx.conf"
    good_dns = tmp_path / "good" / "dns.conf"
    good_nginx = tmp_path / "good" / "nginx.conf"
    for p, content in ((staged_dns, "new-dns"), (staged_nginx, "new-nginx"), (staged_main, "events{}http{}")):
        p.parent.mkdir(parents=True, exist_ok=True); p.write_text(content)

    paths = HelperPaths(staged_dns, staged_nginx, staged_main, live_dns, live_nginx, good_dns, good_nginx)
    calls = []
    class Result:
        returncode=0; stdout=""; stderr=""
    ops = HelperOps(paths=paths, runner=lambda argv, **kwargs: calls.append(argv) or Result())

    ops.apply()
    assert good_dns.read_text() == ""
    assert good_nginx.read_text() == ""
    ops.rollback()
    assert live_dns.read_text() == ""
    assert live_nginx.read_text() == ""


def test_helper_server_accepts_only_fixed_single_word_commands(tmp_path):
    from privileged.helper_server import handle_request

    class Ops:
        def status(self):
            return {"dnsmasq": "active"}

    assert handle_request("status", Ops()) == {"ok": True, "dnsmasq": "active"}
    assert handle_request("status extra", Ops())["ok"] is False
    assert handle_request("shell", Ops())["ok"] is False


def test_unix_socket_client_server_round_trip(tmp_path):
    import socket
    import threading

    from privileged.helper_server import serve_once

    socket_path = tmp_path / "helper.sock"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(socket_path))
    listener.listen(1)

    class Ops:
        def status(self):
            return {"dnsmasq": "active", "nginx": "active"}

    thread = threading.Thread(
        target=serve_once,
        args=(listener,),
        kwargs={"ops_factory": Ops},
        daemon=True,
    )
    thread.start()
    helper = PrivilegedHelper(socket_path=str(socket_path))

    assert helper.status() == {"dnsmasq": "active", "nginx": "active"}
    thread.join(timeout=2)
    listener.close()
    assert not thread.is_alive()


def test_ssl_certbot_operations_use_long_socket_timeout_while_status_stays_short():
    import socket

    timeouts = []
    pairs = []

    def connector(path, timeout):
        timeouts.append(timeout)
        client, server = socket.socketpair()
        pairs.append(server)
        server.sendall(b'{"ok":true,"tested":true}\n')
        return client

    helper = PrivilegedHelper(connector=connector, timeout=10.0)
    assert helper.ssl_test_renewal(domain="dns.example.com", provider="cloudflare", token="secret")["tested"] is True
    pairs.pop().close()

    client, server = socket.socketpair()
    def status_connector(path, timeout):
        timeouts.append(timeout)
        server.sendall(b'{"ok":true,"status":"ISSUED"}\n')
        return client
    helper = PrivilegedHelper(connector=status_connector, timeout=10.0)
    assert helper.ssl_status("dns.example.com")["status"] == "ISSUED"
    server.close()

    assert timeouts == [330.0, 10.0]


def test_helper_server_ignores_broken_pipe_when_client_disconnects():
    from privileged.helper_server import serve_once

    class BrokenConn:
        def __init__(self):
            self.read = False
        def __enter__(self): return self
        def __exit__(self, *args): return False
        def recv(self, size):
            if self.read:
                return b""
            self.read = True
            return b"status\n"
        def sendall(self, payload):
            raise BrokenPipeError(32, "Broken pipe")

    class Listener:
        def accept(self): return BrokenConn(), None

    class Ops:
        def status(self): return {"dnsmasq":"active"}

    serve_once(Listener(), Ops)


def test_acme_dns_client_uses_fixed_helper_commands():
    import socket

    client, server = socket.socketpair()
    helper = PrivilegedHelper(connector=lambda path, timeout: client)
    server.sendall(b'{"ok":true,"service":"active"}\n')
    assert helper.acme_dns_status()["service"] == "active"
    request = json.loads(server.recv(512).decode())
    server.close()
    assert request == {"command": "acme_dns_status"}


def test_helper_server_accepts_only_acme_fixed_fields():
    from privileged.helper_server import handle_request

    class AcmeOps:
        def status(self): return {"service": "active"}
        def txt_set(self, hostname, value): return {"updated": True}

    assert handle_request('{"command":"acme_dns_status"}', acme_ops=AcmeOps()) == {"ok": True, "service": "active"}
    assert handle_request('{"command":"acme_txt_set","hostname":"dns-a1b2c3d4e5f6.acme-dns.connect3.net.bd","value":"x"}', acme_ops=AcmeOps())["ok"] is True
    assert handle_request('{"command":"acme_txt_set","hostname":"x","value":"y","record_type":"A"}', acme_ops=AcmeOps())["ok"] is False
