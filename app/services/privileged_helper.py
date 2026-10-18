from __future__ import annotations

import json
import socket
from typing import Callable


class PrivilegedHelperError(RuntimeError):
    pass


def _connect_unix(path: str, timeout: float):
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect(path)
    except Exception:
        sock.close()
        raise
    return sock


class PrivilegedHelper:
    SOCKET_PATH = "/run/dns-manager/helper.sock"
    ALLOWED = {"validate", "apply", "rollback", "status", "ssl_status", "ssl_issue", "ssl_renew", "ssl_test_renewal", "ssl_apply", "ssl_delete", "ssl_manual_continue", "ssl_manual_status", "acme_dns_status", "acme_zone_check", "acme_txt_set", "acme_txt_delete", "firewall_status", "firewall_preview", "firewall_apply", "firewall_confirm", "firewall_rollback"}
    MAX_RESPONSE_BYTES = 65536
    CERTBOT_TIMEOUT = 330.0

    def __init__(
        self,
        connector: Callable = _connect_unix,
        socket_path: str = SOCKET_PATH,
        timeout: float = 10.0,
    ):
        self.connector = connector
        self.socket_path = socket_path
        self.timeout = timeout

    def _invoke(self, command: str, *, timeout: float | None = None, **payload) -> dict:
        if command not in self.ALLOWED:
            raise ValueError("unsupported privileged helper command")
        try:
            sock = self.connector(self.socket_path, self.timeout if timeout is None else timeout)
            try:
                message = command if command in {"validate", "apply", "rollback", "status"} and not payload else json.dumps({"command": command, **payload}, separators=(",", ":"))
                sock.sendall((message + "\n").encode("utf-8"))
                chunks = bytearray()
                while b"\n" not in chunks:
                    part = sock.recv(4096)
                    if not part:
                        break
                    chunks.extend(part)
                    if len(chunks) > self.MAX_RESPONSE_BYTES:
                        raise PrivilegedHelperError("helper response too large")
            finally:
                sock.close()
        except PrivilegedHelperError:
            raise
        except OSError as exc:
            raise PrivilegedHelperError(f"privileged helper unavailable: {exc}") from exc

        raw = bytes(chunks).split(b"\n", 1)[0].decode("utf-8", errors="strict").strip()
        if not raw:
            raise PrivilegedHelperError("empty helper response")
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise PrivilegedHelperError("invalid helper response") from exc
        if payload.get("ok") is not True:
            raise PrivilegedHelperError(str(payload.get("error") or "helper failed"))
        return {key: value for key, value in payload.items() if key != "ok"}

    def validate(self) -> dict:
        return self._invoke("validate")

    def apply(self) -> dict:
        return self._invoke("apply")

    def rollback(self) -> dict:
        return self._invoke("rollback")

    def status(self) -> dict:
        return self._invoke("status")

    def ssl_status(self, domain: str) -> dict: return self._invoke("ssl_status", domain=domain)
    def ssl_apply(self, domain: str, redirect_http: bool=True, upstream: dict | None=None) -> dict:
        payload={"domain":domain,"redirect_http":redirect_http}
        if upstream is not None:
            payload["upstream"]=upstream
        return self._invoke("ssl_apply", **payload)
    def ssl_delete(self, domain: str) -> dict: return self._invoke("ssl_delete", domain=domain)
    def ssl_issue(self, **payload) -> dict: return self._invoke("ssl_issue", timeout=self.CERTBOT_TIMEOUT, **payload)
    def ssl_renew(self, **payload) -> dict: return self._invoke("ssl_renew", timeout=self.CERTBOT_TIMEOUT, **payload)
    def ssl_test_renewal(self, **payload) -> dict: return self._invoke("ssl_test_renewal", timeout=self.CERTBOT_TIMEOUT, **payload)
    def ssl_manual_continue(self, domain: str) -> dict: return self._invoke("ssl_manual_continue", domain=domain)
    def ssl_manual_status(self, domain: str) -> dict: return self._invoke("ssl_manual_status", domain=domain)
    def acme_dns_status(self) -> dict: return self._invoke("acme_dns_status")
    def acme_zone_check(self) -> dict: return self._invoke("acme_zone_check")
    def acme_txt_set(self, hostname: str, value: str) -> dict: return self._invoke("acme_txt_set", hostname=hostname, value=value)
    def acme_txt_delete(self, hostname: str, value: str) -> dict: return self._invoke("acme_txt_delete", hostname=hostname, value=value)

    def firewall_status(self) -> dict: return self._invoke("firewall_status")
    def firewall_preview(self, policy: dict) -> dict: return self._invoke("firewall_preview", policy=policy)
    def firewall_apply(self, policy: dict) -> dict: return self._invoke("firewall_apply", policy=policy)
    def firewall_confirm(self, token: str) -> dict: return self._invoke("firewall_confirm", token=token)
    def firewall_rollback(self, token: str) -> dict: return self._invoke("firewall_rollback", token=token)
