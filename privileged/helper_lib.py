from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Sequence


@dataclass(frozen=True)
class HelperPaths:
    staged_dnsmasq: Path
    staged_nginx: Path
    staged_nginx_main: Path
    live_dnsmasq: Path
    live_nginx: Path
    known_good_dnsmasq: Path
    known_good_nginx: Path


def production_paths() -> HelperPaths:
    return HelperPaths(
        staged_dnsmasq=Path("/var/lib/dns-manager/generated/dnsmasq.conf"),
        staged_nginx=Path("/var/lib/dns-manager/generated/nginx.conf"),
        staged_nginx_main=Path("/var/lib/dns-manager/generated/nginx-test.conf"),
        live_dnsmasq=Path("/etc/dnsmasq.d/dns-manager.conf"),
        live_nginx=Path("/etc/nginx/conf.d/dns-manager.conf"),
        known_good_dnsmasq=Path("/var/lib/dns-manager/known-good/dnsmasq.conf"),
        known_good_nginx=Path("/var/lib/dns-manager/known-good/nginx.conf"),
    )


def _default_runner(argv, **kwargs):
    return subprocess.run(argv, text=True, capture_output=True, **kwargs)


def _atomic_copy(source: Path, destination: Path) -> None:
    if not source.is_file():
        raise FileNotFoundError(str(source))
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{destination.name}.", dir=destination.parent)
    try:
        with os.fdopen(fd, "wb") as tmp_fp, source.open("rb") as src_fp:
            shutil.copyfileobj(src_fp, tmp_fp)
            tmp_fp.flush()
            os.fsync(tmp_fp.fileno())
        os.chmod(tmp_name, 0o644)
        os.replace(tmp_name, destination)
    except Exception:
        try:
            os.unlink(tmp_name)
        except FileNotFoundError:
            pass
        raise


class HelperOps:
    def __init__(self, paths: HelperPaths | None = None, runner: Callable = _default_runner):
        self.paths = paths or production_paths()
        self.runner = runner

    def _run(self, argv: Sequence[str]):
        result = self.runner(list(argv), check=False)
        if result.returncode != 0:
            message = (result.stderr or result.stdout or "command failed").strip()
            raise RuntimeError(message)
        return result

    def validate(self) -> dict:
        for path in (
            self.paths.staged_dnsmasq,
            self.paths.staged_nginx,
            self.paths.staged_nginx_main,
        ):
            if not path.is_file():
                raise FileNotFoundError(str(path))
        self._run([
            "/usr/sbin/dnsmasq",
            "--test",
            f"--conf-file={self.paths.staged_dnsmasq}",
        ])
        self._run([
            "/usr/sbin/nginx",
            "-t",
            "-c",
            str(self.paths.staged_nginx_main),
            "-g",
            f"pid {self.paths.staged_nginx_main.parent / 'nginx-test.pid'};",
        ])
        return {"validated": True}


    def _cleanup_staged(self) -> None:
        for path in (
            self.paths.staged_dnsmasq,
            self.paths.staged_nginx,
            self.paths.staged_nginx_main,
            self.paths.staged_nginx_main.parent / "nginx-test.pid",
            self.paths.staged_nginx_main.parent / "nginx-test-error.log",
        ):
            try:
                path.unlink()
            except FileNotFoundError:
                pass

    def apply(self) -> dict:
        for source in (self.paths.staged_dnsmasq, self.paths.staged_nginx):
            if not source.is_file():
                raise FileNotFoundError(str(source))
        if self.paths.live_dnsmasq.is_file():
            _atomic_copy(self.paths.live_dnsmasq, self.paths.known_good_dnsmasq)
        else:
            self.paths.known_good_dnsmasq.parent.mkdir(parents=True, exist_ok=True)
            self.paths.known_good_dnsmasq.write_text("")
            os.chmod(self.paths.known_good_dnsmasq, 0o644)
        if self.paths.live_nginx.is_file():
            _atomic_copy(self.paths.live_nginx, self.paths.known_good_nginx)
        else:
            self.paths.known_good_nginx.parent.mkdir(parents=True, exist_ok=True)
            self.paths.known_good_nginx.write_text("")
            os.chmod(self.paths.known_good_nginx, 0o644)
        _atomic_copy(self.paths.staged_dnsmasq, self.paths.live_dnsmasq)
        _atomic_copy(self.paths.staged_nginx, self.paths.live_nginx)
        self._run(["/usr/bin/systemctl", "restart", "dnsmasq"])
        self._run(["/usr/bin/systemctl", "reload", "nginx"])
        self._cleanup_staged()
        return {"applied": True}

    def rollback(self) -> dict:
        if not self.paths.known_good_dnsmasq.is_file():
            raise FileNotFoundError(str(self.paths.known_good_dnsmasq))
        if not self.paths.known_good_nginx.is_file():
            raise FileNotFoundError(str(self.paths.known_good_nginx))
        _atomic_copy(self.paths.known_good_dnsmasq, self.paths.live_dnsmasq)
        _atomic_copy(self.paths.known_good_nginx, self.paths.live_nginx)
        self._run(["/usr/bin/systemctl", "restart", "dnsmasq"])
        self._run(["/usr/bin/systemctl", "reload", "nginx"])
        self._cleanup_staged()
        return {"rolled_back": True}

    def status(self) -> dict:
        dns = self.runner(["/usr/bin/systemctl", "is-active", "dnsmasq"], check=False)
        nginx = self.runner(["/usr/bin/systemctl", "is-active", "nginx"], check=False)
        return {
            "dnsmasq": (dns.stdout or "unknown").strip() or "unknown",
            "nginx": (nginx.stdout or "unknown").strip() or "unknown",
            "staged_dnsmasq": self.paths.staged_dnsmasq.is_file(),
            "staged_nginx": self.paths.staged_nginx.is_file(),
        }


def dispatch(argv: Sequence[str], ops: HelperOps | None = None) -> int:
    if len(argv) != 1 or argv[0] not in {"validate", "apply", "rollback", "status"}:
        return 2
    ops = ops or HelperOps()
    command = argv[0]
    try:
        payload = getattr(ops, command)()
    except Exception as exc:
        print(json.dumps({"ok": False, "error": str(exc)}))
        return 1
    if command == "status":
        print(json.dumps(payload, sort_keys=True))
    else:
        print(json.dumps({"ok": True, **payload}, sort_keys=True))
    return 0
