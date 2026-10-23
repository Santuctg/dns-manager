from __future__ import annotations

import ipaddress
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Sequence

from app.schemas.mapping import normalize_domain, validate_upstream_host

# Root-only state lives outside /var/lib/dns-manager: that tree is owned by the
# unprivileged service user, who could otherwise rename or replace anything in it.
PRIVATE_ROOT = Path("/var/lib/dns-manager-helper")
MAX_STAGED_BYTES = 4 * 1024 * 1024


@dataclass(frozen=True)
class HelperPaths:
    staged_dnsmasq: Path
    staged_nginx: Path
    live_dnsmasq: Path
    live_nginx: Path
    private_dir: Path

    @property
    def candidate_dir(self) -> Path:
        return self.private_dir / "staging"

    @property
    def candidate_dnsmasq(self) -> Path:
        return self.candidate_dir / "dnsmasq.conf"

    @property
    def candidate_nginx(self) -> Path:
        return self.candidate_dir / "nginx.conf"

    @property
    def candidate_nginx_main(self) -> Path:
        return self.candidate_dir / "nginx-test.conf"

    @property
    def known_good_dnsmasq(self) -> Path:
        return self.private_dir / "known-good" / "dnsmasq.conf"

    @property
    def known_good_nginx(self) -> Path:
        return self.private_dir / "known-good" / "nginx.conf"


def production_paths() -> HelperPaths:
    return HelperPaths(
        staged_dnsmasq=Path("/var/lib/dns-manager/generated/dnsmasq.conf"),
        staged_nginx=Path("/var/lib/dns-manager/generated/nginx.conf"),
        live_dnsmasq=Path("/etc/dnsmasq.d/dns-manager.conf"),
        live_nginx=Path("/etc/nginx/conf.d/dns-manager.conf"),
        private_dir=PRIVATE_ROOT / "config",
    )


def ensure_private_dir(path: Path) -> Path:
    """Create ``path`` if needed and refuse it unless only this process's user controls it."""
    path = Path(path)
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = os.lstat(path)
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise RuntimeError(f"helper state path is not a directory: {path}")
    if info.st_uid != os.geteuid() or info.st_mode & 0o022:
        raise RuntimeError(f"helper state directory is not private: {path}")
    return path


def read_untrusted_file(path: Path, limit: int = MAX_STAGED_BYTES) -> str:
    """Read a file the unprivileged service wrote, without following a final symlink."""
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(path, flags)
    except FileNotFoundError:
        raise
    except OSError as exc:  # ELOOP for a symlink, ENXIO for a FIFO, ...
        raise RuntimeError(f"refusing to read staged file: {path.name}") from exc
    with os.fdopen(fd, "rb") as fp:
        info = os.fstat(fp.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise RuntimeError(f"refusing to read staged file: {path.name}")
        data = fp.read(limit + 1)
    if len(data) > limit:
        raise RuntimeError(f"refusing to read staged file: {path.name}")
    try:
        return data.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise RuntimeError(f"staged file is not UTF-8: {path.name}") from exc


_COMMENT_RE = re.compile(r"#[^\x00-\x08\x0a-\x1f\x7f]*")
_DNSMASQ_ADDRESS_RE = re.compile(r"address=/([^/\s]+)/([0-9A-Fa-f.:]+)")


def _reject(kind: str, number: int) -> None:
    # Report only the line number: the file may be a symlink-swapped secret.
    raise ValueError(f"staged {kind} config line {number} is not allowed")


def validate_dnsmasq_text(text: str) -> None:
    """Accept only what render_dnsmasq_config can produce: comments and address= lines."""
    for number, raw in enumerate(text.split("\n"), start=1):
        line = raw.strip()
        if not line or _COMMENT_RE.fullmatch(line):
            continue
        match = _DNSMASQ_ADDRESS_RE.fullmatch(line)
        if not match:
            _reject("dnsmasq", number)
        try:
            if normalize_domain(match.group(1)) != match.group(1):
                _reject("dnsmasq", number)
            ipaddress.ip_address(match.group(2))
        except ValueError:
            _reject("dnsmasq", number)


_PROXY_HEADERS = {
    "Host $host",
    "X-Real-IP $remote_addr",
    "X-Forwarded-For $proxy_add_x_forwarded_for",
    "X-Forwarded-Proto $scheme",
    "Upgrade $http_upgrade",
    'Connection "upgrade"',
}
_SERVER_DIRECTIVES = (
    re.compile(r"listen 80;"),
    re.compile(r"server_name ([^;\s]+);"),
)
_LOCATION_DIRECTIVES = (
    re.compile(r"proxy_http_version 1\.1;"),
    re.compile(r"proxy_(?:connect|send|read)_timeout [0-9]{1,5}s;"),
)
_PROXY_PASS_RE = re.compile(r"proxy_pass (https?)://(\[[0-9A-Fa-f:.]+\]|[^\s:/;\[\]]+):([0-9]{1,5});")
_PROXY_HEADER_RE = re.compile(r"proxy_set_header (.+);")


def _valid_proxy_pass(match: re.Match) -> bool:
    host, port = match.group(2), int(match.group(3))
    if not 1 <= port <= 65535:
        return False
    try:
        if host.startswith("["):
            return ipaddress.ip_address(host[1:-1]).version == 6
        validate_upstream_host(host)
    except ValueError:
        return False
    return True


def validate_nginx_text(text: str) -> None:
    """Accept only the server blocks render_nginx_config produces.

    The file is included into the http context of the live nginx, so anything
    outside this grammar (include, root, alias, lua, ...) is refused.
    """
    depth = 0
    for number, raw in enumerate(text.split("\n"), start=1):
        line = raw.strip()
        if not line or _COMMENT_RE.fullmatch(line):
            continue
        if line == "}":
            if depth == 0:
                _reject("nginx", number)
            depth -= 1
            continue
        if depth == 0:
            if line != "server {":
                _reject("nginx", number)
            depth = 1
            continue
        if depth == 1:
            if line == "location / {":
                depth = 2
                continue
            match = next((m for m in (p.fullmatch(line) for p in _SERVER_DIRECTIVES) if m), None)
            if match is None:
                _reject("nginx", number)
            if match.groups():
                try:
                    if normalize_domain(match.group(1)) != match.group(1):
                        _reject("nginx", number)
                except ValueError:
                    _reject("nginx", number)
            continue
        if any(p.fullmatch(line) for p in _LOCATION_DIRECTIVES):
            continue
        proxy_pass = _PROXY_PASS_RE.fullmatch(line)
        if proxy_pass and _valid_proxy_pass(proxy_pass):
            continue
        header = _PROXY_HEADER_RE.fullmatch(line)
        if header and header.group(1) in _PROXY_HEADERS:
            continue
        _reject("nginx", number)
    if depth != 0:
        raise ValueError("staged nginx config has unbalanced braces")


def nginx_test_config(candidate_nginx: Path) -> str:
    work = candidate_nginx.parent
    return (
        "worker_processes 1;\n"
        f"error_log {work / 'nginx-test-error.log'} notice;\n"
        "events { worker_connections 64; }\n"
        "http {\n"
        "    access_log off;\n"
        f"    client_body_temp_path {work / 'nginx-client-body'};\n"
        f"    proxy_temp_path {work / 'nginx-proxy'};\n"
        f"    fastcgi_temp_path {work / 'nginx-fastcgi'};\n"
        f"    uwsgi_temp_path {work / 'nginx-uwsgi'};\n"
        f"    scgi_temp_path {work / 'nginx-scgi'};\n"
        f"    include {candidate_nginx};\n"
        "}\n"
    )


def _default_runner(argv, **kwargs):
    return subprocess.run(argv, text=True, capture_output=True, **kwargs)


def _atomic_write(destination: Path, content: str, mode: int) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{destination.name}.", dir=destination.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fp:
            fp.write(content)
            fp.flush()
            os.fsync(fp.fileno())
        os.chmod(tmp_name, mode)
        os.replace(tmp_name, destination)
    except Exception:
        try:
            os.unlink(tmp_name)
        except FileNotFoundError:
            pass
        raise


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

    def _ingest_candidates(self) -> None:
        """Copy the service's staged files into root-only storage after checking their content."""
        dnsmasq = read_untrusted_file(self.paths.staged_dnsmasq)
        nginx = read_untrusted_file(self.paths.staged_nginx)
        validate_dnsmasq_text(dnsmasq)
        validate_nginx_text(nginx)
        ensure_private_dir(self.paths.private_dir)
        ensure_private_dir(self.paths.candidate_dir)
        _atomic_write(self.paths.candidate_dnsmasq, dnsmasq, 0o600)
        _atomic_write(self.paths.candidate_nginx, nginx, 0o600)
        _atomic_write(self.paths.candidate_nginx_main, nginx_test_config(self.paths.candidate_nginx), 0o600)

    def validate(self) -> dict:
        self._ingest_candidates()
        self._run([
            "/usr/sbin/dnsmasq",
            "--test",
            f"--conf-file={self.paths.candidate_dnsmasq}",
        ])
        self._run([
            "/usr/sbin/nginx",
            "-t",
            "-c",
            str(self.paths.candidate_nginx_main),
            "-g",
            f"pid {self.paths.candidate_dir / 'nginx-test.pid'};",
        ])
        return {"validated": True}

    def _cleanup_staged(self) -> None:
        for path in (
            self.paths.staged_dnsmasq,
            self.paths.staged_nginx,
            self.paths.staged_nginx.parent / "nginx-test.conf",
            self.paths.candidate_dnsmasq,
            self.paths.candidate_nginx,
            self.paths.candidate_nginx_main,
            self.paths.candidate_dir / "nginx-test.pid",
            self.paths.candidate_dir / "nginx-test-error.log",
        ):
            try:
                path.unlink()
            except FileNotFoundError:
                pass

    def _snapshot_live(self, live: Path, known_good: Path) -> None:
        if live.is_file():
            _atomic_copy(live, known_good)
        else:
            _atomic_write(known_good, "", 0o644)

    def apply(self) -> dict:
        # Re-read and re-check the staged files here so that what is installed is
        # exactly what was validated, regardless of what changed since validate().
        self.validate()
        ensure_private_dir(self.paths.known_good_dnsmasq.parent)
        self._snapshot_live(self.paths.live_dnsmasq, self.paths.known_good_dnsmasq)
        self._snapshot_live(self.paths.live_nginx, self.paths.known_good_nginx)
        _atomic_copy(self.paths.candidate_dnsmasq, self.paths.live_dnsmasq)
        _atomic_copy(self.paths.candidate_nginx, self.paths.live_nginx)
        self._run(["/usr/bin/systemctl", "restart", "dnsmasq"])
        self._run(["/usr/bin/systemctl", "reload", "nginx"])
        self._cleanup_staged()
        return {"applied": True}

    def rollback(self) -> dict:
        ensure_private_dir(self.paths.known_good_dnsmasq.parent)
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
