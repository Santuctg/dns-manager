from __future__ import annotations

import fcntl
import os
import tempfile
from contextlib import contextmanager
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.mapping import Mapping
from app.models.revision import ConfigRevision
from app.models.ssl import SslCertificate
from app.services.dns_service import render_dnsmasq_config
from app.services.nginx_service import render_nginx_config
from app.services.privileged_helper import PrivilegedHelper
from app.services.revision_service import create_revision, mark_revision_status

DEFAULT_GENERATED_DIR = Path("/var/lib/dns-manager/generated")
DEFAULT_LOCK_PATH = Path("/run/dns-manager/apply.lock")


class ConfigLockedError(RuntimeError):
    pass


def _mappings(db: Session) -> list[Mapping]:
    return list(db.scalars(select(Mapping).order_by(Mapping.domain)).all())


def _ssl_redirect_domains(db: Session) -> set[str]:
    rows = db.scalars(
        select(SslCertificate.domain).where(
            SslCertificate.redirect_http.is_(True),
            SslCertificate.status == "ISSUED",
        )
    ).all()
    return {str(domain).strip().lower().rstrip(".") for domain in rows}


def preview_config(db: Session, *, internal_proxy_ip: str) -> dict[str, str]:
    mappings = _mappings(db)
    return {
        "dnsmasq_config": render_dnsmasq_config(mappings, internal_proxy_ip),
        "nginx_config": render_nginx_config(
            mappings, skip_http_domains=_ssl_redirect_domains(db)
        ),
    }


def _atomic_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fp:
            fp.write(content)
            fp.flush()
            os.fsync(fp.fileno())
        os.chmod(tmp_name, 0o640)
        os.replace(tmp_name, path)
    except Exception:
        try:
            os.unlink(tmp_name)
        except FileNotFoundError:
            pass
        raise


def _nginx_test_config(staged_nginx: Path) -> str:
    test_error_log = staged_nginx.parent / "nginx-test-error.log"
    generated_dir = staged_nginx.parent
    return (
        "worker_processes 1;\n"
        f"error_log {test_error_log} notice;\n"
        "events { worker_connections 64; }\n"
        "http {\n"
        "    access_log off;\n"
        f"    client_body_temp_path {generated_dir / 'nginx-client-body'};\n"
        f"    proxy_temp_path {generated_dir / 'nginx-proxy'};\n"
        f"    fastcgi_temp_path {generated_dir / 'nginx-fastcgi'};\n"
        f"    uwsgi_temp_path {generated_dir / 'nginx-uwsgi'};\n"
        f"    scgi_temp_path {generated_dir / 'nginx-scgi'};\n"
        f"    include {staged_nginx};\n"
        "}\n"
    )


def _stage_revision(revision: ConfigRevision, generated_dir: Path) -> None:
    generated_dir.mkdir(parents=True, exist_ok=True)
    dns_path = generated_dir / "dnsmasq.conf"
    nginx_path = generated_dir / "nginx.conf"
    nginx_main = generated_dir / "nginx-test.conf"
    _atomic_write(dns_path, revision.dnsmasq_config)
    _atomic_write(nginx_path, revision.nginx_config)
    _atomic_write(nginx_main, _nginx_test_config(nginx_path))


@contextmanager
def _apply_lock(lock_path: Path):
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("a+") as fp:
        try:
            fcntl.flock(fp.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise ConfigLockedError("CONFIG_LOCKED") from exc
        try:
            yield
        finally:
            fcntl.flock(fp.fileno(), fcntl.LOCK_UN)


def _health_ok(helper: PrivilegedHelper) -> bool:
    status = helper.status()
    return status.get("dnsmasq") == "active" and status.get("nginx") == "active"


def validate_pending_config(
    db: Session,
    *,
    internal_proxy_ip: str,
    created_by: int | None,
    helper: PrivilegedHelper | None = None,
    generated_dir: Path = DEFAULT_GENERATED_DIR,
) -> ConfigRevision:
    helper = helper or PrivilegedHelper()
    preview = preview_config(db, internal_proxy_ip=internal_proxy_ip)
    revision = create_revision(
        db,
        preview["dnsmasq_config"],
        preview["nginx_config"],
        created_by=created_by,
    )
    _stage_revision(revision, generated_dir)
    try:
        helper.validate()
    except Exception:
        mark_revision_status(db, revision, "failed")
        raise
    return mark_revision_status(db, revision, "validated")


def apply_pending_config(
    db: Session,
    *,
    internal_proxy_ip: str,
    created_by: int | None,
    helper: PrivilegedHelper | None = None,
    generated_dir: Path = DEFAULT_GENERATED_DIR,
    lock_path: Path = DEFAULT_LOCK_PATH,
) -> ConfigRevision:
    helper = helper or PrivilegedHelper()
    with _apply_lock(lock_path):
        revision = validate_pending_config(
            db,
            internal_proxy_ip=internal_proxy_ip,
            created_by=created_by,
            helper=helper,
            generated_dir=generated_dir,
        )
        applied_started = False
        try:
            applied_started = True
            helper.apply()
            if not _health_ok(helper):
                raise RuntimeError("post-apply health check failed")
        except Exception as exc:
            if applied_started:
                try:
                    helper.rollback()
                except Exception as rollback_exc:
                    mark_revision_status(db, revision, "failed")
                    raise RuntimeError(f"{exc}; rollback failed: {rollback_exc}") from exc
            mark_revision_status(db, revision, "failed")
            raise
        return mark_revision_status(db, revision, "active")


def rollback_revision(
    db: Session,
    *,
    revision_id: int,
    helper: PrivilegedHelper | None = None,
    lock_path: Path = DEFAULT_LOCK_PATH,
) -> ConfigRevision:
    helper = helper or PrivilegedHelper()
    with _apply_lock(lock_path):
        current = db.get(ConfigRevision, revision_id)
        if current is None:
            raise LookupError("revision not found")
        if current.status != "active":
            raise ValueError("revision is not active")

        previous = db.scalars(
            select(ConfigRevision)
            .where(ConfigRevision.id < current.id, ConfigRevision.status == "rolled_back")
            .order_by(ConfigRevision.id.desc())
        ).first()
        if previous is None:
            raise LookupError("previous revision not found")

        helper.rollback()
        if not _health_ok(helper):
            raise RuntimeError("post-rollback health check failed")
        mark_revision_status(db, current, "rolled_back")
        return mark_revision_status(db, previous, "active")
