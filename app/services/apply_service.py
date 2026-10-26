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
from app.services.nginx_service import render_https_vhost, render_nginx_config
from app.services.privileged_helper import PrivilegedHelper
from app.services.revision_service import create_revision, mark_revision_status
from app.services.audit_service import record_audit_event

DEFAULT_GENERATED_DIR = Path("/var/lib/dns-manager/generated")
DEFAULT_LOCK_PATH = Path("/run/dns-manager/apply.lock")

# A certificate in either state can serve HTTPS, so both keep the HTTPS vhost
# in sync and suppress the duplicate plain-HTTP server block.
SSL_VHOST_STATUSES = frozenset({"ISSUED", "EXPIRING"})


class ConfigLockedError(RuntimeError):
    pass


def _mappings(db: Session) -> list[Mapping]:
    return list(db.scalars(select(Mapping).order_by(Mapping.domain)).all())


def _ssl_redirect_domains(db: Session) -> set[str]:
    rows = db.scalars(
        select(SslCertificate.domain).where(
            SslCertificate.redirect_http.is_(True),
            SslCertificate.status.in_(sorted(SSL_VHOST_STATUSES)),
        )
    ).all()
    return {str(domain).strip().lower().rstrip(".") for domain in rows}


def _ssl_upstream(mapping: Mapping) -> dict:
    return {
        "scheme": mapping.upstream_scheme,
        "host": mapping.upstream_host,
        "port": mapping.upstream_port,
        "preserve_host": mapping.preserve_host,
        "websocket_enabled": mapping.websocket_enabled,
        "timeout": mapping.custom_timeout or 60,
    }


def sync_ssl_vhosts(db: Session, *, helper: PrivilegedHelper, user=None) -> dict[str, list]:
    """Rewrite the HTTPS vhost of every enabled mapping that has a valid certificate.

    Failures are reported and audited but never undo the configuration apply.
    """
    certificates = {
        str(cert.domain).strip().lower().rstrip("."): cert
        for cert in db.scalars(select(SslCertificate)).all()
    }
    updated: list[str] = []
    failed: list[dict[str, str]] = []
    for mapping in _mappings(db):
        if not mapping.enabled:
            continue
        domain = str(mapping.domain).strip().lower().rstrip(".")
        certificate = certificates.get(domain)
        if certificate is None or certificate.status not in SSL_VHOST_STATUSES:
            continue
        try:
            helper.ssl_apply(domain, certificate.redirect_http, upstream=_ssl_upstream(mapping))
        except Exception as exc:  # noqa: BLE001 - a sync failure must not undo the apply
            failed.append({"domain": domain, "error": str(exc)})
            record_audit_event(
                db,
                user=user,
                action="SSL_SYNC_FAILED",
                object_type="ssl_certificate",
                object_id=domain,
                status="failed",
                error_message=str(exc),
            )
        else:
            updated.append(domain)
    return {"updated": updated, "failed": failed}



def preview_config(db: Session, *, internal_proxy_ip: str) -> dict[str, object]:
    mappings = _mappings(db)
    certificates = {
        str(cert.domain).strip().lower().rstrip("."): cert
        for cert in db.scalars(select(SslCertificate)).all()
    }
    ssl_vhosts: dict[str, str] = {}
    for mapping in mappings:
        if not mapping.enabled:
            continue
        domain = str(mapping.domain).strip().lower().rstrip(".")
        certificate = certificates.get(domain)
        if certificate is None or certificate.status not in SSL_VHOST_STATUSES:
            continue
        ssl_vhosts[domain] = render_https_vhost(
            domain, mapping, redirect_http=bool(certificate.redirect_http)
        )
    return {
        "dnsmasq_config": render_dnsmasq_config(mappings, internal_proxy_ip),
        "nginx_config": render_nginx_config(
            mappings, skip_http_domains=_ssl_redirect_domains(db)
        ),
        "ssl_vhosts": ssl_vhosts,
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


def _validate_unlocked(
    db: Session,
    *,
    internal_proxy_ip: str,
    created_by: int | None,
    helper: PrivilegedHelper,
    generated_dir: Path,
) -> ConfigRevision:
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


def validate_pending_config(
    db: Session,
    *,
    internal_proxy_ip: str,
    created_by: int | None,
    helper: PrivilegedHelper | None = None,
    generated_dir: Path = DEFAULT_GENERATED_DIR,
    lock_path: Path = DEFAULT_LOCK_PATH,
) -> ConfigRevision:
    # Staging rewrites the shared generated files, so it must not interleave with an apply.
    with _apply_lock(lock_path):
        return _validate_unlocked(
            db,
            internal_proxy_ip=internal_proxy_ip,
            created_by=created_by,
            helper=helper or PrivilegedHelper(),
            generated_dir=generated_dir,
        )


def _install_staged(helper: PrivilegedHelper, *, check: str) -> None:
    """Install the staged files; on any failure put back what was live before."""
    try:
        helper.apply()
        if not _health_ok(helper):
            raise RuntimeError(f"post-{check} health check failed")
    except Exception as exc:
        try:
            helper.rollback()
        except Exception as rollback_exc:
            raise RuntimeError(f"{exc}; rollback failed: {rollback_exc}") from exc
        raise


def apply_pending_config(
    db: Session,
    *,
    internal_proxy_ip: str,
    created_by: int | None,
    helper: PrivilegedHelper | None = None,
    generated_dir: Path = DEFAULT_GENERATED_DIR,
    lock_path: Path = DEFAULT_LOCK_PATH,
    user=None,
    ssl_sync_out: dict | None = None,
) -> ConfigRevision:
    helper = helper or PrivilegedHelper()
    with _apply_lock(lock_path):
        revision = _validate_unlocked(
            db,
            internal_proxy_ip=internal_proxy_ip,
            created_by=created_by,
            helper=helper,
            generated_dir=generated_dir,
        )
        try:
            _install_staged(helper, check="apply")
        except Exception:
            mark_revision_status(db, revision, "failed")
            raise
        revision = mark_revision_status(db, revision, "active")
        sync_result = sync_ssl_vhosts(db, helper=helper, user=user)
        if ssl_sync_out is not None:
            ssl_sync_out.update(sync_result)
        return revision


def _rollback_target(db: Session, current: ConfigRevision) -> ConfigRevision | None:
    older = select(ConfigRevision).where(ConfigRevision.id < current.id).order_by(ConfigRevision.id.desc())
    target = db.scalars(older.where(ConfigRevision.status == "superseded")).first()
    if target is not None:
        return target
    # Revisions replaced before "superseded" existed were all recorded as
    # "rolled_back"; fall back to them only when no newer history exists.
    has_superseded = db.scalar(select(ConfigRevision.id).where(ConfigRevision.status == "superseded").limit(1))
    if has_superseded is not None:
        return None
    return db.scalars(older.where(ConfigRevision.status == "rolled_back")).first()


def rollback_revision(
    db: Session,
    *,
    revision_id: int,
    helper: PrivilegedHelper | None = None,
    generated_dir: Path = DEFAULT_GENERATED_DIR,
    lock_path: Path = DEFAULT_LOCK_PATH,
) -> ConfigRevision:
    helper = helper or PrivilegedHelper()
    with _apply_lock(lock_path):
        current = db.get(ConfigRevision, revision_id)
        if current is None:
            raise LookupError("revision not found")
        if current.status != "active":
            raise ValueError("revision is not active")

        previous = _rollback_target(db, current)
        if previous is None:
            raise LookupError("previous revision not found")

        # Re-install the previous revision's own stored configuration, so what is
        # live always matches the revision marked active, however many times in a
        # row this runs. The helper's single known-good copy is only the safety net.
        _stage_revision(previous, generated_dir)
        helper.validate()
        _install_staged(helper, check="rollback")
        mark_revision_status(db, current, "rolled_back")
        return mark_revision_status(db, previous, "active")
