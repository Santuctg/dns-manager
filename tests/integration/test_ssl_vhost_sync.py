"""Apply rewrites the HTTPS vhost of every mapping with a valid certificate."""

from __future__ import annotations

import fcntl

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import Base
from app.models.audit import AuditLog
from app.models.mapping import Mapping
from app.models.ssl import SslCertificate
from app.services.apply_service import (
    ConfigLockedError,
    apply_pending_config,
    preview_config,
    render_https_vhost,
)


def make_db():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, expire_on_commit=False)()


def add_mapping(db, domain: str, *, enabled: bool = True, **overrides) -> Mapping:
    row = Mapping(
        domain=domain,
        upstream_scheme=overrides.get("upstream_scheme", "http"),
        upstream_host=overrides.get("upstream_host", "192.168.8.2"),
        upstream_port=overrides.get("upstream_port", 8080),
        enabled=enabled,
        websocket_enabled=overrides.get("websocket_enabled", True),
        preserve_host=overrides.get("preserve_host", True),
        custom_timeout=overrides.get("custom_timeout"),
    )
    db.add(row)
    db.commit()
    return row


def add_certificate(db, domain: str, status: str, *, redirect_http: bool = True) -> None:
    db.add(SslCertificate(domain=domain, status=status, redirect_http=redirect_http))
    db.commit()


class SyncHelper:
    def __init__(self, *, failing: set[str] | None = None):
        self.failing = failing or set()
        self.calls: list[str] = []
        self.ssl_calls: list[tuple[str, bool, dict | None]] = []

    def validate(self):
        self.calls.append("validate")
        return {"ok": True, "validated": True}

    def apply(self):
        self.calls.append("apply")
        return {"ok": True, "applied": True}

    def rollback(self):
        self.calls.append("rollback")
        return {"ok": True, "rolled_back": True}

    def status(self):
        self.calls.append("status")
        return {"dnsmasq": "active", "nginx": "active"}

    def ssl_apply(self, domain, redirect_http=True, upstream=None):
        self.ssl_calls.append((domain, redirect_http, upstream))
        if domain in self.failing:
            raise RuntimeError(f"reload failed for {domain}")
        return {"applied": True, "domain": domain}


def apply(db, helper, tmp_path):
    return apply_pending_config(
        db,
        internal_proxy_ip="192.168.128.2",
        created_by=1,
        helper=helper,
        generated_dir=tmp_path / "generated",
        lock_path=tmp_path / "apply.lock",
    )


def test_sync_updates_issued_and_expiring_certificates_only(tmp_path):
    db = make_db()
    mapping = add_mapping(db, "panel.example.com", upstream_port=8082)
    add_mapping(db, "expiring.example.com")
    add_mapping(db, "expired.example.com")
    add_mapping(db, "failed.example.com")
    add_mapping(db, "pending.example.com")
    add_mapping(db, "disabled.example.com", enabled=False)

    add_certificate(db, "panel.example.com", "ISSUED")
    add_certificate(db, "expiring.example.com", "EXPIRING")
    add_certificate(db, "expired.example.com", "EXPIRED")
    add_certificate(db, "failed.example.com", "ERROR")
    add_certificate(db, "pending.example.com", "NOT_ISSUED")
    add_certificate(db, "disabled.example.com", "ISSUED")

    helper = SyncHelper()
    revision = apply(db, helper, tmp_path)

    assert revision.status == "active"
    assert helper.calls == ["validate", "apply", "status"]
    assert [call[0] for call in helper.ssl_calls] == ["expiring.example.com", "panel.example.com"]
    assert all(call[1] is True for call in helper.ssl_calls)

    domain, redirect, upstream = helper.ssl_calls[1]
    assert redirect is True
    assert upstream == {
        "scheme": "http",
        "host": "192.168.8.2",
        "port": 8082,
        "preserve_host": True,
        "websocket_enabled": True,
        "timeout": 60,
    }
    assert mapping.domain == domain


def test_sync_failure_keeps_the_apply_and_is_audited(tmp_path):
    db = make_db()
    add_mapping(db, "good.example.com")
    add_mapping(db, "broken.example.com")
    add_certificate(db, "good.example.com", "ISSUED")
    add_certificate(db, "broken.example.com", "ISSUED", redirect_http=False)

    helper = SyncHelper(failing={"broken.example.com"})
    ssl_sync: dict = {}
    revision = apply_pending_config(
        db,
        internal_proxy_ip="192.168.128.2",
        created_by=1,
        helper=helper,
        generated_dir=tmp_path / "generated",
        lock_path=tmp_path / "apply.lock",
        ssl_sync_out=ssl_sync,
    )

    assert revision.status == "active"
    assert helper.calls == ["validate", "apply", "status"]
    assert ssl_sync == {
        "updated": ["good.example.com"],
        "failed": [{"domain": "broken.example.com", "error": "reload failed for broken.example.com"}],
    }
    redirects = {call[0]: call[1] for call in helper.ssl_calls}
    assert redirects == {"broken.example.com": False, "good.example.com": True}

    audit = db.query(AuditLog).filter_by(action="SSL_SYNC_FAILED").one()
    assert audit.object_id == "broken.example.com"
    assert audit.status == "failed"
    assert "reload failed" in audit.error_message


def test_sync_runs_inside_the_apply_lock(tmp_path):
    db = make_db()
    add_mapping(db, "panel.example.com")
    add_certificate(db, "panel.example.com", "ISSUED")
    helper = SyncHelper()
    lock_path = tmp_path / "apply.lock"
    lock_path.touch()

    with lock_path.open("a+") as held:
        fcntl.flock(held.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(ConfigLockedError):
            apply(db, helper, tmp_path)

    assert helper.calls == []
    assert helper.ssl_calls == []


def test_preview_exposes_https_vhosts_for_valid_certificates_only():
    db = make_db()
    add_mapping(db, "issued.example.com")
    add_mapping(db, "expiring.example.com", preserve_host=False, websocket_enabled=False)
    add_mapping(db, "expired.example.com")
    add_mapping(db, "disabled.example.com", enabled=False)
    add_certificate(db, "issued.example.com", "ISSUED")
    add_certificate(db, "expiring.example.com", "EXPIRING")
    add_certificate(db, "expired.example.com", "EXPIRED")
    add_certificate(db, "disabled.example.com", "ISSUED")

    preview = preview_config(db, internal_proxy_ip="192.168.128.2")
    vhosts = preview["ssl_vhosts"]
    assert set(vhosts) == {"issued.example.com", "expiring.example.com"}
    assert "listen 443 ssl" in vhosts["issued.example.com"]
    assert "proxy_pass http://192.168.8.2:8080;" in vhosts["issued.example.com"]
    assert "proxy_set_header Host $host;" in vhosts["issued.example.com"]
    assert "proxy_set_header Host $host;" not in vhosts["expiring.example.com"]
    assert "Upgrade $http_upgrade" not in vhosts["expiring.example.com"]
    assert "return 301 https://$host$request_uri;" in vhosts["expiring.example.com"]


def test_expiring_certificate_already_suppresses_the_plain_http_block():
    db = make_db()
    add_mapping(db, "panel.example.com")
    add_certificate(db, "panel.example.com", "EXPIRING")

    preview = preview_config(db, internal_proxy_ip="192.168.128.2")
    config = preview["nginx_config"]
    # Only the HTTPS redirect owns port 80; the old duplicate plain block is gone.
    assert config.count("server_name panel.example.com") == 0
    assert "listen 80; server_name panel.example.com; return 301" in preview["ssl_vhosts"]["panel.example.com"]


def test_redirect_disabled_keeps_the_plain_http_block():
    db = make_db()
    add_mapping(db, "panel.example.com")
    add_certificate(db, "panel.example.com", "ISSUED", redirect_http=False)

    preview = preview_config(db, internal_proxy_ip="192.168.128.2")
    assert "server {" in preview["nginx_config"]
    assert "server_name panel.example.com;" in preview["nginx_config"]
    assert "return 301" not in preview["ssl_vhosts"]["panel.example.com"]


def test_render_https_vhost_matches_the_helper_layout():
    db = make_db()
    mapping = add_mapping(db, "panel.example.com", custom_timeout=90)
    text = render_https_vhost("panel.example.com", mapping, redirect_http=True)
    assert text.startswith("server { listen 80; server_name panel.example.com; return 301 https://$host$request_uri; }")
    assert "ssl_certificate /etc/letsencrypt/live/panel.example.com/fullchain.pem;" in text
    assert "proxy_send_timeout 60s;" in text
    assert "proxy_read_timeout 90s;" in text
    assert "proxy_set_header X-Forwarded-Proto https;" in text
    assert text.endswith("}\n")
