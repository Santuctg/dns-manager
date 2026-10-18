from __future__ import annotations

import fcntl
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import Base
from app.models.mapping import Mapping
from app.services.apply_service import (
    ConfigLockedError,
    apply_pending_config,
    preview_config,
    rollback_revision,
)
from app.services.revision_service import get_active_revision


def make_db():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, expire_on_commit=False)()


def add_mapping(db):
    row = Mapping(
        domain="panel.example.com",
        upstream_scheme="http",
        upstream_host="192.168.8.2",
        upstream_port=8082,
        enabled=True,
    )
    db.add(row)
    db.commit()
    return row


class FakeHelper:
    def __init__(self, *, fail_apply=False, fail_health=False):
        self.fail_apply = fail_apply
        self.fail_health = fail_health
        self.calls = []

    def validate(self):
        self.calls.append("validate")
        return {"ok": True, "validated": True}

    def apply(self):
        self.calls.append("apply")
        if self.fail_apply:
            raise RuntimeError("nginx reload failed")
        return {"ok": True, "applied": True}

    def rollback(self):
        self.calls.append("rollback")
        return {"ok": True, "rolled_back": True}

    def status(self):
        self.calls.append("status")
        if self.fail_health:
            return {"dnsmasq": "active", "nginx": "failed"}
        return {"dnsmasq": "active", "nginx": "active"}


def test_happy_path_generates_validates_applies_health_checks_and_marks_active(tmp_path):
    db = make_db()
    add_mapping(db)
    helper = FakeHelper()

    preview = preview_config(db, internal_proxy_ip="192.168.128.2")
    assert "address=/panel.example.com/192.168.128.2" in preview["dnsmasq_config"]
    assert "proxy_pass http://192.168.8.2:8082;" in preview["nginx_config"]

    revision = apply_pending_config(
        db,
        internal_proxy_ip="192.168.128.2",
        created_by=1,
        helper=helper,
        generated_dir=tmp_path / "generated",
        lock_path=tmp_path / "apply.lock",
    )

    assert helper.calls == ["validate", "apply", "status"]
    assert revision.status == "active"
    assert get_active_revision(db).id == revision.id
    assert (tmp_path / "generated" / "dnsmasq.conf").read_text() == revision.dnsmasq_config
    assert (tmp_path / "generated" / "nginx.conf").read_text() == revision.nginx_config
    nginx_test = (tmp_path / "generated" / "nginx-test.conf").read_text()
    assert "include" in nginx_test
    assert "access_log off;" in nginx_test
    assert f"error_log {tmp_path / 'generated' / 'nginx-test-error.log'} notice;" in nginx_test
    generated = tmp_path / "generated"
    assert f"client_body_temp_path {generated / 'nginx-client-body'};" in nginx_test
    assert f"proxy_temp_path {generated / 'nginx-proxy'};" in nginx_test
    assert f"fastcgi_temp_path {generated / 'nginx-fastcgi'};" in nginx_test
    assert f"uwsgi_temp_path {generated / 'nginx-uwsgi'};" in nginx_test
    assert f"scgi_temp_path {generated / 'nginx-scgi'};" in nginx_test


def test_partial_apply_failure_rolls_back_and_marks_new_revision_failed(tmp_path):
    db = make_db()
    add_mapping(db)
    helper = FakeHelper(fail_apply=True)

    with pytest.raises(RuntimeError, match="nginx reload failed"):
        apply_pending_config(
            db,
            internal_proxy_ip="192.168.128.2",
            created_by=1,
            helper=helper,
            generated_dir=tmp_path / "generated",
            lock_path=tmp_path / "apply.lock",
        )

    assert helper.calls == ["validate", "apply", "rollback"]
    revision = db.query(type(get_active_revision(db))).first() if False else None
    from app.models.revision import ConfigRevision
    newest = db.query(ConfigRevision).order_by(ConfigRevision.id.desc()).first()
    assert newest.status == "failed"
    assert get_active_revision(db) is None


def test_failed_post_apply_health_check_rolls_back_and_marks_failed(tmp_path):
    db = make_db()
    add_mapping(db)
    helper = FakeHelper(fail_health=True)

    with pytest.raises(RuntimeError, match="post-apply health check failed"):
        apply_pending_config(
            db,
            internal_proxy_ip="192.168.128.2",
            created_by=1,
            helper=helper,
            generated_dir=tmp_path / "generated",
            lock_path=tmp_path / "apply.lock",
        )

    assert helper.calls == ["validate", "apply", "status", "rollback"]
    from app.models.revision import ConfigRevision
    newest = db.query(ConfigRevision).order_by(ConfigRevision.id.desc()).first()
    assert newest.status == "failed"


def test_second_apply_returns_config_locked_when_lock_is_held(tmp_path):
    db = make_db()
    add_mapping(db)
    helper = FakeHelper()
    lock_path = tmp_path / "apply.lock"
    lock_path.touch()

    with lock_path.open("a+") as held:
        fcntl.flock(held.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(ConfigLockedError, match="CONFIG_LOCKED"):
            apply_pending_config(
                db,
                internal_proxy_ip="192.168.128.2",
                created_by=1,
                helper=helper,
                generated_dir=tmp_path / "generated",
                lock_path=lock_path,
            )

    assert helper.calls == []


def test_rollback_revision_restores_previous_revision_status(tmp_path):
    db = make_db()
    mapping = add_mapping(db)
    helper = FakeHelper()

    first = apply_pending_config(
        db,
        internal_proxy_ip="192.168.128.2",
        created_by=1,
        helper=helper,
        generated_dir=tmp_path / "generated",
        lock_path=tmp_path / "apply.lock",
    )
    mapping.upstream_port = 9090
    mapping.version += 1
    db.commit()
    second = apply_pending_config(
        db,
        internal_proxy_ip="192.168.128.2",
        created_by=1,
        helper=helper,
        generated_dir=tmp_path / "generated",
        lock_path=tmp_path / "apply.lock",
    )

    rolled_back_to = rollback_revision(
        db,
        revision_id=second.id,
        helper=helper,
        lock_path=tmp_path / "apply.lock",
    )

    assert rolled_back_to.id == first.id
    assert second.status == "rolled_back"
    assert first.status == "active"
    assert helper.calls[-2:] == ["rollback", "status"]


def test_preview_api_requires_explicit_internal_proxy_ip(monkeypatch):
    from fastapi.testclient import TestClient
    from sqlalchemy.orm import Session
    from app.database import get_db
    from app.main import app
    from app.models.auth import Permission, Role, User
    from app.security import hash_password
    from app.services.auth_service import create_session
    from app.config import get_settings

    engine = create_engine('sqlite+pysqlite:///:memory:', connect_args={'check_same_thread': False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        role = Role(name='admin'); permission = Permission(name='config.apply'); role.permissions.append(permission)
        user = User(username='cfgadmin', password_hash=hash_password('very-secure-password'), role=role)
        db.add_all([role, user]); db.commit(); db.refresh(user)
        raw = create_session(db, user, 'csrf-token')
    def override_db():
        with Session(engine) as db:
            yield db
    app.dependency_overrides[get_db] = override_db
    get_settings.cache_clear()
    monkeypatch.delenv('DNS_MANAGER_INTERNAL_PROXY_IP', raising=False)
    client = TestClient(app, base_url='https://testserver')
    client.cookies.set('dns_manager_session', raw)
    try:
        response = client.get('/api/v1/config/preview')
        assert response.status_code == 503
        assert 'DNS_MANAGER_INTERNAL_PROXY_IP' in response.json()['detail']
    finally:
        app.dependency_overrides.clear(); get_settings.cache_clear()


def test_preview_api_uses_configured_internal_proxy_ip(monkeypatch):
    from fastapi.testclient import TestClient
    from sqlalchemy.orm import Session
    from app.database import get_db
    from app.main import app
    from app.models.auth import Permission, Role, User
    from app.security import hash_password
    from app.services.auth_service import create_session
    from app.config import get_settings

    engine = create_engine('sqlite+pysqlite:///:memory:', connect_args={'check_same_thread': False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        role = Role(name='admin'); permission = Permission(name='config.apply'); role.permissions.append(permission)
        user = User(username='cfgadmin', password_hash=hash_password('very-secure-password'), role=role)
        db.add_all([role, user]); db.commit(); db.refresh(user)
        db.add(Mapping(domain='panel.example.com', upstream_scheme='http', upstream_host='192.168.8.2', upstream_port=8082, enabled=True))
        db.commit(); raw = create_session(db, user, 'csrf-token')
    def override_db():
        with Session(engine) as db:
            yield db
    app.dependency_overrides[get_db] = override_db
    monkeypatch.setenv('DNS_MANAGER_INTERNAL_PROXY_IP', '192.168.128.2'); get_settings.cache_clear()
    client = TestClient(app, base_url='https://testserver'); client.cookies.set('dns_manager_session', raw)
    try:
        response = client.get('/api/v1/config/preview')
        assert response.status_code == 200
        assert 'address=/panel.example.com/192.168.128.2' in response.json()['dnsmasq_config']
    finally:
        app.dependency_overrides.clear(); get_settings.cache_clear()


def test_057_preview_omits_http_mapping_when_issued_ssl_redirect_owns_domain():
    from app.models.ssl import SslCertificate

    db = make_db()
    row = Mapping(
        domain="vm226.connect3.net.bd",
        upstream_scheme="https",
        upstream_host="192.168.255.226",
        upstream_port=443,
        enabled=True,
    )
    db.add(row)
    db.add(SslCertificate(
        domain="vm226.connect3.net.bd",
        provider="acme_dns_hosted",
        redirect_http=True,
        status="ISSUED",
    ))
    db.commit()

    preview = preview_config(db, internal_proxy_ip="157.15.20.132")
    assert "server_name vm226.connect3.net.bd;" not in preview["nginx_config"]
    assert "proxy_pass https://192.168.255.226:443;" not in preview["nginx_config"]
