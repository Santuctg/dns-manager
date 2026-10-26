"""API additions for the 0.7.1 console: ssl_status, pending and revisions."""

from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.database import Base, get_db
from app.main import app
from app.models.auth import Permission, Role, User
from app.models.mapping import Mapping
from app.models.revision import ConfigRevision
from app.models.ssl import SslCertificate
from app.security import hash_password
from app.services.auth_service import ALL_PERMISSIONS, ADMIN_PERMISSIONS, VIEWER_PERMISSIONS, create_session


def make_client(role_name: str = "super_admin"):
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    raw_session = None
    with Session(engine) as db:
        perms = {name: Permission(name=name) for name in sorted(ALL_PERMISSIONS)}
        db.add_all(perms.values())
        roles = {
            "super_admin": Role(name="super_admin", permissions=[perms[n] for n in sorted(ALL_PERMISSIONS)]),
            "admin": Role(name="admin", permissions=[perms[n] for n in sorted(ADMIN_PERMISSIONS)]),
            "viewer": Role(name="viewer", permissions=[perms[n] for n in sorted(VIEWER_PERMISSIONS)]),
        }
        db.add_all(roles.values())
        db.flush()
        user = User(
            username=f"{role_name}-user",
            email=f"{role_name}@example.com",
            password_hash=hash_password("very-secure-password"),
            role=roles[role_name],
        )
        db.add(user)
        db.commit()
        raw_session = create_session(db, user, "csrf-token")

    def override_db():
        with Session(engine) as db:
            yield db

    app.dependency_overrides[get_db] = override_db
    client = TestClient(app, base_url="https://testserver", follow_redirects=False)
    client.cookies.set("dns_manager_session", raw_session)
    client.cookies.set("dns_manager_csrf", "csrf-token")
    return client, engine


def add_mapping(engine, domain: str, **overrides) -> int:
    with Session(engine) as db:
        row = Mapping(
            domain=domain,
            upstream_scheme=overrides.get("upstream_scheme", "http"),
            upstream_host=overrides.get("upstream_host", "192.168.8.2"),
            upstream_port=overrides.get("upstream_port", 8080),
            enabled=overrides.get("enabled", True),
            websocket_enabled=overrides.get("websocket_enabled", True),
            preserve_host=overrides.get("preserve_host", True),
        )
        db.add(row)
        db.commit()
        return row.id


def add_certificate(engine, domain: str, status: str, *, redirect_http: bool = True) -> None:
    with Session(engine) as db:
        db.add(SslCertificate(domain=domain, status=status, redirect_http=redirect_http))
        db.commit()


def test_mapping_responses_include_the_certificate_status():
    client, engine = make_client()
    try:
        plain_id = add_mapping(engine, "plain.example.com")
        issued_id = add_mapping(engine, "issued.example.com")
        mixed_id = add_mapping(engine, "mixed.example.com")
        add_certificate(engine, "issued.example.com", "ISSUED")
        add_certificate(engine, "MiXeD.Example.COM.", "EXPIRING")

        index = client.get("/api/v1/mappings")
        assert index.status_code == 200
        rows = {row["domain"]: row for row in index.json()}
        assert rows["plain.example.com"]["ssl_status"] is None
        assert rows["issued.example.com"]["ssl_status"] == "ISSUED"
        assert rows["mixed.example.com"]["ssl_status"] == "EXPIRING"

        single = client.get(f"/api/v1/mappings/{issued_id}")
        assert single.status_code == 200
        assert single.json()["ssl_status"] == "ISSUED"

        plain = client.get(f"/api/v1/mappings/{plain_id}")
        assert plain.json()["ssl_status"] is None
    finally:
        app.dependency_overrides.clear()


def test_create_and_update_responses_also_carry_ssl_status():
    client, engine = make_client()
    try:
        add_certificate(engine, "new.example.com", "ISSUED")
        created = client.post(
            "/api/v1/mappings",
            headers={"X-CSRF-Token": "csrf-token"},
            json={
                "domain": "new.example.com",
                "upstream_scheme": "http",
                "upstream_host": "10.0.0.5",
                "upstream_port": 3000,
                "websocket_enabled": True,
                "preserve_host": True,
            },
        )
        assert created.status_code == 201, created.text
        assert created.json()["ssl_status"] == "ISSUED"

        mapping_id = created.json()["id"]
        updated = client.put(
            f"/api/v1/mappings/{mapping_id}",
            headers={"X-CSRF-Token": "csrf-token"},
            json={
                "domain": "new.example.com",
                "upstream_scheme": "http",
                "upstream_host": "10.0.0.5",
                "upstream_port": 3001,
                "websocket_enabled": True,
                "preserve_host": True,
                "version": 1,
            },
        )
        assert updated.status_code == 200, updated.text
        assert updated.json()["ssl_status"] == "ISSUED"
        assert updated.json()["upstream_port"] == 3001
    finally:
        app.dependency_overrides.clear()


def test_pending_lists_added_changed_and_deleted_domains():
    client, engine = make_client()
    try:
        first_id = add_mapping(engine, "first.example.com")
        add_mapping(engine, "gone.example.com")

        with Session(engine) as db:
            from app.services.revision_service import create_revision, mark_revision_status

            revision = create_revision(db, "dns", "nginx", created_by=None)
            mark_revision_status(db, revision, "active")

        clean = client.get("/api/v1/config/pending")
        assert clean.status_code == 200
        assert clean.json() == {"count": 0, "domains": []}

        with Session(engine) as db:
            mapping = db.get(Mapping, first_id)
            mapping.upstream_port = 9090
            mapping.version += 1
            db.delete(db.query(Mapping).filter_by(domain="gone.example.com").one())
            db.commit()

        add_mapping(engine, "added.example.com")

        pending = client.get("/api/v1/config/pending")
        assert pending.status_code == 200
        payload = pending.json()
        assert payload["count"] == 3
        assert payload["domains"] == ["added.example.com", "first.example.com", "gone.example.com"]
    finally:
        app.dependency_overrides.clear()


def test_pending_requires_only_mapping_view():
    client, engine = make_client("viewer")
    try:
        add_mapping(engine, "one.example.com")
        response = client.get("/api/v1/config/pending")
        assert response.status_code == 200
        assert response.json()["domains"] == ["one.example.com"]
    finally:
        app.dependency_overrides.clear()


def test_pending_requires_authentication():
    _client, _engine = make_client()
    app.dependency_overrides.clear()
    anonymous = TestClient(app, base_url="https://testserver")
    assert anonymous.get("/api/v1/config/pending").status_code == 401


def test_revisions_are_newest_first_and_paged():
    client, engine = make_client()
    try:
        base = datetime(2026, 10, 20, 12, 0, tzinfo=timezone.utc)
        with Session(engine) as db:
            for index in range(52):
                db.add(
                    ConfigRevision(
                        revision=f"REV-20261020-{index:06d}",
                        dnsmasq_config="dns",
                        nginx_config="nginx",
                        mapping_snapshot="{}",
                        created_by=None,
                        created_at=base + timedelta(minutes=index),
                        status="generated",
                    )
                )
            db.commit()

        first = client.get("/api/v1/config/revisions?page=1")
        assert first.status_code == 200
        payload = first.json()
        assert payload["total"] == 52
        assert payload["page"] == 1
        assert payload["per_page"] == 50
        assert len(payload["items"]) == 50
        assert payload["items"][0]["revision"] == "REV-20261020-000051"
        assert payload["items"][-1]["revision"] == "REV-20261020-000002"

        second = client.get("/api/v1/config/revisions?page=2")
        assert second.status_code == 200
        assert len(second.json()["items"]) == 2
        assert second.json()["items"][-1]["revision"] == "REV-20261020-000000"
    finally:
        app.dependency_overrides.clear()


def test_revisions_include_creator_username():
    client, engine = make_client()
    try:
        with Session(engine) as db:
            user = db.query(User).first()
            db.add(
                ConfigRevision(
                    revision="REV-20261025-000001",
                    dnsmasq_config="dns",
                    nginx_config="nginx",
                    mapping_snapshot="{}",
                    created_by=user.id,
                    created_at=datetime(2026, 10, 25, 9, 0, tzinfo=timezone.utc),
                    status="active",
                )
            )
            db.commit()

        response = client.get("/api/v1/config/revisions")
        assert response.status_code == 200
        assert response.json()["items"][0]["created_by_username"] == "super_admin-user"
        assert response.json()["items"][0]["status"] == "active"
    finally:
        app.dependency_overrides.clear()


@pytest.mark.parametrize("role", ["admin", "viewer"])
def test_revisions_require_config_rollback(role):
    client, _engine = make_client(role)
    try:
        assert client.get("/api/v1/config/revisions").status_code == 403
    finally:
        app.dependency_overrides.clear()


def test_revisions_clamp_invalid_pages():
    client, engine = make_client()
    try:
        with Session(engine) as db:
            db.add(
                ConfigRevision(
                    revision="REV-20261025-000001",
                    dnsmasq_config="dns",
                    nginx_config="nginx",
                    mapping_snapshot="{}",
                    created_by=None,
                    created_at=datetime(2026, 10, 25, 9, 0, tzinfo=timezone.utc),
                    status="active",
                )
            )
            db.commit()
        response = client.get("/api/v1/config/revisions?page=0")
        assert response.status_code == 200
        assert response.json()["page"] == 1
        assert len(response.json()["items"]) == 1
    finally:
        app.dependency_overrides.clear()
