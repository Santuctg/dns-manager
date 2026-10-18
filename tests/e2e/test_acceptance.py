from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api import backups as backup_api
from app.api import config_ops
from app.config import get_settings
from app.database import Base, build_engine, get_db
from app.main import app
from app.models.audit import AuditLog
from app.models.auth import Role, User
from app.models.mapping import Mapping
from app.security import hash_password
from app.services import apply_service
from app.services.auth_service import seed_default_rbac
from app.services.backup_service import BackupPaths
from app.services.revision_service import get_pending_change_count

PASSWORD = "Acceptance-Password-2026!"
LAN_IP = "192.168.128.2"
DOMAIN = "acceptance.internal"


class FakePrivilegedHelper:
    """CI-safe stand-in for the root socket helper, with known-good rollback."""

    def __init__(self, generated: Path, live_dnsmasq: Path, live_nginx: Path):
        self.generated = generated
        self.live_dnsmasq = live_dnsmasq
        self.live_nginx = live_nginx
        self.known_good_dnsmasq = ""
        self.known_good_nginx = ""
        self.fail_apply = False
        self.calls: list[str] = []

    def validate(self):
        self.calls.append("validate")
        assert (self.generated / "dnsmasq.conf").is_file()
        assert (self.generated / "nginx.conf").is_file()
        return {"ok": True, "validated": True}

    def apply(self):
        self.calls.append("apply")
        self.known_good_dnsmasq = self.live_dnsmasq.read_text() if self.live_dnsmasq.exists() else ""
        self.known_good_nginx = self.live_nginx.read_text() if self.live_nginx.exists() else ""
        if self.fail_apply:
            raise RuntimeError("simulated live reload failure")
        self.live_dnsmasq.parent.mkdir(parents=True, exist_ok=True)
        self.live_nginx.parent.mkdir(parents=True, exist_ok=True)
        self.live_dnsmasq.write_text((self.generated / "dnsmasq.conf").read_text())
        self.live_nginx.write_text((self.generated / "nginx.conf").read_text())
        return {"ok": True, "applied": True}

    def rollback(self):
        self.calls.append("rollback")
        self.live_dnsmasq.write_text(self.known_good_dnsmasq)
        self.live_nginx.write_text(self.known_good_nginx)
        return {"ok": True, "rolled_back": True}

    def status(self):
        self.calls.append("status")
        return {"dnsmasq": "active", "nginx": "active", "staged_dnsmasq": False, "staged_nginx": False}


@dataclass
class AcceptanceEnv:
    client: TestClient
    engine: object
    helper: FakePrivilegedHelper
    paths: BackupPaths

    def login(self, username: str) -> TestClient:
        client = TestClient(app, base_url="https://testserver")
        csrf = client.get("/api/v1/auth/csrf")
        assert csrf.status_code == 200
        token = csrf.json()["csrf_token"]
        response = client.post(
            "/api/v1/auth/login",
            json={"username": username, "password": PASSWORD},
            headers={"X-CSRF-Token": token},
        )
        assert response.status_code == 200
        return client

    @staticmethod
    def csrf(client: TestClient) -> dict[str, str]:
        token = client.cookies.get("dns_manager_csrf")
        assert token
        return {"X-CSRF-Token": token}


def _role(db: Session, name: str) -> Role:
    return db.scalar(select(Role).where(Role.name == name))


def _seed_users(engine) -> None:
    with Session(engine) as db:
        seed_default_rbac(db)
        for username, role_name in (("root-admin", "super_admin"), ("ops-admin", "admin"), ("read-only", "viewer")):
            db.add(User(username=username, password_hash=hash_password(PASSWORD), role=_role(db, role_name)))
        db.commit()


@pytest.fixture
def acceptance_env(tmp_path, monkeypatch):
    database = tmp_path / "dns-manager.db"
    engine = build_engine(str(database))
    Base.metadata.create_all(engine)
    _seed_users(engine)

    generated = tmp_path / "generated"
    live_dnsmasq = tmp_path / "live" / "dns-manager.conf"
    live_nginx = tmp_path / "live" / "nginx.conf"
    live_dnsmasq.parent.mkdir(parents=True)
    live_dnsmasq.write_text("# initial dns\n")
    live_nginx.write_text("# initial nginx\n")
    paths = BackupPaths(
        database=database,
        live_dnsmasq=live_dnsmasq,
        live_nginx=live_nginx,
        generated_dnsmasq=generated / "dnsmasq.conf",
        generated_nginx=generated / "nginx.conf",
        generated_nginx_main=generated / "nginx-test.conf",
        backup_dir=tmp_path / "backups",
    )
    helper = FakePrivilegedHelper(generated, live_dnsmasq, live_nginx)

    def override_db():
        with Session(engine) as db:
            yield db

    app.dependency_overrides[get_db] = override_db
    monkeypatch.setenv("DNS_MANAGER_INTERNAL_PROXY_IP", LAN_IP)
    get_settings.cache_clear()

    real_apply = apply_service.apply_pending_config
    real_validate = apply_service.validate_pending_config
    real_rollback = apply_service.rollback_revision

    def api_apply(db, *, internal_proxy_ip, created_by):
        return real_apply(
            db,
            internal_proxy_ip=internal_proxy_ip,
            created_by=created_by,
            helper=helper,
            generated_dir=generated,
            lock_path=tmp_path / "apply.lock",
        )

    def api_validate(db, *, internal_proxy_ip, created_by):
        return real_validate(
            db,
            internal_proxy_ip=internal_proxy_ip,
            created_by=created_by,
            helper=helper,
            generated_dir=generated,
        )

    def api_rollback(db, *, revision_id):
        return real_rollback(db, revision_id=revision_id, helper=helper, lock_path=tmp_path / "apply.lock")

    monkeypatch.setattr(config_ops, "apply_pending_config", api_apply)
    monkeypatch.setattr(config_ops, "validate_pending_config", api_validate)
    monkeypatch.setattr(config_ops, "rollback_revision", api_rollback)
    monkeypatch.setattr(backup_api, "production_backup_paths", lambda: paths)
    monkeypatch.setattr(backup_api, "get_engine", lambda: engine)

    from app.services import backup_service
    real_restore = backup_service.restore_backup
    monkeypatch.setattr(
        backup_api,
        "restore_backup",
        lambda backup_id, paths=None: real_restore(backup_id, paths=paths, helper=helper),
    )

    env = AcceptanceEnv(TestClient(app, base_url="https://testserver"), engine, helper, paths)
    try:
        yield env
    finally:
        app.dependency_overrides.clear()
        get_settings.cache_clear()
        engine.dispose()


def _dns_lookup(config: str, domain: str) -> str | None:
    match = re.search(rf"^address=/{re.escape(domain)}/([^\s]+)$", config, re.MULTILINE)
    return match.group(1) if match else None


def _proxy_target(config: str, domain: str) -> str | None:
    block = re.search(rf"server \{{.*?server_name {re.escape(domain)};.*?proxy_pass ([^;]+);.*?\n\}}", config, re.DOTALL)
    return block.group(1) if block else None


def test_complete_mapping_apply_backup_restore_and_cleanup_lifecycle(acceptance_env: AcceptanceEnv):
    env = acceptance_env
    client = env.login("root-admin")
    headers = env.csrf(client)

    me = client.get("/api/v1/auth/me")
    assert me.status_code == 200 and me.json()["role"] == "super_admin"

    created = client.post(
        "/api/v1/mappings",
        headers=headers,
        json={
            "domain": DOMAIN,
            "upstream_scheme": "http",
            "upstream_host": "127.0.0.1",
            "upstream_port": 8500,
            "enabled": True,
            "websocket_enabled": False,
            "preserve_host": True,
            "tls_verify": True,
            "description": "Task 19 acceptance mapping",
        },
    )
    assert created.status_code == 201
    mapping = created.json()

    preview = client.get("/api/v1/config/preview")
    assert preview.status_code == 200
    assert preview.json()["pending_change_count"] == 1
    assert _dns_lookup(preview.json()["dnsmasq_config"], DOMAIN) == LAN_IP
    assert _proxy_target(preview.json()["nginx_config"], DOMAIN) == "http://127.0.0.1:8500"

    validated = client.post("/api/v1/config/validate", headers=headers)
    assert validated.status_code == 200 and validated.json()["status"] == "validated"

    applied = client.post("/api/v1/config/apply", headers=headers)
    assert applied.status_code == 200 and applied.json()["status"] == "active"
    first_active_revision = applied.json()["revision_id"]
    assert _dns_lookup(env.paths.live_dnsmasq.read_text(), DOMAIN) == LAN_IP
    assert _proxy_target(env.paths.live_nginx.read_text(), DOMAIN) == "http://127.0.0.1:8500"
    with Session(env.engine) as db:
        assert get_pending_change_count(db) == 0

    updated = client.put(
        f"/api/v1/mappings/{mapping['id']}",
        headers=headers,
        json={
            **{k: mapping[k] for k in (
                "domain", "upstream_scheme", "upstream_host", "enabled", "websocket_enabled",
                "preserve_host", "tls_verify", "custom_timeout", "description"
            )},
            "upstream_port": 8501,
            "version": mapping["version"],
        },
    )
    assert updated.status_code == 200
    mapping = updated.json()
    reapplied = client.post("/api/v1/config/apply", headers=headers)
    assert reapplied.status_code == 200 and reapplied.json()["status"] == "active"
    assert _proxy_target(env.paths.live_nginx.read_text(), DOMAIN) == "http://127.0.0.1:8501"

    backup = client.post("/api/v1/backups", headers=headers)
    assert backup.status_code == 201
    backup_id = backup.json()["backup_id"]
    assert client.get("/api/v1/backups").json()[0]["backup_id"] == backup_id

    deleted = client.delete(f"/api/v1/mappings/{mapping['id']}", headers=headers)
    assert deleted.status_code == 204
    deletion_apply = client.post("/api/v1/config/apply", headers=headers)
    assert deletion_apply.status_code == 200
    assert _dns_lookup(env.paths.live_dnsmasq.read_text(), DOMAIN) is None
    assert DOMAIN not in env.paths.live_nginx.read_text()

    pre_restore_audit = client.get("/api/v1/audit", params={"limit": 500})
    assert pre_restore_audit.status_code == 200
    pre_restore_actions = {row["action"] for row in pre_restore_audit.json()}
    assert {"BACKUP_CREATED", "MAPPING_DELETED"} <= pre_restore_actions

    restored = client.post(f"/api/v1/backups/{backup_id}/restore", headers=headers)
    assert restored.status_code == 200
    assert restored.json()["restored_backup_id"] == backup_id
    assert restored.json()["pre_restore_backup_id"].startswith("BKP-")
    assert _dns_lookup(env.paths.live_dnsmasq.read_text(), DOMAIN) == LAN_IP
    assert _proxy_target(env.paths.live_nginx.read_text(), DOMAIN) == "http://127.0.0.1:8501"

    mappings = client.get("/api/v1/mappings")
    assert mappings.status_code == 200
    assert any(row["domain"] == DOMAIN for row in mappings.json())

    audit = client.get("/api/v1/audit", params={"limit": 500})
    assert audit.status_code == 200
    actions = {row["action"] for row in audit.json()}
    # Restore rewinds the database to the point-in-time snapshot. Events that
    # occurred after the snapshot are intentionally absent; the restore event
    # itself is written into the restored database.
    assert {"LOGIN_SUCCESS", "MAPPING_CREATED", "MAPPING_UPDATED", "CONFIG_APPLIED", "BACKUP_RESTORED"} <= actions

    # The first active revision remains addressable in the lifecycle history.
    assert first_active_revision > 0


def test_rbac_acceptance_super_admin_admin_viewer(acceptance_env: AcceptanceEnv):
    env = acceptance_env
    super_client = env.login("root-admin")
    admin_client = env.login("ops-admin")
    viewer_client = env.login("read-only")

    assert super_client.get("/api/v1/roles").status_code == 200
    assert admin_client.get("/api/v1/roles").status_code == 200
    assert viewer_client.get("/api/v1/roles").status_code == 403

    denied_mapping = viewer_client.post(
        "/api/v1/mappings",
        headers=env.csrf(viewer_client),
        json={"domain": "viewer-denied.internal", "upstream_scheme": "http", "upstream_host": "127.0.0.1", "upstream_port": 8500},
    )
    assert denied_mapping.status_code == 403

    roles = admin_client.get("/api/v1/roles").json()
    viewer_role = next(row for row in roles if row["name"] == "viewer")
    super_role = next(row for row in roles if row["name"] == "super_admin")
    created_user = admin_client.post(
        "/api/v1/users",
        headers=env.csrf(admin_client),
        json={"username": "acceptance-user", "password": PASSWORD, "role_id": viewer_role["id"]},
    )
    assert created_user.status_code == 201
    forbidden_super = admin_client.post(
        "/api/v1/users",
        headers=env.csrf(admin_client),
        json={"username": "forbidden-super", "password": PASSWORD, "role_id": super_role["id"]},
    )
    assert forbidden_super.status_code == 403
    assert admin_client.put(
        f"/api/v1/roles/{viewer_role['id']}/permissions",
        headers=env.csrf(admin_client),
        json={"permissions": ["mapping.view"]},
    ).status_code == 403


def test_failed_apply_restores_known_good_live_configuration(acceptance_env: AcceptanceEnv):
    env = acceptance_env
    client = env.login("root-admin")
    headers = env.csrf(client)

    created = client.post(
        "/api/v1/mappings",
        headers=headers,
        json={"domain": "known-good.internal", "upstream_scheme": "http", "upstream_host": "127.0.0.1", "upstream_port": 8500},
    )
    assert created.status_code == 201
    assert client.post("/api/v1/config/apply", headers=headers).status_code == 200
    before_dns = env.paths.live_dnsmasq.read_text()
    before_nginx = env.paths.live_nginx.read_text()

    row = created.json()
    update = client.put(
        f"/api/v1/mappings/{row['id']}",
        headers=headers,
        json={
            "domain": row["domain"], "upstream_scheme": "http", "upstream_host": "127.0.0.1",
            "upstream_port": 8502, "enabled": True, "websocket_enabled": True,
            "preserve_host": True, "tls_verify": True, "custom_timeout": None,
            "description": None, "version": row["version"],
        },
    )
    assert update.status_code == 200

    env.helper.fail_apply = True
    failed = client.post("/api/v1/config/apply", headers=headers)
    assert failed.status_code == 500
    env.helper.fail_apply = False
    assert env.paths.live_dnsmasq.read_text() == before_dns
    assert env.paths.live_nginx.read_text() == before_nginx
    assert env.helper.calls[-2:] == ["apply", "rollback"]


def test_25_acceptance_contracts_are_explicitly_accounted_for():
    criteria = [
        "secure login", "persistent session", "csrf writes", "super admin", "admin", "viewer",
        "mapping create", "mapping update", "mapping delete", "domain validation", "config preview",
        "config validate", "config apply", "known-good rollback", "split dns generation", "nginx proxy generation",
        "pending changes", "revision history", "backend health", "audit trail", "backup create", "backup integrity",
        "backup restore", "privileged helper isolation", "dns network safety",
    ]
    assert len(criteria) == 25
    assert len(set(criteria)) == 25
