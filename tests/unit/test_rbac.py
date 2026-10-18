from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool
from starlette.requests import Request

from app.database import Base
from app.models.auth import Permission, Role, User


ALL_PERMISSIONS = {
    "mapping.view",
    "mapping.create",
    "mapping.update",
    "mapping.delete",
    "config.apply",
    "config.rollback",
    "user.view",
    "user.create",
    "user.update",
    "user.delete",
    "role.view",
    "role.manage",
    "audit.view",
    "system.view",
    "system.manage",
    "backup.create",
    "backup.restore",
    "firewall.manage",
}


def make_user(role_name: str, permissions: set[str], *, active: bool = True) -> User:
    role = Role(name=role_name, description=role_name)
    role.permissions = [Permission(name=name) for name in sorted(permissions)]
    return User(
        username=f"{role_name}_user",
        password_hash="not-used-here",
        is_active=active,
        role=role,
    )


def test_super_admin_has_every_defined_permission():
    from app.services.auth_service import has_permission

    user = make_user("super_admin", ALL_PERMISSIONS)
    assert all(has_permission(user, permission) for permission in ALL_PERMISSIONS)


def test_admin_can_manage_mappings_and_apply_but_not_roles_or_restore():
    from app.services.auth_service import has_permission

    allowed = {
        "mapping.view",
        "mapping.create",
        "mapping.update",
        "mapping.delete",
        "config.apply",
        "audit.view",
        "system.view",
        "user.view",
        "user.create",
        "user.update",
        "user.delete",
        "role.view",
    }
    user = make_user("admin", allowed)

    assert has_permission(user, "mapping.create") is True
    assert has_permission(user, "mapping.delete") is True
    assert has_permission(user, "config.apply") is True
    assert has_permission(user, "user.create") is True
    assert has_permission(user, "user.delete") is True
    assert has_permission(user, "role.view") is True
    assert has_permission(user, "role.manage") is False
    assert has_permission(user, "backup.restore") is False
    assert has_permission(user, "config.rollback") is False


def test_viewer_cannot_perform_writes():
    from app.services.auth_service import has_permission

    user = make_user("viewer", {"mapping.view", "audit.view", "system.view"})

    assert has_permission(user, "mapping.view") is True
    assert has_permission(user, "mapping.create") is False
    assert has_permission(user, "config.apply") is False


def test_seed_default_rbac_creates_exact_roles_and_permissions():
    from app.services.auth_service import seed_default_rbac

    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)

    with Session(engine) as db:
        seed_default_rbac(db)
        roles = {role.name: {p.name for p in role.permissions} for role in db.query(Role).all()}

    assert set(roles) == {"super_admin", "admin", "viewer"}
    assert roles["super_admin"] == ALL_PERMISSIONS
    assert roles["admin"] == {
        "mapping.view",
        "mapping.create",
        "mapping.update",
        "mapping.delete",
        "config.apply",
        "audit.view",
        "system.view",
        "user.view",
        "user.create",
        "user.update",
        "user.delete",
        "role.view",
    }
    assert roles["viewer"] == {"mapping.view", "audit.view", "system.view"}


def test_disabled_user_session_is_rejected_on_next_request():
    from app.dependencies import get_current_user
    from app.services.auth_service import seed_default_rbac

    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)

    with Session(engine) as db:
        seed_default_rbac(db)
        role = db.query(Role).filter_by(name="admin").one()
        user = User(username="alice", password_hash="x", role=role, is_active=True)
        db.add(user)
        db.commit()
        db.refresh(user)
        user_id = user.id

        scope = {
            "type": "http",
            "method": "GET",
            "path": "/",
            "headers": [],
            "query_string": b"",
            "server": ("testserver", 80),
            "client": ("127.0.0.1", 12345),
            "scheme": "http",
            "session": {"user_id": user_id},
        }
        request = Request(scope)
        assert get_current_user(request, db).id == user_id

        user.is_active = False
        db.commit()
        db.expire_all()

        with pytest.raises(HTTPException) as exc:
            get_current_user(request, db)

    assert exc.value.status_code == 403


def test_require_permission_denies_missing_permission():
    from app.dependencies import require_permission

    user = make_user("viewer", {"mapping.view"})
    dependency = require_permission("mapping.create")

    with pytest.raises(HTTPException) as exc:
        dependency(user)

    assert exc.value.status_code == 403
