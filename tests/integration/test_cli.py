from __future__ import annotations

import builtins
from io import StringIO

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app.models.auth import Role, User
from app.security import verify_password


def make_db(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'cli.db'}")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, expire_on_commit=False)
    db = Session()
    db.add(Role(name="super_admin", description="Super Admin"))
    db.commit()
    return db


def test_create_superadmin_creates_active_super_admin(tmp_path):
    from app.cli import create_superadmin

    db = make_db(tmp_path)
    user = create_superadmin(
        db,
        username="admin",
        email="Admin@Example.com",
        password="A-very-strong-password-123",
    )

    persisted = db.scalar(select(User).where(User.username == "admin"))
    assert persisted is not None
    assert persisted.id == user.id
    assert persisted.is_active is True
    assert persisted.role.name == "super_admin"
    assert persisted.email == "admin@example.com"
    assert persisted.password_hash != "A-very-strong-password-123"
    assert verify_password(persisted.password_hash, "A-very-strong-password-123") is True


def test_create_superadmin_rejects_duplicate_username(tmp_path):
    from app.cli import create_superadmin

    db = make_db(tmp_path)
    create_superadmin(db, "admin", "a@example.com", "A-very-strong-password-123")

    with pytest.raises(ValueError, match="username already exists"):
        create_superadmin(db, "admin", "b@example.com", "Another-strong-password-456")


def test_reset_password_replaces_hash_and_unlocks_user(tmp_path):
    from app.cli import create_superadmin, reset_password

    db = make_db(tmp_path)
    user = create_superadmin(db, "admin", "a@example.com", "A-very-strong-password-123")
    user.failed_login_count = 10
    from datetime import datetime, timedelta, timezone
    user.locked_until = datetime.now(timezone.utc) + timedelta(minutes=15)
    db.commit()
    old_hash = user.password_hash

    reset_password(db, "admin", "New-very-strong-password-789")
    db.refresh(user)

    assert user.password_hash != old_hash
    assert verify_password(user.password_hash, "New-very-strong-password-789") is True
    assert user.failed_login_count == 0
    assert user.locked_until is None


def test_cli_password_prompt_does_not_echo_or_accept_password_argv(tmp_path, monkeypatch, capsys):
    import app.cli as cli

    db = make_db(tmp_path)
    monkeypatch.setattr(cli, "get_db_session", lambda: db)
    answers = iter(["admin", "admin@example.com"])
    monkeypatch.setattr(builtins, "input", lambda _prompt="": next(answers))
    prompts = []
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt: prompts.append(prompt) or "A-very-strong-password-123")

    rc = cli.main(["create-superadmin"])
    output = capsys.readouterr().out

    assert rc == 0
    assert "A-very-strong-password-123" not in output
    assert len(prompts) == 2  # password + confirmation

    with pytest.raises(SystemExit):
        cli.main(["create-superadmin", "--password", "unsafe"])


def test_get_db_session_is_bound_to_configured_database(tmp_path, monkeypatch):
    import app.cli as cli
    import app.config as config
    import app.database as database

    db_path = tmp_path / "configured.db"
    monkeypatch.setenv("DNS_MANAGER_DATABASE_PATH", str(db_path))
    config.get_settings.cache_clear()
    database.get_engine.cache_clear()

    db = cli.get_db_session()
    try:
        assert db.get_bind() is database.get_engine()
    finally:
        db.close()
        config.get_settings.cache_clear()
        database.get_engine.cache_clear()
