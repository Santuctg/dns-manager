from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.database import Base, get_db
from app.main import app
from app.models.auth import LoginAttempt, Role, User


def make_db():
    engine = create_engine("sqlite+pysqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    return engine


def test_password_hash_uses_argon2id_and_verifies():
    from app.security import hash_password, verify_password
    encoded = hash_password("correct horse battery staple")
    assert encoded.startswith("$argon2id$")
    assert verify_password(encoded, "correct horse battery staple") is True
    assert verify_password(encoded, "wrong") is False


def test_login_sets_secure_server_session_cookie():
    from app.security import hash_password
    engine = make_db()
    with Session(engine) as db:
        role = Role(name="admin")
        db.add(role); db.flush()
        db.add(User(username="alice", password_hash=hash_password("very-secure-password"), role=role))
        db.commit()

    def override_db():
        with Session(engine) as db:
            yield db
    app.dependency_overrides[get_db] = override_db
    try:
        client = TestClient(app, base_url="https://testserver")
        csrf = client.get("/api/v1/auth/csrf").json()["csrf_token"]
        response = client.post("/api/v1/auth/login", json={"username":"alice","password":"very-secure-password"}, headers={"X-CSRF-Token": csrf})
        assert response.status_code == 200
        cookie = response.headers.get("set-cookie", "")
        assert "dns_manager_session=" in cookie
        assert "HttpOnly" in cookie
        assert "Secure" in cookie
        assert "SameSite=lax" in cookie
    finally:
        app.dependency_overrides.clear()


def test_tenth_failed_account_login_locks_for_15_minutes():
    from app.services.auth_service import register_failed_login
    engine = make_db()
    now = datetime.now(timezone.utc)
    with Session(engine) as db:
        role = Role(name="admin"); db.add(role); db.flush()
        user = User(username="alice", password_hash="x", role=role)
        db.add(user); db.commit()
        for _ in range(10):
            register_failed_login(db, user, "192.0.2.10", now=now)
        db.refresh(user)
        assert user.failed_login_count == 10
        locked = user.locked_until
        if locked.tzinfo is None:
            locked = locked.replace(tzinfo=timezone.utc)
        assert locked >= now + timedelta(minutes=15)


def test_five_failed_attempts_from_ip_in_10_minutes_are_throttled():
    from app.services.auth_service import ip_is_rate_limited
    engine = make_db(); now = datetime.now(timezone.utc)
    with Session(engine) as db:
        for _ in range(5):
            db.add(LoginAttempt(ip_address="192.0.2.10", username="alice", success=False, created_at=now))
        db.commit()
        assert ip_is_rate_limited(db, "192.0.2.10", now=now) is True
