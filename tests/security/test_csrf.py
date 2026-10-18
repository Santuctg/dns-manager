from fastapi.testclient import TestClient
from app.main import app


def test_login_without_csrf_is_rejected():
    client = TestClient(app, base_url="https://testserver")
    response = client.post("/api/v1/auth/login", json={"username":"x","password":"y"})
    assert response.status_code == 403


def test_csrf_endpoint_sets_secure_cookie():
    client = TestClient(app, base_url="https://testserver")
    response = client.get("/api/v1/auth/csrf")
    assert response.status_code == 200
    token = response.json()["csrf_token"]
    assert len(token) >= 32
    cookie = response.headers.get("set-cookie", "")
    assert "dns_manager_csrf=" in cookie
    assert "Secure" in cookie
    assert "SameSite=lax" in cookie


def test_logout_without_csrf_is_rejected():
    client = TestClient(app, base_url="https://testserver")
    response = client.post("/api/v1/auth/logout")
    assert response.status_code == 403
