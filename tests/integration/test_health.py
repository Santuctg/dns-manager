from __future__ import annotations

import socket
import socketserver
import ssl
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.database import Base, get_db
from app.main import app
from app.models.auth import Permission, Role, User
from app.models.mapping import Mapping
from app.security import hash_password
from app.services.auth_service import create_session


class _Handler(BaseHTTPRequestHandler):
    status = 200

    def do_HEAD(self):
        self.send_response(self.status)
        self.end_headers()

    def log_message(self, *_args):
        pass


class _ThreadedServer:
    def __init__(self, handler=_Handler):
        self.server = HTTPServer(("127.0.0.1", 0), handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def port(self):
        return self.server.server_address[1]

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_args):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=1)


class _SlowHandler(socketserver.BaseRequestHandler):
    def handle(self):
        time.sleep(0.5)


class _SlowServer:
    def __init__(self):
        self.server = socketserver.TCPServer(("127.0.0.1", 0), _SlowHandler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def port(self):
        return self.server.server_address[1]

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_args):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=1)


def _mapping(port: int, scheme: str = "http", tls_verify: bool = True) -> Mapping:
    return Mapping(
        id=1,
        domain="backend.example.com",
        upstream_scheme=scheme,
        upstream_host="127.0.0.1",
        upstream_port=port,
        tls_verify=tls_verify,
        enabled=True,
    )


def test_backend_health_reports_up_for_reachable_http():
    from app.services.health_service import check_backend

    with _ThreadedServer() as server:
        result = check_backend(_mapping(server.port), timeout=0.5)

    assert result["status"] == "UP"
    assert result["http_status"] == 200
    assert result["latency_ms"] >= 0


def test_backend_health_reports_http_error_for_5xx():
    from app.services.health_service import check_backend

    class ErrorHandler(_Handler):
        status = 503

    with _ThreadedServer(ErrorHandler) as server:
        result = check_backend(_mapping(server.port), timeout=0.5)

    assert result["status"] == "HTTP_ERROR"
    assert result["http_status"] == 503


def test_backend_health_reports_down_for_refused_connection():
    from app.services.health_service import check_backend

    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()

    result = check_backend(_mapping(port), timeout=0.2)
    assert result["status"] == "DOWN"


def test_backend_health_reports_timeout_when_backend_accepts_but_does_not_respond():
    from app.services.health_service import check_backend

    with _SlowServer() as server:
        result = check_backend(_mapping(server.port), timeout=0.1)

    assert result["status"] == "TIMEOUT"


def test_backend_health_reports_tls_error_for_plaintext_on_https_port():
    from app.services.health_service import check_backend

    with _ThreadedServer() as server:
        result = check_backend(_mapping(server.port, scheme="https"), timeout=0.5)

    assert result["status"] == "TLS_ERROR"


def _api_env():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        role = Role(name="viewer")
        permission = Permission(name="system.view")
        role.permissions.append(permission)
        user = User(username="health-viewer", password_hash=hash_password("very-secure-password"), role=role)
        mapping = Mapping(
            domain="backend.example.com",
            upstream_scheme="http",
            upstream_host="127.0.0.1",
            upstream_port=8080,
            enabled=True,
        )
        db.add_all([role, user, mapping])
        db.commit()
        db.refresh(user)
        raw = create_session(db, user, "csrf-token")

    def override_db():
        with Session(engine) as db:
            yield db

    app.dependency_overrides[get_db] = override_db
    client = TestClient(app, base_url="https://testserver")
    client.cookies.set("dns_manager_session", raw)
    return client


def test_system_status_api_requires_permission_and_returns_service_port_state(monkeypatch):
    import app.api.system as system_api

    client = _api_env()
    monkeypatch.setattr(
        system_api,
        "get_system_status",
        lambda: {
            "status": "ready",
            "database": "ok",
            "dnsmasq": "active",
            "nginx": "active",
            "ports": {"53": True, "80": True, "443": False},
        },
    )
    try:
        response = client.get("/api/v1/system/status")
        assert response.status_code == 200
        assert response.json()["ports"] == {"53": True, "80": True, "443": False}
    finally:
        app.dependency_overrides.clear()


def test_ready_returns_503_when_required_service_is_not_ready(monkeypatch):
    import app.api.system as system_api

    monkeypatch.setattr(
        system_api,
        "get_system_status",
        lambda: {
            "status": "not_ready",
            "database": "ok",
            "dnsmasq": "failed",
            "nginx": "active",
            "ports": {"53": False, "80": True, "443": False},
        },
    )
    client = TestClient(app)
    response = client.get("/ready")
    assert response.status_code == 503
    assert response.json()["status"] == "not_ready"


def test_backend_status_api_returns_mapping_reachability(monkeypatch):
    import app.api.system as system_api

    client = _api_env()
    monkeypatch.setattr(
        system_api,
        "check_backend",
        lambda mapping: {
            "mapping_id": mapping.id,
            "domain": mapping.domain,
            "status": "UP",
            "latency_ms": 1.5,
            "http_status": 200,
            "detail": None,
        },
    )
    try:
        response = client.get("/api/v1/system/backends")
        assert response.status_code == 200
        payload = response.json()
        assert payload[0]["domain"] == "backend.example.com"
        assert payload[0]["status"] == "UP"
    finally:
        app.dependency_overrides.clear()


def test_acme_dns_disabled_does_not_change_core_readiness(monkeypatch):
    import app.services.health_service as hs
    from app.config import AcmeDnsConfig
    class H:
        def status(self): return {'dnsmasq':'active','nginx':'active'}
        def acme_dns_status(self): return {'configured':False,'service':'disabled','zone':None,'zone_loaded':False,'listen_ip':None,'listen_port':53,'tcp_53':False,'udp_53':False}
    monkeypatch.setattr(hs,'database_health',lambda:'ok')
    monkeypatch.setattr(hs,'get_dns_safety_status',lambda:{'safe':True})
    monkeypatch.setattr(hs,'_port_open',lambda *a,**k:True)
    result=hs.get_system_status(H())
    assert result['status']=='ready'
    assert result['acme_dns']['configured'] is False


def test_acme_dns_enabled_reports_authoritative_health(monkeypatch):
    import app.services.health_service as hs
    from app.config import AcmeDnsConfig
    class H:
        def status(self): return {'dnsmasq':'active','nginx':'active'}
        def acme_dns_status(self): return {'configured':True,'service':'active','zone':'acme-dns.connect3.net.bd','zone_loaded':True,'listen_ip':'203.0.113.5','listen_port':5353,'tcp_53':True,'udp_53':True}
    monkeypatch.setattr(hs,'database_health',lambda:'ok')
    monkeypatch.setattr(hs,'get_dns_safety_status',lambda:{'safe':True})
    monkeypatch.setattr(hs,'_port_open',lambda *a,**k:True)
    result=hs.get_system_status(H())
    assert result['status']=='ready'
    assert result['acme_dns']['configured'] is True
    assert result['acme_dns']['service']=='active'
    assert result['acme_dns']['zone_loaded'] is True
    assert result['acme_dns']['listen_port'] == 5353


def test_hosted_acme_unreachable_does_not_change_core_readiness(monkeypatch):
    import app.services.health_service as hs
    class H:
        def status(self): return {'dnsmasq':'active','nginx':'active'}
        def acme_dns_status(self): return {'configured':False,'service':'disabled','zone':None,'zone_loaded':False,'listen_ip':None,'listen_port':53,'tcp_53':False,'udp_53':False}
    monkeypatch.setattr(hs,'database_health',lambda:'ok')
    monkeypatch.setattr(hs,'get_dns_safety_status',lambda:{'safe':True})
    monkeypatch.setattr(hs,'_port_open',lambda *a,**k:True)
    monkeypatch.setattr(hs,'hosted_acme_health',lambda:{'configured':True,'server_url':'https://auth.acme-dns.io','reachable':False})
    result=hs.get_system_status(H())
    assert result['status']=='ready'
    assert result['hosted_acme_dns']['reachable'] is False
