from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.database import Base, get_db
from app.main import app
from app.models.auth import Permission, Role, User
from app.security import hash_password
from app.services.auth_service import create_session


def make_env(role_name='admin', permissions=None):
    engine = create_engine('sqlite+pysqlite:///:memory:', connect_args={'check_same_thread': False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        role = Role(name=role_name)
        for name in permissions or []:
            p = Permission(name=name); db.add(p); role.permissions.append(p)
        user = User(username='alice', password_hash=hash_password('very-secure-password'), role=role)
        db.add_all([role, user]); db.commit(); db.refresh(user)
        session = create_session(db, user, 'csrf-token')
    def override_db():
        with Session(engine) as db:
            yield db
    app.dependency_overrides[get_db] = override_db
    client = TestClient(app, base_url='https://testserver')
    client.cookies.set('dns_manager_session', session)
    client.cookies.set('dns_manager_csrf', 'csrf-token')
    return engine, client


def cleanup(): app.dependency_overrides.clear()


def test_admin_can_create_list_update_and_delete_mapping():
    _, client = make_env(permissions=['mapping.view','mapping.create','mapping.update','mapping.delete'])
    try:
        r = client.post('/api/v1/mappings', json={'domain':'Panel.Example.com','upstream_scheme':'http','upstream_host':'192.168.8.2','upstream_port':8082}, headers={'X-CSRF-Token':'csrf-token'})
        assert r.status_code == 201
        item = r.json(); assert item['domain'] == 'panel.example.com'; assert item['version'] == 1
        assert client.get('/api/v1/mappings').status_code == 200
        r2 = client.put(f"/api/v1/mappings/{item['id']}", json={'domain':'panel.example.com','upstream_scheme':'https','upstream_host':'192.168.8.3','upstream_port':8443,'version':1}, headers={'X-CSRF-Token':'csrf-token'})
        assert r2.status_code == 200 and r2.json()['version'] == 2
        r3 = client.delete(f"/api/v1/mappings/{item['id']}", headers={'X-CSRF-Token':'csrf-token'})
        assert r3.status_code == 204
    finally: cleanup()


def test_case_insensitive_duplicate_domain_is_conflict():
    _, client = make_env(permissions=['mapping.create'])
    try:
        h={'X-CSRF-Token':'csrf-token'}
        p={'domain':'panel.example.com','upstream_scheme':'http','upstream_host':'192.168.8.2','upstream_port':8082}
        assert client.post('/api/v1/mappings', json=p, headers=h).status_code == 201
        p['domain']='PANEL.EXAMPLE.COM'
        assert client.post('/api/v1/mappings', json=p, headers=h).status_code == 409
    finally: cleanup()


def test_viewer_cannot_create_mapping():
    _, client = make_env(role_name='viewer', permissions=['mapping.view'])
    try:
        r=client.post('/api/v1/mappings', json={'domain':'x.example.com','upstream_scheme':'http','upstream_host':'192.168.8.2','upstream_port':80}, headers={'X-CSRF-Token':'csrf-token'})
        assert r.status_code == 403
    finally: cleanup()


def test_stale_version_update_returns_conflict():
    _, client = make_env(permissions=['mapping.create','mapping.update'])
    try:
        h={'X-CSRF-Token':'csrf-token'}
        r=client.post('/api/v1/mappings', json={'domain':'x.example.com','upstream_scheme':'http','upstream_host':'192.168.8.2','upstream_port':80}, headers=h)
        mid=r.json()['id']
        payload={'domain':'x.example.com','upstream_scheme':'http','upstream_host':'192.168.8.3','upstream_port':81,'version':1}
        assert client.put(f'/api/v1/mappings/{mid}', json=payload, headers=h).status_code == 200
        assert client.put(f'/api/v1/mappings/{mid}', json=payload, headers=h).status_code == 409
    finally: cleanup()
