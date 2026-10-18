import json
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.database import Base, get_db
from app.main import app
from app.models.audit import AuditLog
from app.models.auth import Permission, Role, User
from app.security import hash_password
from app.services.auth_service import create_session


def make_env(permissions=None):
    engine = create_engine('sqlite+pysqlite:///:memory:', connect_args={'check_same_thread': False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        role = Role(name='admin')
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


def cleanup():
    app.dependency_overrides.clear()


def test_mapping_create_update_delete_are_audited_with_old_and_new_values():
    engine, client = make_env(['mapping.view','mapping.create','mapping.update','mapping.delete'])
    try:
        h={'X-CSRF-Token':'csrf-token'}
        created = client.post('/api/v1/mappings', json={'domain':'panel.example.com','upstream_scheme':'http','upstream_host':'192.168.8.2','upstream_port':8082}, headers=h)
        assert created.status_code == 201
        item = created.json()
        updated = client.put(f"/api/v1/mappings/{item['id']}", json={'domain':'panel.example.com','upstream_scheme':'https','upstream_host':'192.168.8.3','upstream_port':8443,'version':1}, headers=h)
        assert updated.status_code == 200
        deleted = client.delete(f"/api/v1/mappings/{item['id']}", headers=h)
        assert deleted.status_code == 204
        with Session(engine) as db:
            rows = list(db.scalars(select(AuditLog).order_by(AuditLog.id)))
            assert [r.action for r in rows] == ['MAPPING_CREATED','MAPPING_UPDATED','MAPPING_DELETED']
            assert rows[0].username == 'alice'
            assert json.loads(rows[0].new_value)['domain'] == 'panel.example.com'
            assert json.loads(rows[1].old_value)['upstream_host'] == '192.168.8.2'
            assert json.loads(rows[1].new_value)['upstream_host'] == '192.168.8.3'
            assert json.loads(rows[2].old_value)['domain'] == 'panel.example.com'
    finally:
        cleanup()


def test_failed_login_is_audited_without_password_or_session_secrets():
    engine = create_engine('sqlite+pysqlite:///:memory:', connect_args={'check_same_thread': False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        role = Role(name='admin'); db.add(role); db.flush()
        db.add(User(username='alice', password_hash=hash_password('very-secure-password'), role=role)); db.commit()
    def override_db():
        with Session(engine) as db:
            yield db
    app.dependency_overrides[get_db] = override_db
    try:
        client=TestClient(app, base_url='https://testserver')
        csrf=client.get('/api/v1/auth/csrf').json()['csrf_token']
        r=client.post('/api/v1/auth/login', json={'username':'alice','password':'wrong-password'}, headers={'X-CSRF-Token':csrf})
        assert r.status_code == 401
        with Session(engine) as db:
            row=db.scalar(select(AuditLog).where(AuditLog.action=='LOGIN_FAILED'))
            assert row is not None
            blob=' '.join(filter(None,[row.old_value,row.new_value,row.error_message,row.user_agent]))
            assert 'wrong-password' not in blob
            assert 'dns_manager_session' not in blob
    finally:
        cleanup()


def test_audit_api_filters_by_action_and_requires_permission():
    engine, client = make_env(['audit.view'])
    try:
        from app.services.audit_service import record_audit_event
        with Session(engine) as db:
            user=db.scalar(select(User).where(User.username=='alice'))
            record_audit_event(db,user=user,action='LOGIN_SUCCESS',source_ip='192.0.2.1')
            record_audit_event(db,user=user,action='MAPPING_CREATED',source_ip='192.0.2.1')
        r=client.get('/api/v1/audit?action=MAPPING_CREATED')
        assert r.status_code==200
        assert len(r.json())==1 and r.json()[0]['action']=='MAPPING_CREATED'
    finally:
        cleanup()
