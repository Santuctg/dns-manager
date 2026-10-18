from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.database import Base, get_db
from app.main import app
from app.models.auth import Permission, Role, User
from app.models.ssl import SslCertificate
from app.security import hash_password
from app.services.auth_service import create_session


def env(role_name='super_admin'):
    engine=create_engine('sqlite+pysqlite:///:memory:',connect_args={'check_same_thread':False},poolclass=StaticPool)
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        p=Permission(name='system.view'); db.add(p)
        role=Role(name=role_name,permissions=[p]); db.add(role); db.flush()
        u=User(username='actor',password_hash=hash_password('very-secure-password'),role=role); db.add(u); db.commit()
        sid=create_session(db,u,'csrf-token')
    def odb():
        with Session(engine) as db: yield db
    app.dependency_overrides[get_db]=odb
    c=TestClient(app,base_url='https://testserver')
    c.cookies.set('dns_manager_session',sid); c.cookies.set('dns_manager_csrf','csrf-token')
    return engine,c


def seed_manual(engine):
    with Session(engine) as db:
        db.add(SslCertificate(domain='example.com',provider='manual',status='ISSUED',auto_renew=False))
        db.commit()


def test_superadmin_can_convert_manual_certificate_to_delegation_without_reissue():
    engine,c=env(); seed_manual(engine)
    try:
        r=c.post('/api/v1/ssl/certificates/example.com/delegation',headers={'X-CSRF-Token':'csrf-token'})
        assert r.status_code==200, r.text
        body=r.json()
        assert body['domain']=='example.com'
        assert body['challenge_domain']=='_acme-challenge.example.com'
        assert body['delegated_fqdn'].endswith('.acme-dns.connect3.net.bd')
        assert body['verified'] is False
        with Session(engine) as db:
            cert=db.query(SslCertificate).filter_by(domain='example.com').one()
            assert cert.provider=='acme_delegation'
            assert cert.status=='ISSUED'
            assert cert.auto_renew is False
    finally: app.dependency_overrides.clear()


def test_delegation_identity_is_stable_on_repeat_request():
    engine,c=env(); seed_manual(engine)
    try:
        first=c.post('/api/v1/ssl/certificates/example.com/delegation',headers={'X-CSRF-Token':'csrf-token'})
        second=c.post('/api/v1/ssl/certificates/example.com/delegation',headers={'X-CSRF-Token':'csrf-token'})
        assert first.status_code==200 and second.status_code==200
        assert first.json()['delegation_id']==second.json()['delegation_id']
    finally: app.dependency_overrides.clear()


def test_verify_delegation_records_exact_public_cname(monkeypatch):
    engine,c=env(); seed_manual(engine)
    try:
        created=c.post('/api/v1/ssl/certificates/example.com/delegation',headers={'X-CSRF-Token':'csrf-token'})
        target=created.json()['delegated_fqdn']
        def fake_verify(challenge_domain, expected_target, resolvers=None):
            assert challenge_domain=='_acme-challenge.example.com'
            assert expected_target==target
            return {'verified':True,'observed':[target],'error':None}
        monkeypatch.setattr('app.api.acme_dns.verify_delegation',fake_verify)
        r=c.post('/api/v1/ssl/certificates/example.com/delegation/verify',headers={'X-CSRF-Token':'csrf-token'})
        assert r.status_code==200, r.text
        assert r.json()['verified'] is True
        assert c.get('/api/v1/ssl/certificates/example.com/delegation').json()['verified'] is True
    finally: app.dependency_overrides.clear()


def test_verify_delegation_mismatch_does_not_mark_verified(monkeypatch):
    engine,c=env(); seed_manual(engine)
    try:
        c.post('/api/v1/ssl/certificates/example.com/delegation',headers={'X-CSRF-Token':'csrf-token'})
        monkeypatch.setattr('app.api.acme_dns.verify_delegation',lambda *a,**k:{'verified':False,'observed':['wrong.example.net'],'error':'CNAME mismatch'})
        r=c.post('/api/v1/ssl/certificates/example.com/delegation/verify',headers={'X-CSRF-Token':'csrf-token'})
        assert r.status_code==200
        assert r.json()['verified'] is False
        assert r.json()['last_verification_error']=='CNAME mismatch'
    finally: app.dependency_overrides.clear()


def test_admin_cannot_create_delegation():
    engine,c=env('admin'); seed_manual(engine)
    try:
        r=c.post('/api/v1/ssl/certificates/example.com/delegation',headers={'X-CSRF-Token':'csrf-token'})
        assert r.status_code==403
    finally: app.dependency_overrides.clear()


def test_certificate_delete_preserves_acme_delegation_until_explicit_removal(monkeypatch):
    engine,c=env(); seed_manual(engine)
    try:
        created=c.post('/api/v1/ssl/certificates/example.com/delegation',headers={'X-CSRF-Token':'csrf-token'})
        delegation_id=created.json()['delegation_id']
        monkeypatch.setattr('app.api.ssl.PrivilegedHelper.ssl_delete',lambda *a,**k:{'deleted':True})
        deleted=c.delete('/api/v1/ssl/certificates/example.com',headers={'X-CSRF-Token':'csrf-token'})
        assert deleted.status_code==200, deleted.text
        assert deleted.json()['delegation_preserved'] is True
        assert c.get('/api/v1/ssl/certificates/example.com/delegation').json()['delegation_id']==delegation_id
        removed=c.delete('/api/v1/ssl/certificates/example.com/delegation',headers={'X-CSRF-Token':'csrf-token'})
        assert removed.status_code==200, removed.text
        assert c.get('/api/v1/ssl/certificates/example.com/delegation').status_code==404
        with Session(engine) as db:
            cert=db.query(SslCertificate).filter_by(domain='example.com').one()
            assert cert.provider=='manual'
    finally: app.dependency_overrides.clear()
