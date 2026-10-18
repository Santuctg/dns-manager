from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool
from cryptography.fernet import Fernet

from app.database import Base, get_db
from app.main import app
from app.models.auth import Permission, Role, User
from app.models.ssl import SslCertificate
from app.models.hosted_acme import SslHostedAcmeCredential
from app.security import hash_password
from app.services.auth_service import create_session
from app.services.ssl_crypto import load_ssl_secret_key, decrypt_secret
from app.config import HostedAcmeConfig
from app.services.hosted_acme_service import HostedAcmeRegistration


def env(monkeypatch, tmp_path, role_name='super_admin'):
    key = tmp_path/'key'; key.write_bytes(Fernet.generate_key())
    monkeypatch.setenv('DNS_MANAGER_SSL_SECRET_KEY_FILE', str(key)); load_ssl_secret_key.cache_clear()
    engine=create_engine('sqlite+pysqlite:///:memory:',connect_args={'check_same_thread':False},poolclass=StaticPool)
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        p=Permission(name='system.view'); role=Role(name=role_name,permissions=[p]); db.add_all([p,role]); db.flush()
        u=User(username='actor',password_hash=hash_password('very-secure-password'),role=role); db.add(u); db.flush()
        sid=create_session(db,u,'csrf-token'); db.add(SslCertificate(domain='example.com',provider='manual',status='ISSUED')); db.commit()
    def odb():
        with Session(engine) as db: yield db
    app.dependency_overrides[get_db]=odb
    c=TestClient(app,base_url='https://testserver'); c.cookies.set('dns_manager_session',sid); c.cookies.set('dns_manager_csrf','csrf-token')
    monkeypatch.setattr('app.api.ssl.load_hosted_acme_config', lambda: HostedAcmeConfig(enabled=True))
    return engine,c


def test_register_converts_manual_without_reissuing_and_hides_credentials(monkeypatch,tmp_path):
    engine,c=env(monkeypatch,tmp_path)
    secret_user='user-secret-123'; secret_pass='pass-secret-456'
    monkeypatch.setattr('app.api.ssl.HostedAcmeClient.register', lambda self: HostedAcmeRegistration(secret_user,secret_pass,'abc123','abc123.auth.acme-dns.io'))
    try:
        r=c.post('/api/v1/ssl/certificates/example.com/hosted-acme/register',headers={'X-CSRF-Token':'csrf-token'})
        assert r.status_code==200, r.text
        body=r.json(); text=r.text
        assert body['provider']=='acme_dns_hosted'
        assert body['challenge_domain']=='_acme-challenge.example.com'
        assert body['fulldomain']=='abc123.auth.acme-dns.io'
        assert secret_user not in text and secret_pass not in text
        with Session(engine) as db:
            cert=db.query(SslCertificate).filter_by(domain='example.com').one()
            assert cert.provider=='acme_dns_hosted'
            assert cert.status=='ISSUED'
            assert cert.auto_renew is False
            assert cert.last_renewal_status is None
            cred=db.query(SslHostedAcmeCredential).one()
            assert decrypt_secret(cred.username_ciphertext)==secret_user
            assert decrypt_secret(cred.password_ciphertext)==secret_pass
    finally: app.dependency_overrides.clear()


def test_registration_rejects_non_manual_provider(monkeypatch,tmp_path):
    engine,c=env(monkeypatch,tmp_path)
    with Session(engine) as db:
        cert=db.query(SslCertificate).one(); cert.provider='cloudflare'; db.commit()
    try:
        r=c.post('/api/v1/ssl/certificates/example.com/hosted-acme/register',headers={'X-CSRF-Token':'csrf-token'})
        assert r.status_code==409
    finally: app.dependency_overrides.clear()


def test_registration_requires_csrf(monkeypatch,tmp_path):
    _engine,c=env(monkeypatch,tmp_path)
    try:
        r=c.post('/api/v1/ssl/certificates/example.com/hosted-acme/register')
        assert r.status_code==403
    finally: app.dependency_overrides.clear()


def test_verify_hosted_cname_marks_registration_verified(monkeypatch,tmp_path):
    engine,c=env(monkeypatch,tmp_path)
    monkeypatch.setattr('app.api.ssl.HostedAcmeClient.register', lambda self: HostedAcmeRegistration('u','p','abc','abc.auth.acme-dns.io'))
    monkeypatch.setattr('app.api.ssl.verify_hosted_cname', lambda challenge, expected, resolvers=('1.1.1.1','8.8.8.8'): {'verified': True, 'observed':[expected], 'error':None})
    try:
        assert c.post('/api/v1/ssl/certificates/example.com/hosted-acme/register',headers={'X-CSRF-Token':'csrf-token'}).status_code==200
        r=c.post('/api/v1/ssl/certificates/example.com/hosted-acme/verify',headers={'X-CSRF-Token':'csrf-token'})
        assert r.status_code==200, r.text
        assert r.json()['verified'] is True
        with Session(engine) as db:
            assert db.query(SslHostedAcmeCredential).one().verified is True
    finally: app.dependency_overrides.clear()


def test_verify_hosted_cname_mismatch_keeps_unverified(monkeypatch,tmp_path):
    _engine,c=env(monkeypatch,tmp_path)
    monkeypatch.setattr('app.api.ssl.HostedAcmeClient.register', lambda self: HostedAcmeRegistration('u','p','abc','abc.auth.acme-dns.io'))
    monkeypatch.setattr('app.api.ssl.verify_hosted_cname', lambda *a,**k: {'verified': False, 'observed':['wrong.example.net'], 'error':'CNAME mismatch'})
    try:
        c.post('/api/v1/ssl/certificates/example.com/hosted-acme/register',headers={'X-CSRF-Token':'csrf-token'})
        r=c.post('/api/v1/ssl/certificates/example.com/hosted-acme/verify',headers={'X-CSRF-Token':'csrf-token'})
        assert r.status_code==200
        assert r.json()['verified'] is False
        assert r.json()['last_verification_error']=='CNAME mismatch'
    finally: app.dependency_overrides.clear()


def test_hosted_auto_renew_requires_verify_and_test_success(monkeypatch,tmp_path):
    engine,c=env(monkeypatch,tmp_path)
    monkeypatch.setattr('app.api.ssl.HostedAcmeClient.register', lambda self: HostedAcmeRegistration('u','p','abc','abc.auth.acme-dns.io'))
    try:
        c.post('/api/v1/ssl/certificates/example.com/hosted-acme/register',headers={'X-CSRF-Token':'csrf-token'})
        r=c.put('/api/v1/ssl/settings/example.com',headers={'X-CSRF-Token':'csrf-token'},json={'auto_renew':True})
        assert r.status_code==409
        with Session(engine) as db:
            cert=db.query(SslCertificate).one(); cert.hosted_acme.verified=True; cert.last_renewal_status='TEST_SUCCESS'; db.commit()
        r=c.put('/api/v1/ssl/settings/example.com',headers={'X-CSRF-Token':'csrf-token'},json={'auto_renew':True})
        assert r.status_code==200, r.text
        assert r.json()['auto_renew'] is True
    finally: app.dependency_overrides.clear()


def test_reregister_resets_verification_and_auto_renew(monkeypatch,tmp_path):
    engine,c=env(monkeypatch,tmp_path)
    regs=iter([
        HostedAcmeRegistration('u1','p1','abc','abc.auth.acme-dns.io'),
        HostedAcmeRegistration('u2','p2','def','def.auth.acme-dns.io'),
    ])
    monkeypatch.setattr('app.api.ssl.HostedAcmeClient.register', lambda self: next(regs))
    try:
        c.post('/api/v1/ssl/certificates/example.com/hosted-acme/register',headers={'X-CSRF-Token':'csrf-token'})
        with Session(engine) as db:
            cert=db.query(SslCertificate).one(); cert.hosted_acme.verified=True; cert.last_renewal_status='TEST_SUCCESS'; cert.auto_renew=True;
            from datetime import datetime, timezone, timedelta
            cert.hosted_acme.updated_at=datetime.now(timezone.utc)-timedelta(seconds=61); db.commit()
        r=c.post('/api/v1/ssl/certificates/example.com/hosted-acme/register',headers={'X-CSRF-Token':'csrf-token'})
        assert r.status_code==200, r.text
        assert r.json()['fulldomain']=='def.auth.acme-dns.io'
        assert r.json()['verified'] is False
        assert r.json()['auto_renew'] is False
        assert r.json()['last_renewal_status'] is None
    finally: app.dependency_overrides.clear()


def test_delete_hosted_credentials_is_explicit_and_reverts_provider(monkeypatch,tmp_path):
    engine,c=env(monkeypatch,tmp_path)
    monkeypatch.setattr('app.api.ssl.HostedAcmeClient.register', lambda self: HostedAcmeRegistration('u','p','abc','abc.auth.acme-dns.io'))
    try:
        c.post('/api/v1/ssl/certificates/example.com/hosted-acme/register',headers={'X-CSRF-Token':'csrf-token'})
        r=c.delete('/api/v1/ssl/certificates/example.com/hosted-acme',headers={'X-CSRF-Token':'csrf-token'})
        assert r.status_code==200, r.text
        with Session(engine) as db:
            cert=db.query(SslCertificate).one()
            assert cert.provider=='manual'
            assert cert.hosted_acme is None
    finally: app.dependency_overrides.clear()


def test_hosted_reregistration_has_sixty_second_cooldown(monkeypatch,tmp_path):
    _engine,c=env(monkeypatch,tmp_path)
    monkeypatch.setattr('app.api.ssl.HostedAcmeClient.register', lambda self: HostedAcmeRegistration('u','p','abc','abc.auth.acme-dns.io'))
    try:
        assert c.post('/api/v1/ssl/certificates/example.com/hosted-acme/register',headers={'X-CSRF-Token':'csrf-token'}).status_code==200
        second=c.post('/api/v1/ssl/certificates/example.com/hosted-acme/register',headers={'X-CSRF-Token':'csrf-token'})
        assert second.status_code==429
    finally: app.dependency_overrides.clear()
