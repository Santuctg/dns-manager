from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.database import Base, get_db
from app.main import app
from app.models.auth import Permission, Role, User
from app.security import hash_password
from app.services.auth_service import create_session


def env(role_name='super_admin'):
    engine=create_engine('sqlite+pysqlite:///:memory:',connect_args={'check_same_thread':False},poolclass=StaticPool); Base.metadata.create_all(engine)
    with Session(engine) as db:
        p=Permission(name='system.view'); db.add(p)
        role=Role(name=role_name,permissions=[p]); db.add(role); db.flush()
        u=User(username='actor',password_hash=hash_password('very-secure-password'),role=role); db.add(u); db.commit(); sid=create_session(db,u,'csrf-token')
    def odb():
        with Session(engine) as db: yield db
    app.dependency_overrides[get_db]=odb
    c=TestClient(app,base_url='https://testserver'); c.cookies.set('dns_manager_session',sid); c.cookies.set('dns_manager_csrf','csrf-token')
    return engine,c


def test_superadmin_can_create_ssl_config_without_token_echo(monkeypatch,tmp_path):
    monkeypatch.setenv('DNS_MANAGER_SSL_SECRET_KEY_FILE',str(tmp_path/'key'))
    from cryptography.fernet import Fernet
    (tmp_path/'key').write_bytes(Fernet.generate_key())
    from app.services.ssl_crypto import load_ssl_secret_key; load_ssl_secret_key.cache_clear()
    def fake_reconcile(db, cert, **kwargs):
        cert.status='NOT_ISSUED'; db.commit(); db.refresh(cert)
        return {'domain':cert.domain,'status':'NOT_ISSUED','issuer':None,'issued_at':None,'expires_at':None,'days_remaining':None}
    monkeypatch.setattr('app.api.ssl.reconcile_certificate', fake_reconcile)
    def fake_reconcile_all(db, **kwargs):
        return []
    monkeypatch.setattr('app.api.ssl.reconcile_all_certificates', fake_reconcile_all)
    engine,c=env()
    try:
        r=c.post('/api/v1/ssl/certificates',headers={'X-CSRF-Token':'csrf-token'},json={'domain':'DNS.Example.COM','provider':'cloudflare','api_token':'secret-token-1234','auto_renew':True,'redirect_http':True})
        assert r.status_code==201, r.text
        assert r.json()['domain']=='dns.example.com'
        assert 'secret-token' not in r.text and 'ciphertext' not in r.text
        assert c.get('/api/v1/ssl/certificates').status_code==200
    finally: app.dependency_overrides.clear()


def test_admin_cannot_mutate_ssl(monkeypatch,tmp_path):
    monkeypatch.setenv('DNS_MANAGER_SSL_SECRET_KEY_FILE',str(tmp_path/'key'))
    from cryptography.fernet import Fernet
    (tmp_path/'key').write_bytes(Fernet.generate_key())
    from app.services.ssl_crypto import load_ssl_secret_key; load_ssl_secret_key.cache_clear()
    _,c=env('admin')
    try:
        assert c.post('/api/v1/ssl/certificates',headers={'X-CSRF-Token':'csrf-token'},json={'domain':'dns.example.com','provider':'manual'}).status_code==403
    finally: app.dependency_overrides.clear()


def test_ssl_list_reconciles_existing_local_certificate(monkeypatch,tmp_path):
    engine,c=env()
    try:
        from app.models.ssl import SslCertificate
        with Session(engine) as db:
            db.add(SslCertificate(domain='dns.example.com',provider='manual',status='NOT_ISSUED'))
            db.commit()

        def fake_reconcile(db, *, letsencrypt_root='/etc/letsencrypt'):
            row=db.query(SslCertificate).filter_by(domain='dns.example.com').one()
            row.status='ISSUED'
            row.issuer="CN=Let's Encrypt"
            row.expires_at=__import__('datetime').datetime(2027,1,8,tzinfo=__import__('datetime').timezone.utc)
            db.commit()
            return [{'domain':row.domain,'status':row.status}]

        monkeypatch.setattr('app.api.ssl.reconcile_all_certificates', fake_reconcile, raising=False)
        r=c.get('/api/v1/ssl/certificates')
        assert r.status_code==200, r.text
        body=r.json()[0]
        assert body['status']=='ISSUED'
        assert body['expires_at'] is not None
        assert "Let's Encrypt" in body['issuer']
    finally:
        app.dependency_overrides.clear()


def test_ssl_create_reconciles_existing_local_certificate(monkeypatch,tmp_path):
    monkeypatch.setenv('DNS_MANAGER_SSL_SECRET_KEY_FILE',str(tmp_path/'key'))
    from cryptography.fernet import Fernet
    (tmp_path/'key').write_bytes(Fernet.generate_key())
    from app.services.ssl_crypto import load_ssl_secret_key; load_ssl_secret_key.cache_clear()

    def fake_reconcile(db, cert, **kwargs):
        from datetime import datetime, timezone
        cert.status='ISSUED'; cert.issuer="CN=Let's Encrypt"
        cert.issued_at=datetime(2026,10,10,tzinfo=timezone.utc)
        cert.expires_at=datetime(2027,1,8,tzinfo=timezone.utc)
        db.commit(); db.refresh(cert)
        return {'domain':cert.domain,'status':'ISSUED','issuer':cert.issuer,'issued_at':cert.issued_at,'expires_at':cert.expires_at,'days_remaining':84}

    monkeypatch.setattr('app.api.ssl.reconcile_certificate', fake_reconcile)
    engine,c=env()
    try:
        r=c.post('/api/v1/ssl/certificates',headers={'X-CSRF-Token':'csrf-token'},json={'domain':'dns.example.com','provider':'manual','auto_renew':False,'redirect_http':True})
        assert r.status_code==201, r.text
        assert r.json()['status']=='ISSUED'
        assert r.json()['expires_at'] is not None
        with Session(engine) as db:
            row=db.query(__import__('app.models.ssl',fromlist=['SslCertificate']).SslCertificate).filter_by(domain='dns.example.com').one()
            assert row.status=='ISSUED'
            assert row.expires_at is not None
    finally:
        app.dependency_overrides.clear()


def test_manual_certificate_can_convert_to_cloudflare_without_reissuing(monkeypatch,tmp_path):
    monkeypatch.setenv('DNS_MANAGER_SSL_SECRET_KEY_FILE',str(tmp_path/'key'))
    from cryptography.fernet import Fernet
    (tmp_path/'key').write_bytes(Fernet.generate_key())
    from app.services.ssl_crypto import load_ssl_secret_key, decrypt_secret
    load_ssl_secret_key.cache_clear()
    engine,c=env()
    try:
        from app.models.ssl import SslCertificate, SslProviderCredential
        with Session(engine) as db:
            db.add(SslCertificate(domain='dns.example.com',provider='manual',status='ISSUED',auto_renew=False))
            db.commit()
        r=c.put('/api/v1/ssl/settings/dns.example.com',headers={'X-CSRF-Token':'csrf-token'},json={'provider':'cloudflare','api_token':'cf-secret-1234','auto_renew':True})
        assert r.status_code==200, r.text
        assert r.json()['provider']=='cloudflare'
        assert r.json()['status']=='ISSUED'
        assert r.json()['auto_renew'] is False
        assert 'cf-secret-1234' not in r.text
        with Session(engine) as db:
            cert=db.query(SslCertificate).filter_by(domain='dns.example.com').one()
            cred=db.query(SslProviderCredential).filter_by(certificate_id=cert.id).one()
            assert cert.provider=='cloudflare'
            assert cert.auto_renew is False
            assert cred.provider=='cloudflare'
            assert decrypt_secret(cred.token_ciphertext)=='cf-secret-1234'
    finally:
        app.dependency_overrides.clear()


def test_manual_to_cloudflare_conversion_requires_token(monkeypatch,tmp_path):
    monkeypatch.setenv('DNS_MANAGER_SSL_SECRET_KEY_FILE',str(tmp_path/'key'))
    from cryptography.fernet import Fernet
    (tmp_path/'key').write_bytes(Fernet.generate_key())
    from app.services.ssl_crypto import load_ssl_secret_key
    load_ssl_secret_key.cache_clear()
    engine,c=env()
    try:
        from app.models.ssl import SslCertificate
        with Session(engine) as db:
            db.add(SslCertificate(domain='dns.example.com',provider='manual',status='ISSUED'))
            db.commit()
        r=c.put('/api/v1/ssl/settings/dns.example.com',headers={'X-CSRF-Token':'csrf-token'},json={'provider':'cloudflare'})
        assert r.status_code==422
        with Session(engine) as db:
            assert db.query(SslCertificate).filter_by(domain='dns.example.com').one().provider=='manual'
    finally:
        app.dependency_overrides.clear()


def test_auto_renew_requires_successful_renewal_test(monkeypatch,tmp_path):
    monkeypatch.setenv('DNS_MANAGER_SSL_SECRET_KEY_FILE',str(tmp_path/'key'))
    from cryptography.fernet import Fernet
    (tmp_path/'key').write_bytes(Fernet.generate_key())
    from app.services.ssl_crypto import load_ssl_secret_key, encrypt_secret
    load_ssl_secret_key.cache_clear()
    engine,c=env()
    try:
        from app.models.ssl import SslCertificate, SslProviderCredential
        with Session(engine) as db:
            cert=SslCertificate(domain='dns.example.com',provider='cloudflare',status='ISSUED',auto_renew=False)
            db.add(cert); db.flush()
            db.add(SslProviderCredential(certificate_id=cert.id,provider='cloudflare',token_ciphertext=encrypt_secret('cf-secret-1234'),token_last4='1234'))
            db.commit()
        denied=c.put('/api/v1/ssl/settings/dns.example.com',headers={'X-CSRF-Token':'csrf-token'},json={'auto_renew':True})
        assert denied.status_code==409
        monkeypatch.setattr('app.api.ssl.PrivilegedHelper.ssl_test_renewal',lambda self,**kwargs:{'ok':True})
        tested=c.post('/api/v1/ssl/certificates/dns.example.com/test-renewal',headers={'X-CSRF-Token':'csrf-token'})
        assert tested.status_code==200, tested.text
        with Session(engine) as db:
            assert db.query(SslCertificate).filter_by(domain='dns.example.com').one().last_renewal_status=='TEST_SUCCESS'
        enabled=c.put('/api/v1/ssl/settings/dns.example.com',headers={'X-CSRF-Token':'csrf-token'},json={'auto_renew':True})
        assert enabled.status_code==200, enabled.text
        assert enabled.json()['auto_renew'] is True
    finally:
        app.dependency_overrides.clear()


def test_failed_renewal_test_keeps_auto_renew_disabled(monkeypatch,tmp_path):
    monkeypatch.setenv('DNS_MANAGER_SSL_SECRET_KEY_FILE',str(tmp_path/'key'))
    from cryptography.fernet import Fernet
    (tmp_path/'key').write_bytes(Fernet.generate_key())
    from app.services.ssl_crypto import load_ssl_secret_key, encrypt_secret
    load_ssl_secret_key.cache_clear()
    engine,c=env()
    try:
        from app.models.ssl import SslCertificate, SslProviderCredential
        from app.services.privileged_helper import PrivilegedHelperError
        with Session(engine) as db:
            cert=SslCertificate(domain='dns.example.com',provider='cloudflare',status='ISSUED',auto_renew=False)
            db.add(cert); db.flush()
            db.add(SslProviderCredential(certificate_id=cert.id,provider='cloudflare',token_ciphertext=encrypt_secret('cf-secret-1234'),token_last4='1234')); db.commit()
        def fail(*args,**kwargs): raise PrivilegedHelperError('provider rejected request')
        monkeypatch.setattr('app.api.ssl.PrivilegedHelper.ssl_test_renewal',fail)
        r=c.post('/api/v1/ssl/certificates/dns.example.com/test-renewal',headers={'X-CSRF-Token':'csrf-token'})
        assert r.status_code==422
        with Session(engine) as db:
            row=db.query(SslCertificate).filter_by(domain='dns.example.com').one()
            assert row.last_renewal_status=='TEST_FAILED'
            assert row.auto_renew is False
    finally:
        app.dependency_overrides.clear()


def test_new_cloudflare_certificate_does_not_enable_auto_renew_before_test(monkeypatch,tmp_path):
    monkeypatch.setenv('DNS_MANAGER_SSL_SECRET_KEY_FILE',str(tmp_path/'key'))
    from cryptography.fernet import Fernet
    (tmp_path/'key').write_bytes(Fernet.generate_key())
    from app.services.ssl_crypto import load_ssl_secret_key
    load_ssl_secret_key.cache_clear()
    monkeypatch.setattr('app.api.ssl.reconcile_certificate',lambda db,cert,**kwargs: {'domain':cert.domain,'status':cert.status})
    engine,c=env()
    try:
        r=c.post('/api/v1/ssl/certificates',headers={'X-CSRF-Token':'csrf-token'},json={'domain':'dns.example.com','provider':'cloudflare','api_token':'cf-secret-1234','auto_renew':True,'redirect_http':True})
        assert r.status_code==201, r.text
        assert r.json()['auto_renew'] is False
    finally:
        app.dependency_overrides.clear()


def test_failed_renewal_test_returns_sanitized_provider_error(monkeypatch,tmp_path):
    monkeypatch.setenv('DNS_MANAGER_SSL_SECRET_KEY_FILE',str(tmp_path/'key'))
    from cryptography.fernet import Fernet
    (tmp_path/'key').write_bytes(Fernet.generate_key())
    from app.services.ssl_crypto import load_ssl_secret_key, encrypt_secret
    load_ssl_secret_key.cache_clear()
    engine,c=env()
    try:
        from app.models.ssl import SslCertificate, SslProviderCredential
        from app.services.privileged_helper import PrivilegedHelperError
        secret='cf-secret-1234'
        with Session(engine) as db:
            cert=SslCertificate(domain='dns.example.com',provider='cloudflare',status='ISSUED',auto_renew=False)
            db.add(cert); db.flush()
            db.add(SslProviderCredential(certificate_id=cert.id,provider='cloudflare',token_ciphertext=encrypt_secret(secret),token_last4='1234')); db.commit()
        def fail(*args,**kwargs):
            raise PrivilegedHelperError(f'Cloudflare rejected token {secret}: invalid permissions')
        monkeypatch.setattr('app.api.ssl.PrivilegedHelper.ssl_test_renewal',fail)
        r=c.post('/api/v1/ssl/certificates/dns.example.com/test-renewal',headers={'X-CSRF-Token':'csrf-token'})
        assert r.status_code==422
        assert 'invalid permissions' in r.json()['detail']
        assert secret not in r.text
        with Session(engine) as db:
            row=db.query(SslCertificate).filter_by(domain='dns.example.com').one()
            assert 'invalid permissions' in (row.last_error or '')
            assert secret not in (row.last_error or '')
    finally:
        app.dependency_overrides.clear()


def _seed_delegated(engine, verified=True):
    from app.models.ssl import SslCertificate
    from app.models.acme_dns import SslAcmeDelegation
    with Session(engine) as db:
        cert=SslCertificate(domain='delegated.example.com',provider='acme_delegation',status='ISSUED',auto_renew=False)
        db.add(cert); db.flush()
        db.add(SslAcmeDelegation(certificate_id=cert.id,domain=cert.domain,challenge_domain='_acme-challenge.delegated.example.com',delegation_id='dns-123456abcdef',delegated_fqdn='dns-123456abcdef.acme-dns.connect3.net.bd',verified=verified))
        db.commit()


def test_acme_delegation_test_requires_verified_delegation(monkeypatch):
    engine,c=env(); _seed_delegated(engine,verified=False)
    try:
        r=c.post('/api/v1/ssl/certificates/delegated.example.com/test-renewal',headers={'X-CSRF-Token':'csrf-token'})
        assert r.status_code==409
        assert 'verified' in r.json()['detail'].lower()
    finally: app.dependency_overrides.clear()


def test_acme_delegation_test_success_sets_test_success(monkeypatch):
    engine,c=env(); _seed_delegated(engine,verified=True)
    try:
        monkeypatch.setattr('app.api.ssl.PrivilegedHelper.ssl_test_renewal',lambda self,**kwargs:{'tested':True})
        r=c.post('/api/v1/ssl/certificates/delegated.example.com/test-renewal',headers={'X-CSRF-Token':'csrf-token'})
        assert r.status_code==200, r.text
        with Session(engine) as db:
            row=db.query(__import__('app.models.ssl',fromlist=['SslCertificate']).SslCertificate).filter_by(domain='delegated.example.com').one()
            assert row.last_renewal_status=='TEST_SUCCESS'
    finally: app.dependency_overrides.clear()


def test_acme_delegation_failed_test_disables_auto_renew(monkeypatch):
    from app.services.privileged_helper import PrivilegedHelperError
    engine,c=env(); _seed_delegated(engine,verified=True)
    try:
        with Session(engine) as db:
            row=db.query(__import__('app.models.ssl',fromlist=['SslCertificate']).SslCertificate).filter_by(domain='delegated.example.com').one(); row.auto_renew=True; db.commit()
        def fail(*a,**k): raise PrivilegedHelperError('staging validation failed')
        monkeypatch.setattr('app.api.ssl.PrivilegedHelper.ssl_test_renewal',fail)
        r=c.post('/api/v1/ssl/certificates/delegated.example.com/test-renewal',headers={'X-CSRF-Token':'csrf-token'})
        assert r.status_code==422
        with Session(engine) as db:
            row=db.query(__import__('app.models.ssl',fromlist=['SslCertificate']).SslCertificate).filter_by(domain='delegated.example.com').one()
            assert row.last_renewal_status=='TEST_FAILED'
            assert row.auto_renew is False
    finally: app.dependency_overrides.clear()


def test_acme_delegation_auto_renew_requires_verified_and_successful_test(monkeypatch):
    engine,c=env(); _seed_delegated(engine,verified=True)
    try:
        denied=c.put('/api/v1/ssl/settings/delegated.example.com',headers={'X-CSRF-Token':'csrf-token'},json={'auto_renew':True})
        assert denied.status_code==409
        with Session(engine) as db:
            cert=db.query(__import__('app.models.ssl',fromlist=['SslCertificate']).SslCertificate).filter_by(domain='delegated.example.com').one()
            cert.last_renewal_status='TEST_SUCCESS'; db.commit()
        enabled=c.put('/api/v1/ssl/settings/delegated.example.com',headers={'X-CSRF-Token':'csrf-token'},json={'auto_renew':True})
        assert enabled.status_code==200, enabled.text
        assert enabled.json()['auto_renew'] is True
    finally: app.dependency_overrides.clear()


def test_acme_delegation_manual_renew_rechecks_public_cname(monkeypatch):
    engine,c=env(); _seed_delegated(engine,verified=True)
    try:
        called=[]
        monkeypatch.setattr('app.api.ssl.verify_delegation',lambda *a,**k:{'verified':False,'observed':['wrong.example.net'],'error':'CNAME mismatch'})
        monkeypatch.setattr('app.api.ssl.PrivilegedHelper.ssl_renew',lambda *a,**k: called.append(k))
        r=c.post('/api/v1/ssl/certificates/delegated.example.com/renew',headers={'X-CSRF-Token':'csrf-token'})
        assert r.status_code==409
        assert 'delegation' in r.json()['detail'].lower()
        assert called==[]
        with Session(engine) as db:
            cert=db.query(__import__('app.models.ssl',fromlist=['SslCertificate']).SslCertificate).filter_by(domain='delegated.example.com').one()
            assert cert.delegation.verified is False
    finally: app.dependency_overrides.clear()


def test_acme_delegation_create_does_not_require_reading_root_only_acme_config(monkeypatch,tmp_path):
    monkeypatch.setattr('app.api.ssl.reconcile_certificate',lambda db,cert,**kwargs:{'domain':cert.domain,'status':cert.status})
    def forbidden():
        raise PermissionError('root-only config')
    monkeypatch.setattr('app.api.ssl.load_acme_dns_config',forbidden,raising=False)
    engine,c=env()
    try:
        r=c.post('/api/v1/ssl/certificates',headers={'X-CSRF-Token':'csrf-token'},json={'domain':'delegated2.example.com','provider':'acme_delegation'})
        assert r.status_code==201, r.text
        assert r.json()['delegated_fqdn'].endswith('.acme-dns.connect3.net.bd')
    finally: app.dependency_overrides.clear()


def test_acme_test_and_manual_renew_write_sanitized_audit_events(monkeypatch):
    from app.models.audit import AuditLog
    engine,c=env(); _seed_delegated(engine,verified=True)
    try:
        monkeypatch.setattr('app.api.ssl.PrivilegedHelper.ssl_test_renewal',lambda self,**kwargs:{'tested':True})
        monkeypatch.setattr('app.api.ssl.verify_delegation',lambda *a,**k:{'verified':True,'observed':['dns-123456abcdef.acme-dns.connect3.net.bd'],'error':None})
        monkeypatch.setattr('app.api.ssl.PrivilegedHelper.ssl_renew',lambda self,**kwargs:{'renewed':True})
        monkeypatch.setattr('app.api.ssl.reconcile_certificate',lambda db,cert,**kwargs:{'domain':cert.domain,'status':cert.status})
        h={'X-CSRF-Token':'csrf-token'}
        assert c.post('/api/v1/ssl/certificates/delegated.example.com/test-renewal',headers=h).status_code==200
        assert c.post('/api/v1/ssl/certificates/delegated.example.com/renew',headers=h).status_code==200
        with Session(engine) as db:
            rows=db.query(AuditLog).filter(AuditLog.action.in_(['ACME_RENEWAL_TEST_SUCCESS','ACME_RENEWAL_SUCCESS'])).order_by(AuditLog.id).all()
            assert [r.action for r in rows]==['ACME_RENEWAL_TEST_SUCCESS','ACME_RENEWAL_SUCCESS']
            assert 'validation' not in repr([(r.new_value,r.error_message) for r in rows]).lower()
    finally:
        app.dependency_overrides.clear()


def test_hosted_manual_renew_writes_sanitized_audit_event(monkeypatch):
    from app.models.audit import AuditLog
    from app.models.ssl import SslCertificate
    from app.models.hosted_acme import SslHostedAcmeCredential
    engine,c=env()
    try:
        with Session(engine) as db:
            cert=SslCertificate(domain='hosted.example.com',provider='acme_dns_hosted',status='ISSUED')
            db.add(cert); db.flush()
            db.add(SslHostedAcmeCredential(certificate_id=cert.id,server_url='https://auth.acme-dns.io',username_ciphertext='cipher-user',password_ciphertext='cipher-pass',subdomain='abc',fulldomain='abc.auth.acme-dns.io',challenge_domain='_acme-challenge.hosted.example.com',verified=True))
            db.commit()
        monkeypatch.setattr('app.api.ssl.verify_hosted_cname',lambda *a,**k:{'verified':True,'observed':['abc.auth.acme-dns.io'],'error':None})
        monkeypatch.setattr('app.api.ssl.PrivilegedHelper.ssl_renew',lambda self,**kwargs:{'renewed':True})
        monkeypatch.setattr('app.api.ssl.reconcile_certificate',lambda db,cert,**kwargs:{'domain':cert.domain,'status':cert.status})
        r=c.post('/api/v1/ssl/certificates/hosted.example.com/renew',headers={'X-CSRF-Token':'csrf-token'})
        assert r.status_code==200,r.text
        with Session(engine) as db:
            row=db.query(AuditLog).filter_by(action='HOSTED_ACME_RENEWAL_SUCCESS',object_id='hosted.example.com').first()
            assert row is not None
            assert 'cipher' not in repr((row.old_value,row.new_value,row.error_message)).lower()
    finally:
        app.dependency_overrides.clear()


def test_ssl_apply_routes_enabled_mapping_to_mapping_upstream(monkeypatch):
    from app.models.ssl import SslCertificate
    from app.models.mapping import Mapping
    engine,c=env()
    captured={}
    try:
        with Session(engine) as db:
            db.add(SslCertificate(domain='vm226.connect3.net.bd',provider='manual',status='ISSUED',redirect_http=True))
            db.add(Mapping(
                domain='vm226.connect3.net.bd',upstream_scheme='https',upstream_host='192.168.255.226',upstream_port=443,
                enabled=True,websocket_enabled=True,preserve_host=True,tls_verify=False,custom_timeout=None,
            ))
            db.commit()
        def fake_apply(self, domain, redirect_http=True, upstream=None):
            captured.update(domain=domain,redirect_http=redirect_http,upstream=upstream)
            return {'applied':True,'domain':domain}
        monkeypatch.setattr('app.api.ssl.PrivilegedHelper.ssl_apply',fake_apply)
        r=c.post('/api/v1/ssl/certificates/vm226.connect3.net.bd/apply',headers={'X-CSRF-Token':'csrf-token'})
        assert r.status_code==200, r.text
        assert captured['domain']=='vm226.connect3.net.bd'
        assert captured['upstream']=={
            'scheme':'https','host':'192.168.255.226','port':443,
            'preserve_host':True,'websocket_enabled':True,'timeout':60,
        }
    finally:
        app.dependency_overrides.clear()
