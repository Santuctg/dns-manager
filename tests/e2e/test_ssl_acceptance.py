from pathlib import Path
from types import SimpleNamespace
from cryptography.fernet import Fernet

from app.services.ssl_crypto import encrypt_secret, decrypt_secret, load_ssl_secret_key
from app.services.ssl_service import normalize_ssl_domain
from privileged.helper_server import handle_request
from privileged.ssl_helper import SslHelperOps


def test_ssl_management_acceptance_core(tmp_path, monkeypatch):
    key=tmp_path/'key'; key.write_bytes(Fernet.generate_key())
    monkeypatch.setenv('DNS_MANAGER_SSL_SECRET_KEY_FILE',str(key)); load_ssl_secret_key.cache_clear()
    token='cf-token-acceptance'
    encrypted=encrypt_secret(token)
    assert token not in encrypted and decrypt_secret(encrypted)==token
    assert normalize_ssl_domain('DNS.Example.COM.')=='dns.example.com'

    renewal=tmp_path/'le'/'renewal'; renewal.mkdir(parents=True)
    calls=[]
    def runner(argv, **kwargs):
        calls.append(list(argv))
        if '/usr/bin/certbot' in argv[0]:
            cred=Path(argv[argv.index('--dns-cloudflare-credentials')+1]); assert token in cred.read_text(); assert token not in ' '.join(argv)
            (renewal/'dns.example.com.conf').write_text('[renewalparams]\nauthenticator = dns-cloudflare\n')
        return SimpleNamespace(returncode=0,stdout='ok',stderr='')
    ops=SslHelperOps(letsencrypt_root=tmp_path/'le',work_root=tmp_path/'work',runner=runner)
    result=ops.ssl_issue('dns.example.com','cloudflare',token)
    assert result['issued'] is True
    assert not list((tmp_path/'work').glob('cf-*'))
    assert handle_request('{"command":"ssl_status","domain":"dns.example.com","argv":["rm"]}',ops)['ok'] is False


def test_acme_delegation_acceptance_flow(tmp_path, monkeypatch):
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

    engine=create_engine('sqlite+pysqlite:///:memory:',connect_args={'check_same_thread':False},poolclass=StaticPool)
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        p=Permission(name='system.view'); role=Role(name='super_admin',permissions=[p]); db.add_all([p,role]); db.flush()
        user=User(username='acceptance',password_hash=hash_password('very-secure-password'),role=role); db.add(user); db.flush()
        sid=create_session(db,user,'csrf-token')
        db.add(SslCertificate(domain='example.com',provider='manual',status='ISSUED')); db.commit()
    def odb():
        with Session(engine) as db: yield db
    app.dependency_overrides[get_db]=odb
    c=TestClient(app,base_url='https://testserver'); c.cookies.set('dns_manager_session',sid); c.cookies.set('dns_manager_csrf','csrf-token')
    try:
        created=c.post('/api/v1/ssl/certificates/example.com/delegation',headers={'X-CSRF-Token':'csrf-token'})
        assert created.status_code==200, created.text
        target=created.json()['delegated_fqdn']
        assert target.endswith('.acme-dns.connect3.net.bd')
        monkeypatch.setattr('app.api.acme_dns.verify_delegation',lambda *a,**k:{'verified':True,'observed':[target],'error':None})
        verified=c.post('/api/v1/ssl/certificates/example.com/delegation/verify',headers={'X-CSRF-Token':'csrf-token'})
        assert verified.status_code==200 and verified.json()['verified'] is True
        monkeypatch.setattr('app.api.ssl.PrivilegedHelper.ssl_test_renewal',lambda *a,**k:{'tested':True})
        tested=c.post('/api/v1/ssl/certificates/example.com/test-renewal',headers={'X-CSRF-Token':'csrf-token'})
        assert tested.status_code==200, tested.text
        enabled=c.put('/api/v1/ssl/settings/example.com',headers={'X-CSRF-Token':'csrf-token'},json={'auto_renew':True})
        assert enabled.status_code==200 and enabled.json()['auto_renew'] is True
    finally:
        app.dependency_overrides.clear()


def test_acme_delegation_multi_value_txt_acceptance(tmp_path):
    from app.config import AcmeDnsConfig
    from privileged.acme_dns_helper import AcmeDnsHelperOps
    class R:
        returncode=0; stdout='active'; stderr=''
    ops=AcmeDnsHelperOps(
        AcmeDnsConfig(enabled=True,listen_ip='192.0.2.10'),
        storage=tmp_path,
        registration_checker=lambda host: True,
        runner=lambda argv,**kwargs:R(),
    )
    host='dns-123456abcdef.acme-dns.connect3.net.bd'
    ops.txt_set(host,'token_one'); ops.txt_set(host,'token_two'); ops.txt_delete(host,'token_one')
    zone=ops.zone_path.read_text()
    assert 'token_one' not in zone
    assert 'token_two' in zone


def test_hosted_acme_dns_acceptance_flow(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session
    from sqlalchemy.pool import StaticPool
    from cryptography.fernet import Fernet
    from app.config import HostedAcmeConfig
    from app.database import Base, get_db
    from app.main import app
    from app.models.auth import Permission, Role, User
    from app.models.ssl import SslCertificate
    from app.security import hash_password
    from app.services.auth_service import create_session
    from app.services.hosted_acme_service import HostedAcmeRegistration
    from app.services.ssl_crypto import load_ssl_secret_key

    key=tmp_path/'key'; key.write_bytes(Fernet.generate_key())
    monkeypatch.setenv('DNS_MANAGER_SSL_SECRET_KEY_FILE',str(key)); load_ssl_secret_key.cache_clear()
    engine=create_engine('sqlite+pysqlite:///:memory:',connect_args={'check_same_thread':False},poolclass=StaticPool)
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        p=Permission(name='system.view'); role=Role(name='super_admin',permissions=[p]); db.add_all([p,role]); db.flush()
        user=User(username='hosted-acceptance',password_hash=hash_password('very-secure-password'),role=role); db.add(user); db.flush()
        sid=create_session(db,user,'csrf-token'); db.add(SslCertificate(domain='example.com',provider='manual',status='ISSUED')); db.commit()
    def odb():
        with Session(engine) as db: yield db
    app.dependency_overrides[get_db]=odb
    c=TestClient(app,base_url='https://testserver'); c.cookies.set('dns_manager_session',sid); c.cookies.set('dns_manager_csrf','csrf-token')
    monkeypatch.setattr('app.api.ssl.load_hosted_acme_config',lambda:HostedAcmeConfig(enabled=True))
    monkeypatch.setattr('app.api.ssl.HostedAcmeClient.register',lambda self:HostedAcmeRegistration('secret-user','secret-pass','abc123','abc123.auth.acme-dns.io'))
    monkeypatch.setattr('app.api.ssl.verify_hosted_cname',lambda *a,**k:{'verified':True,'observed':['abc123.auth.acme-dns.io'],'error':None})
    monkeypatch.setattr('app.api.ssl.PrivilegedHelper.ssl_test_renewal',lambda *a,**k:{'tested':True})
    try:
        registered=c.post('/api/v1/ssl/certificates/example.com/hosted-acme/register',headers={'X-CSRF-Token':'csrf-token'})
        assert registered.status_code==200,registered.text
        assert registered.json()['fulldomain']=='abc123.auth.acme-dns.io'
        assert 'secret-user' not in registered.text and 'secret-pass' not in registered.text
        verified=c.post('/api/v1/ssl/certificates/example.com/hosted-acme/verify',headers={'X-CSRF-Token':'csrf-token'})
        assert verified.status_code==200 and verified.json()['verified'] is True
        tested=c.post('/api/v1/ssl/certificates/example.com/test-renewal',headers={'X-CSRF-Token':'csrf-token'})
        assert tested.status_code==200,tested.text
        enabled=c.put('/api/v1/ssl/settings/example.com',headers={'X-CSRF-Token':'csrf-token'},json={'auto_renew':True})
        assert enabled.status_code==200 and enabled.json()['auto_renew'] is True
    finally:
        app.dependency_overrides.clear()
