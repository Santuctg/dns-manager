from pathlib import Path
from sqlalchemy.orm import Session
from cryptography.fernet import Fernet

from app.database import Base, build_engine
from app.models import SslCertificate, SslHostedAcmeCredential
from app.schemas.hosted_acme import HostedAcmeStatus
from app.services.ssl_crypto import encrypt_secret, load_ssl_secret_key


def test_hosted_acme_credential_persists_encrypted_fields(tmp_path, monkeypatch):
    keyfile = tmp_path/'key'; keyfile.write_bytes(Fernet.generate_key())
    monkeypatch.setenv('DNS_MANAGER_SSL_SECRET_KEY_FILE', str(keyfile)); load_ssl_secret_key.cache_clear()
    engine = build_engine(str(tmp_path/'db.sqlite3')); Base.metadata.create_all(engine)
    with Session(engine) as db:
        cert = SslCertificate(domain='example.com', provider='acme_dns_hosted')
        db.add(cert); db.flush()
        cred = SslHostedAcmeCredential(
            certificate_id=cert.id,
            server_url='https://auth.acme-dns.io',
            username_ciphertext=encrypt_secret('user-secret'),
            password_ciphertext=encrypt_secret('pass-secret'),
            subdomain='abc123',
            fulldomain='abc123.auth.acme-dns.io',
            challenge_domain='_acme-challenge.example.com',
            verified=False,
        )
        db.add(cred); db.commit(); db.refresh(cred)
        assert cred.username_ciphertext != 'user-secret'
        assert cred.password_ciphertext != 'pass-secret'
        assert cred.fulldomain == 'abc123.auth.acme-dns.io'
        assert cert.hosted_acme is not None


def test_hosted_acme_safe_schema_excludes_credentials():
    status = HostedAcmeStatus(
        server_url='https://auth.acme-dns.io',
        subdomain='abc',
        fulldomain='abc.auth.acme-dns.io',
        challenge_domain='_acme-challenge.example.com',
        verified=False,
    )
    data = status.model_dump()
    assert 'username' not in data
    assert 'password' not in data
    assert 'ciphertext' not in str(data)


def test_migration_0008_declares_hosted_acme_table():
    text = Path('migrations/versions/0008_hosted_acme_dns.py').read_text()
    assert 'revision: str = "0008_hosted_acme_dns"' in text
    assert 'down_revision' in text and '0007_acme_dns_delegation' in text
    assert 'ssl_acme_dns_credentials' in text
