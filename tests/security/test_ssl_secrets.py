import os
import pytest
from cryptography.fernet import Fernet, InvalidToken

from app.services.ssl_crypto import encrypt_secret, decrypt_secret, load_ssl_secret_key


def test_secret_round_trip_and_wrong_key(tmp_path, monkeypatch):
    keyfile = tmp_path / 'key'
    keyfile.write_bytes(Fernet.generate_key())
    monkeypatch.setenv('DNS_MANAGER_SSL_SECRET_KEY_FILE', str(keyfile))
    load_ssl_secret_key.cache_clear()
    token = 'cf-super-secret-token'
    ciphertext = encrypt_secret(token)
    assert token not in ciphertext
    assert decrypt_secret(ciphertext) == token
    keyfile.write_bytes(Fernet.generate_key())
    load_ssl_secret_key.cache_clear()
    with pytest.raises(InvalidToken):
        decrypt_secret(ciphertext)


def test_missing_key_is_rejected(tmp_path, monkeypatch):
    monkeypatch.setenv('DNS_MANAGER_SSL_SECRET_KEY_FILE', str(tmp_path / 'missing'))
    load_ssl_secret_key.cache_clear()
    with pytest.raises(RuntimeError, match='SSL secret key'):
        load_ssl_secret_key()


def test_cloudflare_conversion_token_is_absent_from_audit(monkeypatch,tmp_path):
    from fastapi.testclient import TestClient
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session
    from sqlalchemy.pool import StaticPool
    from cryptography.fernet import Fernet
    from app.database import Base, get_db
    from app.main import app
    from app.models.auth import Permission, Role, User
    from app.models.audit import AuditLog
    from app.models.ssl import SslCertificate
    from app.security import hash_password
    from app.services.auth_service import create_session
    from app.services.ssl_crypto import load_ssl_secret_key

    key=tmp_path/'key'; key.write_bytes(Fernet.generate_key())
    monkeypatch.setenv('DNS_MANAGER_SSL_SECRET_KEY_FILE',str(key)); load_ssl_secret_key.cache_clear()
    engine=create_engine('sqlite+pysqlite:///:memory:',connect_args={'check_same_thread':False},poolclass=StaticPool)
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        p=Permission(name='system.view'); role=Role(name='super_admin',permissions=[p]); db.add_all([p,role]); db.flush()
        user=User(username='actor',password_hash=hash_password('very-secure-password'),role=role); db.add(user); db.flush()
        sid=create_session(db,user,'csrf-token'); db.add(SslCertificate(domain='dns.example.com',provider='manual',status='ISSUED')); db.commit()
    def odb():
        with Session(engine) as db: yield db
    app.dependency_overrides[get_db]=odb
    c=TestClient(app,base_url='https://testserver'); c.cookies.set('dns_manager_session',sid); c.cookies.set('dns_manager_csrf','csrf-token')
    try:
        secret='cf-super-secret-9876'
        r=c.put('/api/v1/ssl/settings/dns.example.com',headers={'X-CSRF-Token':'csrf-token'},json={'provider':'cloudflare','api_token':secret})
        assert r.status_code==200, r.text
        with Session(engine) as db:
            audit=db.query(AuditLog).filter_by(action='SSL_SETTINGS_UPDATED',object_id='dns.example.com').order_by(AuditLog.id.desc()).first()
            assert audit is not None
            text=(audit.old_value or '')+(audit.new_value or '')+(audit.error_message or '')
            assert secret not in text
            assert 'ciphertext' not in text
    finally:
        app.dependency_overrides.clear()


def test_global_modal_does_not_persist_prompt_secrets_in_browser_storage():
    text = __import__('pathlib').Path('app/static/app.js').read_text()
    assert 'localStorage.setItem' not in text
    assert 'sessionStorage.setItem' not in text
    assert 'input.value=\'\'' in text or 'input.value = \'\'' in text
    assert 'textContent' in text
