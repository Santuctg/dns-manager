import sqlite3
from cryptography.fernet import Fernet
import pytest

from app.services.ssl_crypto import encrypt_secret, load_ssl_secret_key
from privileged.hosted_acme_hook import run_hook


def make_db(path, monkeypatch, tmp_path, verified=True):
    key=tmp_path/'key'; key.write_bytes(Fernet.generate_key()); monkeypatch.setenv('DNS_MANAGER_SSL_SECRET_KEY_FILE',str(key)); load_ssl_secret_key.cache_clear()
    con=sqlite3.connect(path)
    con.execute('CREATE TABLE ssl_certificates(id INTEGER PRIMARY KEY, domain TEXT, provider TEXT)')
    con.execute('CREATE TABLE ssl_acme_dns_credentials(certificate_id INTEGER, server_url TEXT, username_ciphertext TEXT, password_ciphertext TEXT, subdomain TEXT, fulldomain TEXT, challenge_domain TEXT, verified INTEGER)')
    con.execute('INSERT INTO ssl_certificates VALUES(1,?,?)',('example.com','acme_dns_hosted'))
    con.execute('INSERT INTO ssl_acme_dns_credentials VALUES(1,?,?,?,?,?,?,?)',('https://auth.acme-dns.io',encrypt_secret('user-secret'),encrypt_secret('pass-secret'),'abc','abc.auth.acme-dns.io','_acme-challenge.example.com',1 if verified else 0))
    con.commit(); con.close()


def test_hosted_auth_updates_txt_and_waits(monkeypatch,tmp_path):
    db=tmp_path/'db'; make_db(db,monkeypatch,tmp_path)
    seen={}
    class Client:
        def update_txt(self,u,p,s,v): seen.update(u=u,p=p,s=s,v=v)
    rc=run_hook('auth',env={'CERTBOT_DOMAIN':'example.com','CERTBOT_VALIDATION':'token-secret'},database_path=db,client_factory=lambda *_:Client(),waiter=lambda host,val,**k: host=='abc.auth.acme-dns.io' and val=='token-secret')
    assert rc==0
    assert seen=={'u':'user-secret','p':'pass-secret','s':'abc','v':'token-secret'}


def test_hosted_auth_requires_verified_registration(monkeypatch,tmp_path):
    db=tmp_path/'db'; make_db(db,monkeypatch,tmp_path,verified=False)
    with pytest.raises(RuntimeError,match='not verified'):
        run_hook('auth',env={'CERTBOT_DOMAIN':'example.com','CERTBOT_VALIDATION':'secret-token'},database_path=db,client_factory=lambda *_:None)


def test_hosted_cleanup_is_best_effort(monkeypatch,tmp_path):
    db=tmp_path/'db'; make_db(db,monkeypatch,tmp_path)
    assert run_hook('cleanup',env={'CERTBOT_DOMAIN':'example.com','CERTBOT_VALIDATION':'secret-token'},database_path=db,client_factory=lambda *_:None)==0


def test_hosted_update_failure_audits_without_secrets(monkeypatch,tmp_path):
    db=tmp_path/'db'; make_db(db,monkeypatch,tmp_path)
    con=sqlite3.connect(db)
    con.execute('CREATE TABLE audit_logs(id INTEGER PRIMARY KEY, user_id INTEGER, username TEXT, action TEXT, object_type TEXT, object_id TEXT, source_ip TEXT, user_agent TEXT, old_value TEXT, new_value TEXT, status TEXT, error_message TEXT, created_at TEXT)')
    con.commit(); con.close()
    class Client:
        def update_txt(self,*args): raise RuntimeError('provider failure')
    with pytest.raises(RuntimeError):
        run_hook('auth',env={'CERTBOT_DOMAIN':'example.com','CERTBOT_VALIDATION':'token-secret'},database_path=db,client_factory=lambda *_:Client(),waiter=None)
    con=sqlite3.connect(db); row=con.execute("SELECT action,new_value,error_message FROM audit_logs ORDER BY id DESC LIMIT 1").fetchone(); con.close()
    assert row[0]=='HOSTED_ACME_UPDATE_FAILED'
    text=''.join(x or '' for x in row)
    assert 'token-secret' not in text and 'user-secret' not in text and 'pass-secret' not in text
