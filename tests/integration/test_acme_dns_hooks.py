import os
import sqlite3
from pathlib import Path

import pytest


def make_db(path: Path, verified=True):
    con=sqlite3.connect(path)
    con.executescript('''
      CREATE TABLE ssl_certificates(id INTEGER PRIMARY KEY, domain TEXT, provider TEXT);
      CREATE TABLE ssl_acme_delegations(id INTEGER PRIMARY KEY, certificate_id INTEGER, domain TEXT, delegated_fqdn TEXT, verified INTEGER);
      CREATE TABLE audit_logs(id INTEGER PRIMARY KEY, user_id INTEGER, username TEXT, action TEXT NOT NULL, object_type TEXT, object_id TEXT, source_ip TEXT, user_agent TEXT, old_value TEXT, new_value TEXT, status TEXT NOT NULL, error_message TEXT, created_at TEXT NOT NULL);
    ''')
    con.execute("INSERT INTO ssl_certificates(id,domain,provider) VALUES(1,'example.com','acme_delegation')")
    con.execute("INSERT INTO ssl_acme_delegations(certificate_id,domain,delegated_fqdn,verified) VALUES(1,'example.com','dns-123456abcdef.acme-dns.connect3.net.bd',?)",(1 if verified else 0,))
    con.commit(); con.close()


class FakeHelper:
    def __init__(self): self.calls=[]
    def acme_txt_set(self, hostname, value): self.calls.append(('set',hostname,value)); return {'updated':True}
    def acme_txt_delete(self, hostname, value): self.calls.append(('delete',hostname,value)); return {'deleted':True}


def test_auth_hook_sets_registered_verified_txt(tmp_path):
    from privileged.acme_dns_hook import run_hook
    db=tmp_path/'db.sqlite3'; make_db(db)
    helper=FakeHelper()
    env={'CERTBOT_DOMAIN':'example.com','CERTBOT_VALIDATION':'secret-validation-token'}
    assert run_hook('auth',env=env,database_path=db,helper=helper,waiter=lambda *a,**k: True)==0
    assert helper.calls==[('set','dns-123456abcdef.acme-dns.connect3.net.bd','secret-validation-token')]


def test_cleanup_hook_removes_only_matching_txt(tmp_path):
    from privileged.acme_dns_hook import run_hook
    db=tmp_path/'db.sqlite3'; make_db(db)
    helper=FakeHelper(); env={'CERTBOT_DOMAIN':'example.com','CERTBOT_VALIDATION':'token-two'}
    assert run_hook('cleanup',env=env,database_path=db,helper=helper)==0
    assert helper.calls==[('delete','dns-123456abcdef.acme-dns.connect3.net.bd','token-two')]


def test_auth_hook_rejects_unverified_or_unknown_delegation_without_token_in_error(tmp_path):
    from privileged.acme_dns_hook import run_hook
    db=tmp_path/'db.sqlite3'; make_db(db,verified=False)
    token='ultra-secret-validation-token'
    with pytest.raises(RuntimeError) as exc:
        run_hook('auth',env={'CERTBOT_DOMAIN':'example.com','CERTBOT_VALIDATION':token},database_path=db,helper=FakeHelper())
    assert 'verified' in str(exc.value).lower()
    assert token not in str(exc.value)
    with pytest.raises(RuntimeError,match='delegation'):
        run_hook('auth',env={'CERTBOT_DOMAIN':'missing.example','CERTBOT_VALIDATION':token},database_path=db,helper=FakeHelper())


def test_hook_requires_certbot_environment_without_echoing_values(tmp_path):
    from privileged.acme_dns_hook import run_hook
    db=tmp_path/'db.sqlite3'; make_db(db)
    with pytest.raises(RuntimeError,match='environment'):
        run_hook('auth',env={},database_path=db,helper=FakeHelper())


def test_hook_audits_challenge_lifecycle_without_validation_token(tmp_path):
    from privileged.acme_dns_hook import run_hook
    db=tmp_path/'db.sqlite3'; make_db(db)
    token='do-not-store-this-validation-token'
    helper=FakeHelper(); env={'CERTBOT_DOMAIN':'example.com','CERTBOT_VALIDATION':token}
    assert run_hook('auth',env=env,database_path=db,helper=helper,waiter=lambda *a,**k: True)==0
    assert run_hook('cleanup',env=env,database_path=db,helper=helper)==0
    con=sqlite3.connect(db)
    rows=con.execute("SELECT action,new_value,error_message FROM audit_logs ORDER BY id").fetchall(); con.close()
    assert [r[0] for r in rows]==['ACME_CHALLENGE_CREATED','ACME_CHALLENGE_REMOVED']
    assert token not in repr(rows)
    assert 'dns-123456abcdef.acme-dns.connect3.net.bd' in repr(rows)
