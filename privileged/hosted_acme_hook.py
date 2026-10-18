#!/usr/bin/python3
from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Mapping, Callable

from app.config import get_settings, load_hosted_acme_config
from app.services.hosted_acme_service import HostedAcmeClient, wait_for_hosted_txt
from app.services.ssl_crypto import decrypt_secret


def _base_domain(domain: str) -> str:
    value=(domain or '').strip().lower().rstrip('.')
    if value.startswith('*.'):
        value=value[2:]
    if not value or '/' in value or '\\' in value or '..' in value:
        raise RuntimeError('invalid Certbot domain')
    return value


def _lookup_hosted(database_path: str | Path, domain: str) -> dict:
    base=_base_domain(domain)
    try:
        con=sqlite3.connect(f'file:{Path(database_path)}?mode=ro',uri=True)
        try:
            row=con.execute('''
                SELECT c.server_url,c.username_ciphertext,c.password_ciphertext,c.subdomain,c.fulldomain,c.challenge_domain,c.verified
                FROM ssl_acme_dns_credentials c
                JOIN ssl_certificates s ON s.id=c.certificate_id
                WHERE s.domain=? AND s.provider='acme_dns_hosted' LIMIT 1
            ''',(base,)).fetchone()
        finally:
            con.close()
    except sqlite3.Error as exc:
        raise RuntimeError('Hosted ACME credential database unavailable') from exc
    if not row:
        raise RuntimeError('Hosted ACME-DNS registration not configured')
    if not bool(row[6]):
        raise RuntimeError('Hosted ACME-DNS registration is not verified')
    return {
        'server_url':str(row[0]), 'username':decrypt_secret(str(row[1])), 'password':decrypt_secret(str(row[2])),
        'subdomain':str(row[3]), 'fulldomain':str(row[4]), 'challenge_domain':str(row[5]),
    }




def _record_audit(database_path: str | Path, action: str, domain: str, fulldomain: str, *, status: str='failed', error_message: str | None=None) -> None:
    try:
        con=sqlite3.connect(str(database_path),timeout=5)
        try:
            con.execute(
                "INSERT INTO audit_logs(username,action,object_type,object_id,new_value,status,error_message,created_at) VALUES(?,?,?,?,?,?,?,?)",
                ('system:hosted-acme-hook',action,'ssl_certificate',_base_domain(domain),json.dumps({'fulldomain':fulldomain},separators=(',',':'),sort_keys=True),status,error_message,datetime.now(timezone.utc).isoformat()),
            )
            con.commit()
        finally:
            con.close()
    except sqlite3.Error:
        return


def run_hook(mode: str, *, env: Mapping[str,str] | None=None, database_path: str | Path | None=None,
             client_factory: Callable | None=None, waiter=wait_for_hosted_txt) -> int:
    env=dict(os.environ if env is None else env)
    domain=env.get('CERTBOT_DOMAIN'); validation=env.get('CERTBOT_VALIDATION')
    if not domain or not validation:
        raise RuntimeError('required Certbot environment is missing')
    record=_lookup_hosted(database_path or get_settings().database_path,domain)
    if mode=='cleanup':
        # Hosted acme-dns registrations replace the TXT value on the next update.
        return 0
    if mode!='auth':
        raise RuntimeError('unsupported Hosted ACME hook mode')
    cfg=load_hosted_acme_config()
    if record['server_url'] != cfg.server_url:
        raise RuntimeError('Hosted ACME-DNS server configuration mismatch')
    factory=client_factory or (lambda url,timeout: HostedAcmeClient(url,timeout))
    client=factory(record['server_url'], cfg.http_timeout)
    try:
        client.update_txt(record['username'],record['password'],record['subdomain'],validation)
    except Exception:
        _record_audit(database_path or get_settings().database_path,'HOSTED_ACME_UPDATE_FAILED',domain,record['fulldomain'],error_message='Hosted ACME TXT update failed')
        raise
    if waiter is not None:
        try:
            ok=waiter(record['fulldomain'],validation,timeout=cfg.propagation_timeout,interval=2)
        except TypeError:
            ok=waiter(record['fulldomain'],validation)
        if ok is False:
            raise RuntimeError('Hosted ACME TXT propagation timed out')
    return 0


def main() -> int:
    import sys
    if len(sys.argv)!=2:
        raise SystemExit('usage: dns-manager-hosted-acme-hook auth|cleanup')
    return run_hook(sys.argv[1])


if __name__=='__main__':
    raise SystemExit(main())
