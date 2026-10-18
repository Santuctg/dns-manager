#!/usr/bin/python3
from __future__ import annotations

import json
import os
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Mapping

from app.config import get_settings
from app.services.privileged_helper import PrivilegedHelper


def _base_domain(domain: str) -> str:
    value=(domain or '').strip().lower().rstrip('.')
    if value.startswith('*.'):
        value=value[2:]
    if not value or '/' in value or '\\' in value or '..' in value:
        raise RuntimeError('invalid Certbot domain')
    return value


def _lookup_delegation(database_path: str | Path, domain: str) -> tuple[str, bool]:
    base=_base_domain(domain)
    try:
        con=sqlite3.connect(f'file:{Path(database_path)}?mode=ro',uri=True)
        try:
            row=con.execute(
                'SELECT delegated_fqdn, verified FROM ssl_acme_delegations WHERE domain=? LIMIT 1',
                (base,),
            ).fetchone()
        finally:
            con.close()
    except sqlite3.Error as exc:
        raise RuntimeError('ACME delegation database unavailable') from exc
    if not row:
        raise RuntimeError('ACME delegation not configured')
    return str(row[0]), bool(row[1])


def _record_hook_audit(database_path: str | Path, action: str, domain: str, hostname: str, *, status: str="success", error_message: str | None=None) -> None:
    """Best-effort audit that intentionally never receives the ACME validation token."""
    try:
        con=sqlite3.connect(str(database_path),timeout=5)
        try:
            con.execute(
                "INSERT INTO audit_logs(username,action,object_type,object_id,new_value,status,error_message,created_at) VALUES(?,?,?,?,?,?,?,?)",
                (
                    "system:acme-hook", action, "ssl_certificate", _base_domain(domain),
                    json.dumps({"delegated_fqdn":hostname},separators=(",",":"),sort_keys=True),
                    status, error_message, datetime.now(timezone.utc).isoformat(),
                ),
            )
            con.commit()
        finally:
            con.close()
    except sqlite3.Error:
        # ACME availability must not depend on audit storage availability.
        return


def wait_for_txt(hostname: str, value: str, *, timeout: int=120, interval: float=2.0) -> bool:
    import dns.resolver
    deadline=time.monotonic()+timeout
    resolvers=('1.1.1.1','8.8.8.8')
    while time.monotonic()<deadline:
        ok=True
        for nameserver in resolvers:
            resolver=dns.resolver.Resolver(configure=False)
            resolver.nameservers=[nameserver]
            resolver.timeout=min(3.0, max(1.0, interval+1.0))
            resolver.lifetime=4.0
            try:
                answers=resolver.resolve(hostname,'TXT')
                values=[]
                for answer in answers:
                    if getattr(answer,'strings',None):
                        values.append(b''.join(answer.strings).decode())
                    else:
                        values.append(str(answer).strip('"'))
                if value not in values:
                    ok=False; break
            except Exception:
                ok=False; break
        if ok:
            return True
        time.sleep(interval)
    return False


def run_hook(
    mode: str,
    *,
    env: Mapping[str,str] | None=None,
    database_path: str | Path | None=None,
    helper=None,
    waiter=wait_for_txt,
) -> int:
    env=dict(os.environ if env is None else env)
    domain=env.get('CERTBOT_DOMAIN')
    validation=env.get('CERTBOT_VALIDATION')
    if not domain or not validation:
        raise RuntimeError('required Certbot environment is missing')
    hostname, verified=_lookup_delegation(database_path or get_settings().database_path, domain)
    if not verified:
        raise RuntimeError('ACME delegation is not verified')
    db_path=database_path or get_settings().database_path
    helper=helper or PrivilegedHelper()
    if mode=='auth':
        helper.acme_txt_set(hostname,validation)
        _record_hook_audit(db_path,'ACME_CHALLENGE_CREATED',domain,hostname)
        if waiter is not None and not waiter(hostname,validation):
            try:
                helper.acme_txt_delete(hostname,validation)
                _record_hook_audit(db_path,'ACME_CHALLENGE_REMOVED',domain,hostname)
            finally:
                raise RuntimeError('ACME TXT propagation timed out')
        return 0
    if mode=='cleanup':
        try:
            helper.acme_txt_delete(hostname,validation)
        except Exception:
            _record_hook_audit(db_path,'ACME_CLEANUP_FAILED',domain,hostname,status='failed',error_message='ACME TXT cleanup failed')
            raise
        _record_hook_audit(db_path,'ACME_CHALLENGE_REMOVED',domain,hostname)
        return 0
    raise RuntimeError('unsupported ACME hook mode')


def main() -> int:
    import sys
    if len(sys.argv)!=2:
        raise SystemExit('usage: dns-manager-acme-dns-hook auth|cleanup')
    return run_hook(sys.argv[1])


if __name__=='__main__':
    raise SystemExit(main())
