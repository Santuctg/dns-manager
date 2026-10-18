from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import re

from cryptography import x509

_DOMAIN_RE = re.compile(r'^(?=.{4,253}\.?$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\.?$', re.I)


def normalize_ssl_domain(value: str) -> str:
    value = value.strip().rstrip('.')
    try:
        ascii_domain = value.encode('idna').decode('ascii').lower()
    except Exception as exc:
        raise ValueError('invalid domain') from exc
    if not _DOMAIN_RE.fullmatch(ascii_domain) or '*' in value or '/' in value or ':' in value or ' ' in value:
        raise ValueError('invalid domain')
    return ascii_domain


def inspect_certificate(domain: str, *, letsencrypt_root: Path | str = '/etc/letsencrypt') -> dict:
    domain = normalize_ssl_domain(domain)
    cert_path = Path(letsencrypt_root) / 'live' / domain / 'fullchain.pem'
    if not cert_path.is_file():
        return {'domain': domain, 'status': 'NOT_ISSUED', 'issuer': None, 'issued_at': None, 'expires_at': None, 'days_remaining': None}
    try:
        cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
        now = datetime.now(timezone.utc)
        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc
        days = (not_after - now).days
        if not_after <= now:
            status='EXPIRED'
        elif days <= 30:
            status='EXPIRING'
        else:
            status='ISSUED'
        issuer = cert.issuer.rfc4514_string()
        return {'domain':domain,'status':status,'issuer':issuer,'issued_at':not_before,'expires_at':not_after,'days_remaining':days}
    except Exception as exc:
        return {'domain':domain,'status':'ERROR','issuer':None,'issued_at':None,'expires_at':None,'days_remaining':None,'error':str(exc)}



def apply_certificate_info(cert, info: dict):
    cert.status = info['status']
    cert.issuer = info.get('issuer')
    cert.issued_at = info.get('issued_at')
    cert.expires_at = info.get('expires_at')
    if info['status'] != 'ERROR':
        cert.last_error = None
    return cert


def _parse_helper_datetime(value):
    if value is None or isinstance(value, datetime):
        return value
    return datetime.fromisoformat(str(value))


def inspect_certificate_via_helper(domain: str, *, helper=None) -> dict:
    domain = normalize_ssl_domain(domain)
    if helper is None:
        from app.services.privileged_helper import PrivilegedHelper
        helper = PrivilegedHelper()
    info = dict(helper.ssl_status(domain))
    info['domain'] = domain
    info.setdefault('status', 'ISSUED' if info.get('certificate_present') else 'NOT_ISSUED')
    info.setdefault('issuer', None)
    info.setdefault('issued_at', None)
    info.setdefault('expires_at', None)
    info.setdefault('days_remaining', None)
    info['issued_at'] = _parse_helper_datetime(info.get('issued_at'))
    info['expires_at'] = _parse_helper_datetime(info.get('expires_at'))
    return info


def reconcile_certificate(db, cert, *, letsencrypt_root: Path | str | None = None, helper=None) -> dict:
    if letsencrypt_root is None:
        info = inspect_certificate_via_helper(cert.domain, helper=helper)
    else:
        info = inspect_certificate(cert.domain, letsencrypt_root=letsencrypt_root)
    apply_certificate_info(cert, info)
    db.commit()
    db.refresh(cert)
    return info

def reconcile_all_certificates(db, *, letsencrypt_root: Path | str | None = None, helper=None) -> list[dict]:
    from sqlalchemy import select
    from app.models.ssl import SslCertificate
    rows = list(db.scalars(select(SslCertificate)).all())
    results = []
    for cert in rows:
        if letsencrypt_root is None:
            info = inspect_certificate_via_helper(cert.domain, helper=helper)
        else:
            info = inspect_certificate(cert.domain, letsencrypt_root=letsencrypt_root)
        apply_certificate_info(cert, info)
        results.append(info)
    db.commit()
    return results
