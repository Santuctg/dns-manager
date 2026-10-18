from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.database import get_db
from app.dependencies import get_current_user
from app.models.acme_dns import SslAcmeDelegation
from app.models.auth import User
from app.models.ssl import SslCertificate
from app.security import CSRF_COOKIE, SESSION_COOKIE, token_hash, validate_csrf_tokens
from app.services.acme_dns_service import (
    challenge_domain_for,
    delegated_fqdn_for,
    generate_delegation_id,
    verify_delegation,
    configured_acme_zone,
)
from app.services.auth_service import resolve_session
from app.services.audit_service import record_audit_event

router = APIRouter(prefix='/api/v1/ssl/certificates', tags=['acme-dns'])


def _super(user: User = Depends(get_current_user)) -> User:
    if not user.role or user.role.name != 'super_admin':
        raise HTTPException(403, 'Super Admin required')
    return user


def _csrf(request: Request, db: Session) -> None:
    cookie = request.cookies.get(CSRF_COOKIE)
    submitted = request.headers.get('X-CSRF-Token')
    if not validate_csrf_tokens(cookie, submitted):
        raise HTTPException(403, 'CSRF validation failed')
    raw = request.cookies.get(SESSION_COOKIE)
    sess = resolve_session(db, raw) if raw else None
    if sess is None or sess.csrf_hash != token_hash(submitted):
        raise HTTPException(403, 'CSRF validation failed')


def _cert(db: Session, domain: str) -> SslCertificate:
    from app.services.ssl_service import normalize_ssl_domain
    normalized = normalize_ssl_domain(domain)
    cert = db.scalar(
        select(SslCertificate)
        .options(selectinload(SslCertificate.delegation))
        .where(SslCertificate.domain == normalized)
    )
    if cert is None:
        raise HTTPException(404, 'Certificate configuration not found')
    return cert


def _out(row: SslAcmeDelegation) -> dict:
    return {
        'domain': row.domain,
        'challenge_domain': row.challenge_domain,
        'delegation_id': row.delegation_id,
        'delegated_fqdn': row.delegated_fqdn,
        'verified': row.verified,
        'verified_at': row.verified_at,
        'last_verification_error': row.last_verification_error,
    }


@router.post('/{domain}/delegation')
def create_delegation(
    domain: str,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(_super),
):
    _csrf(request, db)
    cert = _cert(db, domain)
    if cert.provider not in {'manual', 'acme_delegation'}:
        raise HTTPException(409, 'Provider conversion is only supported from manual to ACME Delegation')
    if cert.delegation is None:
        zone = configured_acme_zone()
        delegation_id = generate_delegation_id()
        row = SslAcmeDelegation(
            certificate_id=cert.id,
            domain=cert.domain,
            challenge_domain=challenge_domain_for(cert.domain),
            delegation_id=delegation_id,
            delegated_fqdn=delegated_fqdn_for(delegation_id, zone),
            verified=False,
        )
        db.add(row)
        cert.provider = 'acme_delegation'
        cert.auto_renew = False
        cert.last_renewal_status = None
        db.commit()
        db.refresh(row)
        record_audit_event(
            db,
            user=user,
            action='ACME_DELEGATION_CREATED',
            object_type='ssl_certificate',
            object_id=cert.domain,
            source_ip=request.client.host if request.client else 'unknown',
            new_value={'delegated_fqdn': row.delegated_fqdn},
        )
        return _out(row)
    if cert.provider == 'manual':
        cert.provider = 'acme_delegation'
        cert.auto_renew = False
        cert.last_renewal_status = None
        db.commit()
    return _out(cert.delegation)


@router.get('/{domain}/delegation')
def get_delegation(domain: str, db: Session = Depends(get_db), _user: User = Depends(_super)):
    cert = _cert(db, domain)
    if cert.delegation is None:
        raise HTTPException(404, 'ACME delegation not configured')
    return _out(cert.delegation)


@router.post('/{domain}/delegation/verify')
def verify_delegation_endpoint(
    domain: str,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(_super),
):
    _csrf(request, db)
    cert = _cert(db, domain)
    row = cert.delegation
    if row is None:
        raise HTTPException(404, 'ACME delegation not configured')
    result = verify_delegation(row.challenge_domain, row.delegated_fqdn)
    row.verified = bool(result.get('verified'))
    row.verified_at = datetime.now(timezone.utc) if row.verified else None
    row.last_verification_error = result.get('error')
    db.commit(); db.refresh(row)
    record_audit_event(
        db,
        user=user,
        action='ACME_DELEGATION_VERIFIED' if row.verified else 'ACME_DELEGATION_VERIFY_FAILED',
        object_type='ssl_certificate',
        object_id=cert.domain,
        source_ip=request.client.host if request.client else 'unknown',
        new_value={'delegated_fqdn': row.delegated_fqdn, 'verified': row.verified},
    )
    return _out(row)


@router.delete('/{domain}/delegation')
def delete_delegation(
    domain: str,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(_super),
):
    _csrf(request, db)
    cert=_cert(db,domain)
    row=cert.delegation
    if row is None:
        raise HTTPException(404,'ACME delegation not configured')
    if cert.auto_renew:
        raise HTTPException(409,'Disable auto renew before removing ACME delegation')
    delegated_fqdn=row.delegated_fqdn
    db.delete(row)
    if cert.provider=='acme_delegation':
        cert.provider='manual'
        cert.last_renewal_status=None
    db.commit()
    record_audit_event(
        db,user=user,action='ACME_DELEGATION_REMOVED',object_type='ssl_certificate',
        object_id=cert.domain,source_ip=request.client.host if request.client else 'unknown',
        old_value={'delegated_fqdn':delegated_fqdn},
    )
    return {'deleted':True,'domain':cert.domain,'delegated_fqdn':delegated_fqdn}
