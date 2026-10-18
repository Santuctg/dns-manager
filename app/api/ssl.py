from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.database import get_db
from app.dependencies import get_current_user
from app.models.auth import User
from app.models.mapping import Mapping
from app.models.ssl import SslCertificate, SslProviderCredential
from app.models.hosted_acme import SslHostedAcmeCredential
from app.models.acme_dns import SslAcmeDelegation
from app.security import CSRF_COOKIE, SESSION_COOKIE, token_hash, validate_csrf_tokens
from app.services.auth_service import resolve_session
from app.services.ssl_crypto import encrypt_secret, decrypt_secret
from app.services.ssl_service import normalize_ssl_domain, reconcile_all_certificates, reconcile_certificate
from app.services.privileged_helper import PrivilegedHelper, PrivilegedHelperError
from app.services.audit_service import record_audit_event
from app.services.acme_dns_service import verify_delegation, generate_delegation_id, challenge_domain_for as legacy_challenge_domain_for, delegated_fqdn_for, configured_acme_zone
from app.config import load_hosted_acme_config
from app.services.hosted_acme_service import HostedAcmeClient, HostedAcmeError, challenge_domain_for, verify_hosted_cname

router=APIRouter(prefix='/api/v1/ssl',tags=['ssl'])

def _ip(request): return request.client.host if request.client else 'unknown'


def _super(user:User=Depends(get_current_user))->User:
    if not user.role or user.role.name!='super_admin': raise HTTPException(403,'Super Admin required')
    return user


def _csrf(request:Request,db:Session):
    cookie=request.cookies.get(CSRF_COOKIE); submitted=request.headers.get('X-CSRF-Token')
    if not validate_csrf_tokens(cookie,submitted): raise HTTPException(403,'CSRF validation failed')
    raw=request.cookies.get(SESSION_COOKIE); sess=resolve_session(db,raw) if raw else None
    if sess is None or sess.csrf_hash!=token_hash(submitted): raise HTTPException(403,'CSRF validation failed')


def _out(cert:SslCertificate)->dict:
    data={k:getattr(cert,k) for k in ('domain','provider','auto_renew','redirect_http','status','issuer','issued_at','expires_at','last_renewal_status','last_error')}
    delegation=cert.delegation
    data.update({
        'delegation_verified': bool(delegation and delegation.verified),
        'challenge_domain': delegation.challenge_domain if delegation else None,
        'delegated_fqdn': delegation.delegated_fqdn if delegation else None,
        'hosted_acme_verified': bool(cert.hosted_acme and cert.hosted_acme.verified),
        'hosted_acme_fulldomain': cert.hosted_acme.fulldomain if cert.hosted_acme else None,
        'hosted_acme_challenge_domain': cert.hosted_acme.challenge_domain if cert.hosted_acme else None,
    })
    return data


def _cert(db,domain):
    d=normalize_ssl_domain(domain)
    row=db.scalar(select(SslCertificate).options(selectinload(SslCertificate.credential),selectinload(SslCertificate.delegation),selectinload(SslCertificate.hosted_acme)).where(SslCertificate.domain==d))
    if row is None: raise HTTPException(404,'Certificate configuration not found')
    return row

@router.get('/certificates')
def list_certificates(db:Session=Depends(get_db),_user:User=Depends(_super)):
    reconcile_all_certificates(db)
    rows=db.scalars(select(SslCertificate).order_by(SslCertificate.domain)).all()
    return [_out(x) for x in rows]

@router.get('/certificates/{domain}')
def get_certificate(domain:str,db:Session=Depends(get_db),_user:User=Depends(_super)):
    cert=_cert(db,domain)
    reconcile_certificate(db,cert)
    return _out(cert)

@router.post('/certificates',status_code=status.HTTP_201_CREATED)
def create_certificate(payload:dict,request:Request,db:Session=Depends(get_db),_user:User=Depends(_super)):
    _csrf(request,db)
    try:d=normalize_ssl_domain(str(payload.get('domain','')))
    except ValueError as exc: raise HTTPException(422,str(exc))
    provider=payload.get('provider','manual')
    if provider not in {'cloudflare','manual','acme_delegation'}: raise HTTPException(422,'Unsupported provider')
    if db.scalar(select(SslCertificate).where(SslCertificate.domain==d)): raise HTTPException(409,'Certificate configuration already exists')
    cert=SslCertificate(domain=d,provider=provider,auto_renew=False,redirect_http=bool(payload.get('redirect_http',True)))
    db.add(cert); db.flush()
    token=payload.get('api_token')
    if provider=='cloudflare':
        if not isinstance(token,str) or not token.strip(): raise HTTPException(422,'Cloudflare API token required')
        db.add(SslProviderCredential(certificate_id=cert.id,provider='cloudflare',token_ciphertext=encrypt_secret(token.strip()),token_last4=token.strip()[-4:]))
    elif provider=='acme_delegation':
        zone=configured_acme_zone()
        delegation_id=generate_delegation_id()
        db.add(SslAcmeDelegation(certificate_id=cert.id,domain=d,challenge_domain=challenge_domain_for(d),delegation_id=delegation_id,delegated_fqdn=delegated_fqdn_for(delegation_id,zone),verified=False))
    db.commit(); db.refresh(cert)
    reconcile_certificate(db,cert)
    record_audit_event(db,user=_user,action='SSL_SETTINGS_UPDATED',object_type='ssl_certificate',object_id=d,source_ip=_ip(request),new_value={'domain':d,'provider':provider,'auto_renew':cert.auto_renew,'redirect_http':cert.redirect_http}); return _out(cert)

@router.put('/settings/{domain}')
def update_settings(domain:str,payload:dict,request:Request,db:Session=Depends(get_db),_user:User=Depends(_super)):
    _csrf(request,db); cert=_cert(db,domain)
    old_value={'provider':cert.provider,'auto_renew':cert.auto_renew,'redirect_http':cert.redirect_http}
    requested_provider=payload.get('provider')
    token_value=payload.get('api_token')
    converted_to_cloudflare=False

    if requested_provider is not None:
        if requested_provider not in {'cloudflare','manual'}:
            raise HTTPException(422,'Unsupported provider')
        if cert.provider=='manual' and requested_provider=='cloudflare':
            if not isinstance(token_value,str) or not token_value.strip():
                raise HTTPException(422,'Cloudflare API token required')
            token=token_value.strip()
            if cert.credential is None:
                cert.credential=SslProviderCredential(provider='cloudflare',token_ciphertext=encrypt_secret(token),token_last4=token[-4:])
            else:
                cert.credential.provider='cloudflare'
                cert.credential.token_ciphertext=encrypt_secret(token)
                cert.credential.token_last4=token[-4:]
            cert.provider='cloudflare'
            cert.auto_renew=False
            cert.last_renewal_status=None
            converted_to_cloudflare=True
        elif requested_provider!=cert.provider:
            raise HTTPException(409,'Provider conversion is only supported from manual to cloudflare')

    if payload.get('api_token') and cert.provider=='cloudflare' and not (requested_provider=='cloudflare' and old_value['provider']=='manual'):
        token=str(payload['api_token']).strip()
        if not token:
            raise HTTPException(422,'Cloudflare API token required')
        if cert.credential is None:
            cert.credential=SslProviderCredential(provider='cloudflare',token_ciphertext=encrypt_secret(token),token_last4=token[-4:])
        else:
            cert.credential.provider='cloudflare'
            cert.credential.token_ciphertext=encrypt_secret(token)
            cert.credential.token_last4=token[-4:]

    if 'auto_renew' in payload and not converted_to_cloudflare:
        requested_auto=bool(payload['auto_renew'])
        if requested_auto:
            if cert.provider not in {'cloudflare','acme_delegation','acme_dns_hosted'}:
                raise HTTPException(409,'Auto renew requires an automated DNS-01 provider')
            if cert.provider=='acme_delegation' and (cert.delegation is None or not cert.delegation.verified):
                raise HTTPException(409,'Verify ACME delegation before enabling auto renew')
            if cert.provider=='acme_dns_hosted' and (cert.hosted_acme is None or not cert.hosted_acme.verified):
                raise HTTPException(409,'Verify Hosted ACME-DNS CNAME before enabling auto renew')
            if cert.last_renewal_status!='TEST_SUCCESS':
                raise HTTPException(409,'Run a successful renewal test before enabling auto renew')
        cert.auto_renew=requested_auto
    if 'redirect_http' in payload:
        cert.redirect_http=bool(payload['redirect_http'])

    db.commit(); db.refresh(cert)
    record_audit_event(db,user=_user,action='SSL_SETTINGS_UPDATED',object_type='ssl_certificate',object_id=cert.domain,source_ip=_ip(request),old_value=old_value,new_value={'provider':cert.provider,'auto_renew':cert.auto_renew,'redirect_http':cert.redirect_http})
    return _out(cert)


def _token(cert):
    return decrypt_secret(cert.credential.token_ciphertext) if cert.credential else None

def _hosted_out(cert: SslCertificate) -> dict:
    cred = cert.hosted_acme
    if cred is None:
        raise HTTPException(404, 'Hosted ACME-DNS registration not configured')
    return {
        'domain': cert.domain,
        'provider': cert.provider,
        'server_url': cred.server_url,
        'subdomain': cred.subdomain,
        'fulldomain': cred.fulldomain,
        'challenge_domain': cred.challenge_domain,
        'verified': cred.verified,
        'verified_at': cred.verified_at,
        'last_verification_error': cred.last_verification_error,
        'auto_renew': cert.auto_renew,
        'last_renewal_status': cert.last_renewal_status,
    }


@router.post('/certificates/{domain}/hosted-acme/register')
def hosted_acme_register(domain: str, request: Request, db: Session = Depends(get_db), _user: User = Depends(_super)):
    _csrf(request, db)
    cert = _cert(db, domain)
    if cert.provider not in {'manual', 'acme_dns_hosted'}:
        raise HTTPException(409, 'Provider conversion is only supported from manual to Hosted ACME-DNS')
    if cert.hosted_acme is not None:
        updated=cert.hosted_acme.updated_at
        if updated.tzinfo is None:
            updated=updated.replace(tzinfo=timezone.utc)
        if (datetime.now(timezone.utc)-updated).total_seconds() < 60:
            raise HTTPException(429,'Hosted ACME-DNS registration can be retried after 60 seconds')
    config = load_hosted_acme_config()
    if not config.enabled:
        raise HTTPException(409, 'Hosted ACME-DNS provider is disabled')
    try:
        registration = HostedAcmeClient(config.server_url, config.http_timeout).register()
    except HostedAcmeError as exc:
        raise HTTPException(502, str(exc))
    if cert.hosted_acme is None:
        cert.hosted_acme = SslHostedAcmeCredential(
            server_url=config.server_url,
            username_ciphertext=encrypt_secret(registration.username),
            password_ciphertext=encrypt_secret(registration.password),
            subdomain=registration.subdomain,
            fulldomain=registration.fulldomain.rstrip('.').lower(),
            challenge_domain=challenge_domain_for(cert.domain),
            verified=False,
        )
    else:
        cred=cert.hosted_acme
        cred.server_url=config.server_url
        cred.username_ciphertext=encrypt_secret(registration.username)
        cred.password_ciphertext=encrypt_secret(registration.password)
        cred.subdomain=registration.subdomain
        cred.fulldomain=registration.fulldomain.rstrip('.').lower()
        cred.challenge_domain=challenge_domain_for(cert.domain)
        cred.verified=False
        cred.verified_at=None
        cred.last_verification_error=None
    cert.provider='acme_dns_hosted'
    cert.auto_renew=False
    cert.last_renewal_status=None
    db.commit(); db.refresh(cert)
    record_audit_event(db,user=_user,action='HOSTED_ACME_REGISTERED',object_type='ssl_certificate',object_id=cert.domain,source_ip=_ip(request),new_value={'server_url':config.server_url,'fulldomain':cert.hosted_acme.fulldomain})
    return _hosted_out(cert)


@router.get('/certificates/{domain}/hosted-acme')
def hosted_acme_status(domain: str, db: Session = Depends(get_db), _user: User = Depends(_super)):
    return _hosted_out(_cert(db, domain))


@router.delete('/certificates/{domain}/hosted-acme')
def hosted_acme_delete(domain: str, request: Request, db: Session = Depends(get_db), _user: User = Depends(_super)):
    _csrf(request, db)
    cert=_cert(db,domain)
    if cert.hosted_acme is None:
        raise HTTPException(404,'Hosted ACME-DNS registration not configured')
    if cert.auto_renew:
        raise HTTPException(409,'Disable auto renew before removing Hosted ACME-DNS credentials')
    fulldomain=cert.hosted_acme.fulldomain
    cert.hosted_acme=None
    if cert.provider=='acme_dns_hosted':
        cert.provider='manual'; cert.last_renewal_status=None
    db.commit()
    record_audit_event(db,user=_user,action='HOSTED_ACME_CREDENTIALS_REMOVED',object_type='ssl_certificate',object_id=cert.domain,source_ip=_ip(request),old_value={'fulldomain':fulldomain})
    return {'deleted':True,'domain':cert.domain,'remote_deleted':False}


@router.post('/certificates/{domain}/hosted-acme/verify')
def hosted_acme_verify(domain: str, request: Request, db: Session = Depends(get_db), _user: User = Depends(_super)):
    _csrf(request, db)
    cert = _cert(db, domain)
    cred = cert.hosted_acme
    if cred is None:
        raise HTTPException(404, 'Hosted ACME-DNS registration not configured')
    result = verify_hosted_cname(cred.challenge_domain, cred.fulldomain)
    cred.verified = bool(result.get('verified'))
    cred.verified_at = datetime.now(timezone.utc) if cred.verified else None
    cred.last_verification_error = result.get('error')
    if not cred.verified:
        cert.auto_renew = False
    db.commit(); db.refresh(cert)
    record_audit_event(db,user=_user,action='HOSTED_ACME_VERIFY_SUCCESS' if cred.verified else 'HOSTED_ACME_VERIFY_FAILED',object_type='ssl_certificate',object_id=cert.domain,source_ip=_ip(request),new_value={'fulldomain':cred.fulldomain,'verified':cred.verified})
    return _hosted_out(cert)


@router.post('/certificates/{domain}/issue')
def issue(domain:str,request:Request,db:Session=Depends(get_db),_user:User=Depends(_super)):
    _csrf(request,db); cert=_cert(db,domain)
    if cert.provider=='manual': raise HTTPException(409,'Use manual DNS workflow')
    if cert.provider=='acme_delegation' and (cert.delegation is None or not cert.delegation.verified):
        raise HTTPException(409,'ACME delegation must be verified before certificate issuance')
    if cert.provider=='acme_dns_hosted' and (cert.hosted_acme is None or not cert.hosted_acme.verified):
        raise HTTPException(409,'Hosted ACME-DNS CNAME must be verified before certificate issuance')
    try: PrivilegedHelper().ssl_issue(domain=cert.domain,provider=cert.provider,token=_token(cert))
    except PrivilegedHelperError as exc: cert.status='ERROR'; cert.last_error=str(exc); db.commit(); raise HTTPException(422,'Certificate issuance failed')
    reconcile_certificate(db,cert); cert.last_error=None; db.commit(); return _out(cert)

@router.post('/certificates/{domain}/renew')
def renew(domain:str,request:Request,db:Session=Depends(get_db),_user:User=Depends(_super)):
    _csrf(request,db); cert=_cert(db,domain)
    if cert.provider not in {'cloudflare','acme_delegation','acme_dns_hosted'}: raise HTTPException(409,'Manual certificates are not automatically renewable')
    if cert.provider=='acme_delegation':
        if cert.delegation is None or not cert.delegation.verified:
            raise HTTPException(409,'ACME delegation must be verified before renewal')
        check=verify_delegation(cert.delegation.challenge_domain,cert.delegation.delegated_fqdn)
        if not check.get('verified'):
            cert.delegation.verified=False
            cert.delegation.verified_at=None
            cert.delegation.last_verification_error=check.get('error') or 'Delegation verification failed'
            cert.auto_renew=False
            db.commit()
            raise HTTPException(409,'ACME delegation is no longer valid; verify delegation again')
    if cert.provider=='acme_dns_hosted':
        cred=cert.hosted_acme
        if cred is None or not cred.verified:
            raise HTTPException(409,'Hosted ACME-DNS CNAME must be verified before renewal')
        check=verify_hosted_cname(cred.challenge_domain,cred.fulldomain)
        if not check.get('verified'):
            cred.verified=False; cred.verified_at=None; cred.last_verification_error=check.get('error') or 'CNAME verification failed'
            cert.auto_renew=False; db.commit()
            raise HTTPException(409,'Hosted ACME-DNS CNAME is no longer valid; verify again')
    try: PrivilegedHelper().ssl_renew(domain=cert.domain,provider=cert.provider,token=_token(cert),force=True)
    except PrivilegedHelperError:
        cert.last_renewal_status='FAILED'; db.commit()
        if cert.provider in {'acme_delegation','acme_dns_hosted'}:
            action='HOSTED_ACME_RENEWAL_FAILED' if cert.provider=='acme_dns_hosted' else 'ACME_RENEWAL_FAILED'
            record_audit_event(db,user=_user,action=action,object_type='ssl_certificate',object_id=cert.domain,source_ip=_ip(request),status='failed',error_message='Certificate renewal failed')
        raise HTTPException(422,'Certificate renewal failed')
    reconcile_certificate(db,cert); cert.last_renewal_status='SUCCESS'; db.commit()
    if cert.provider in {'acme_delegation','acme_dns_hosted'}:
        action='HOSTED_ACME_RENEWAL_SUCCESS' if cert.provider=='acme_dns_hosted' else 'ACME_RENEWAL_SUCCESS'
        record_audit_event(db,user=_user,action=action,object_type='ssl_certificate',object_id=cert.domain,source_ip=_ip(request))
    return _out(cert)

@router.post('/certificates/{domain}/test-renewal')
def test_renewal(domain:str,request:Request,db:Session=Depends(get_db),_user:User=Depends(_super)):
    _csrf(request,db); cert=_cert(db,domain)
    if cert.provider not in {'cloudflare','acme_delegation','acme_dns_hosted'}: raise HTTPException(409,'Manual certificates do not support automated renewal tests')
    if cert.provider=='acme_delegation' and (cert.delegation is None or not cert.delegation.verified):
        raise HTTPException(409,'ACME delegation must be verified before renewal testing')
    if cert.provider=='acme_dns_hosted' and (cert.hosted_acme is None or not cert.hosted_acme.verified):
        raise HTTPException(409,'Hosted ACME-DNS CNAME must be verified before renewal testing')
    token=_token(cert)
    try:
        result=PrivilegedHelper().ssl_test_renewal(domain=cert.domain,provider=cert.provider,token=token)
    except PrivilegedHelperError as exc:
        safe=str(exc)
        if token:
            safe=safe.replace(token,'[REDACTED]')
        cert.last_renewal_status='TEST_FAILED'; cert.last_error=safe; cert.auto_renew=False; db.commit()
        if cert.provider in {'acme_delegation','acme_dns_hosted'}:
            action='HOSTED_ACME_TEST_FAILED' if cert.provider=='acme_dns_hosted' else 'ACME_RENEWAL_TEST_FAILED'
            record_audit_event(db,user=_user,action=action,object_type='ssl_certificate',object_id=cert.domain,source_ip=_ip(request),status='failed',error_message=safe)
        raise HTTPException(422,f'Renewal test failed: {safe}')
    cert.last_renewal_status='TEST_SUCCESS'; cert.last_error=None; db.commit()
    if cert.provider in {'acme_delegation','acme_dns_hosted'}:
        action='HOSTED_ACME_TEST_SUCCESS' if cert.provider=='acme_dns_hosted' else 'ACME_RENEWAL_TEST_SUCCESS'
        record_audit_event(db,user=_user,action=action,object_type='ssl_certificate',object_id=cert.domain,source_ip=_ip(request))
    return result

@router.post('/certificates/{domain}/apply')
def apply_cert(domain:str,request:Request,db:Session=Depends(get_db),_user:User=Depends(_super)):
    _csrf(request,db); cert=_cert(db,domain)
    mapping=db.scalar(select(Mapping).where(Mapping.domain==cert.domain, Mapping.enabled.is_(True)))
    upstream=None
    if mapping is not None:
        upstream={
            'scheme':mapping.upstream_scheme,
            'host':mapping.upstream_host,
            'port':mapping.upstream_port,
            'preserve_host':mapping.preserve_host,
            'websocket_enabled':mapping.websocket_enabled,
            'timeout':mapping.custom_timeout or 60,
        }
    try:return PrivilegedHelper().ssl_apply(cert.domain,cert.redirect_http,upstream=upstream)
    except PrivilegedHelperError: raise HTTPException(422,'SSL Nginx apply failed')

@router.post('/certificates/{domain}/manual-start')
def manual_start(domain:str,request:Request,db:Session=Depends(get_db),_user:User=Depends(_super)):
    _csrf(request,db); cert=_cert(db,domain)
    if cert.provider!='manual': raise HTTPException(409,'Certificate is not configured for manual DNS')
    try: result=PrivilegedHelper().ssl_issue(domain=cert.domain,provider='manual',token=None)
    except PrivilegedHelperError: raise HTTPException(422,'Unable to start manual DNS challenge')
    record_audit_event(db,user=_user,action='SSL_CERT_ISSUE_STARTED',object_type='ssl_certificate',object_id=cert.domain,source_ip=_ip(request))
    return result

@router.get('/manual-dns/{domain}')
def manual_status(domain:str,db:Session=Depends(get_db),_user:User=Depends(_super)):
    cert=_cert(db,domain)
    if cert.provider!='manual': raise HTTPException(409,'Certificate is not configured for manual DNS')
    try:return PrivilegedHelper().ssl_manual_status(cert.domain)
    except PrivilegedHelperError: raise HTTPException(422,'Manual DNS status unavailable')

@router.post('/manual-dns/{domain}/check')
def manual_check(domain:str,request:Request,db:Session=Depends(get_db),_user:User=Depends(_super)):
    _csrf(request,db); cert=_cert(db,domain)
    try: state=PrivilegedHelper().ssl_manual_status(cert.domain)
    except PrivilegedHelperError: raise HTTPException(422,'Manual DNS status unavailable')
    name,value=state.get('challenge_name'),state.get('challenge_value')
    if not name or not value: return {'ready':False,**state}
    try:
        import dns.resolver
        observed=[str(x).strip('"') for answer in dns.resolver.resolve(name,'TXT') for x in answer.strings]
    except Exception: observed=[]
    ready=value in observed
    if ready: PrivilegedHelper().ssl_manual_continue(cert.domain)
    return {'ready':ready,'observed':observed,**state}

@router.delete('/certificates/{domain}')
def delete_cert(domain:str,request:Request,db:Session=Depends(get_db),_user:User=Depends(_super)):
    _csrf(request,db); cert=_cert(db,domain)
    try: PrivilegedHelper().ssl_delete(cert.domain)
    except PrivilegedHelperError: pass
    if cert.delegation is not None:
        cert.auto_renew=False
        db.commit()
        return {'deleted':True,'domain':cert.domain,'delegation_preserved':True}
    db.delete(cert); db.commit(); return {'deleted':True,'domain':cert.domain,'delegation_preserved':False}
