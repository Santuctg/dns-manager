from pathlib import Path
from types import SimpleNamespace
from privileged.ssl_helper import SslHelperOps


def test_cloudflare_token_uses_temp_file_and_is_cleaned(tmp_path):
    seen=[]
    token='secret-token-1234'
    le=tmp_path/'le'
    renewal=le/'renewal'
    renewal.mkdir(parents=True)
    def runner(argv, **kwargs):
        seen.append(list(argv))
        cred=Path(argv[argv.index('--dns-cloudflare-credentials')+1])
        assert cred.exists()
        assert oct(cred.stat().st_mode & 0o777)=='0o600'
        assert token in cred.read_text()
        assert token not in ' '.join(argv)
        (renewal/'dns.example.com.conf').write_text('[renewalparams]\nauthenticator = dns-cloudflare\n')
        return SimpleNamespace(returncode=0,stdout='ok',stderr='')
    ops=SslHelperOps(letsencrypt_root=le, runner=runner, work_root=tmp_path/'work')
    result=ops.ssl_issue('dns.example.com','cloudflare',token)
    assert result['issued'] is True
    assert not list((tmp_path/'work').glob('cf-*'))


def test_cloudflare_failure_redacts_token(tmp_path):
    token='secret-token-1234'
    def runner(argv, **kwargs): return SimpleNamespace(returncode=1,stdout='',stderr='API rejected secret-token-1234')
    ops=SslHelperOps(letsencrypt_root=tmp_path/'le', runner=runner, work_root=tmp_path/'work')
    try: ops.ssl_issue('dns.example.com','cloudflare',token)
    except RuntimeError as exc: assert token not in str(exc)


def test_real_cloudflare_issue_verifies_renewal_lineage_authenticator(tmp_path):
    token='secret-token-1234'
    domain='dns.example.com'
    le=tmp_path/'le'
    renewal=le/'renewal'
    renewal.mkdir(parents=True)
    def runner(argv, **kwargs):
        (renewal/f'{domain}.conf').write_text('[renewalparams]\nauthenticator = dns-cloudflare\n')
        return SimpleNamespace(returncode=0,stdout='ok',stderr='')
    ops=SslHelperOps(letsencrypt_root=le, runner=runner, work_root=tmp_path/'work')
    out=ops.ssl_issue(domain,'cloudflare',token)
    assert out['issued'] is True
    assert out['renewal_authenticator']=='dns-cloudflare'


def test_real_cloudflare_issue_rejects_wrong_renewal_authenticator(tmp_path):
    token='secret-token-1234'
    domain='dns.example.com'
    le=tmp_path/'le'
    renewal=le/'renewal'
    renewal.mkdir(parents=True)
    def runner(argv, **kwargs):
        (renewal/f'{domain}.conf').write_text('[renewalparams]\nauthenticator = manual\n')
        return SimpleNamespace(returncode=0,stdout='ok',stderr='')
    ops=SslHelperOps(letsencrypt_root=le, runner=runner, work_root=tmp_path/'work')
    import pytest
    with pytest.raises(RuntimeError, match='renewal lineage is not configured for dns-cloudflare'):
        ops.ssl_issue(domain,'cloudflare',token)


def test_cloudflare_token_cannot_inject_credentials_file_settings(tmp_path):
    import pytest
    calls=[]
    ops=SslHelperOps(letsencrypt_root=tmp_path/'le', runner=lambda argv, **kw: calls.append(argv), work_root=tmp_path/'work')
    for bad in ('secret-token-1234\ndns_cloudflare_email = x@example.com', 'secret token with spaces 1234', '', None, 'x'*257):
        with pytest.raises(ValueError):
            ops.ssl_issue('dns.example.com','cloudflare',bad) if bad else ops._cloudflare_run('dns.example.com',bad)
    assert calls == []
    assert not (tmp_path/'work').exists() or not list((tmp_path/'work').glob('cf-*'))


def test_api_schema_rejects_tokens_with_control_characters():
    import pytest
    from pydantic import ValidationError
    from app.schemas.ssl import SslCertificateCreate
    assert SslCertificateCreate(domain='dns.example.com', provider='cloudflare', api_token=' abcDEF_123-xyz.0987654321 ').api_token == 'abcDEF_123-xyz.0987654321'
    for bad in ('abc\ndns_cloudflare_email=x', 'abc def', 'ünïcode-token-123456789'):
        with pytest.raises(ValidationError):
            SslCertificateCreate(domain='dns.example.com', provider='cloudflare', api_token=bad)
