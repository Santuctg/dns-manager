from pathlib import Path
import pytest

from app.config import load_hosted_acme_config
from app.services.hosted_acme_service import validate_hosted_acme_server_url


def test_hosted_acme_config_defaults_when_missing(tmp_path):
    cfg = load_hosted_acme_config(tmp_path / 'missing.conf')
    assert cfg.enabled is False
    assert cfg.server_url == 'https://auth.acme-dns.io'
    assert cfg.http_timeout == 15.0
    assert cfg.propagation_timeout == 120


def test_hosted_acme_config_parses_enabled_file(tmp_path):
    p = tmp_path / 'hosted.conf'
    p.write_text('HOSTED_ACME_ENABLED=true\nHOSTED_ACME_SERVER_URL=https://auth.acme-dns.io\nHOSTED_ACME_HTTP_TIMEOUT=15\nHOSTED_ACME_PROPAGATION_TIMEOUT=120\n')
    cfg = load_hosted_acme_config(p)
    assert cfg.enabled is True
    assert cfg.server_url == 'https://auth.acme-dns.io'


@pytest.mark.parametrize('url', [
    'http://auth.acme-dns.io',
    'https://user:pass@auth.acme-dns.io',
    'https://127.0.0.1',
    'https://localhost',
    'https://10.0.0.1',
    'https://auth.acme-dns.io/#frag',
])
def test_validate_hosted_acme_server_url_rejects_unsafe_urls(url):
    with pytest.raises(ValueError):
        validate_hosted_acme_server_url(url)


def test_validate_hosted_acme_server_url_accepts_public_https():
    assert validate_hosted_acme_server_url('https://auth.acme-dns.io/') == 'https://auth.acme-dns.io'


def test_hosted_update_uses_expected_headers_and_payload():
    import httpx
    from app.services.hosted_acme_service import HostedAcmeClient
    seen={}
    def handler(request):
        seen['headers']=dict(request.headers); seen['json']=request.content.decode()
        return httpx.Response(200,json={'txt':'ok'})
    client=HostedAcmeClient('https://auth.acme-dns.io', transport=httpx.MockTransport(handler))
    client.update_txt('user-secret','pass-secret','abc123','token-value')
    assert seen['headers']['x-api-user']=='user-secret'
    assert seen['headers']['x-api-key']=='pass-secret'
    assert '"subdomain":"abc123"' in seen['json'].replace(' ','')
    assert '"txt":"token-value"' in seen['json'].replace(' ','')


def test_hosted_update_failure_does_not_leak_secrets():
    import httpx
    from app.services.hosted_acme_service import HostedAcmeClient, HostedAcmeError
    def handler(request):
        return httpx.Response(500,text='server failed')
    client=HostedAcmeClient('https://auth.acme-dns.io', transport=httpx.MockTransport(handler))
    with pytest.raises(HostedAcmeError) as exc:
        client.update_txt('user-secret','pass-secret','abc123','token-value')
    text=str(exc.value)
    assert 'user-secret' not in text and 'pass-secret' not in text and 'token-value' not in text


def test_hosted_client_rejects_hostname_resolving_to_private_ip(monkeypatch):
    import socket
    from app.services.hosted_acme_service import HostedAcmeClient, HostedAcmeError
    monkeypatch.setattr(socket,'getaddrinfo',lambda *a,**k:[(socket.AF_INET,socket.SOCK_STREAM,6,'',('10.0.0.5',443))])
    client=HostedAcmeClient('https://provider.example')
    with pytest.raises(HostedAcmeError,match='public'):
        client._ensure_public_resolution()
