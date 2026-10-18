import json
from pathlib import Path
from types import SimpleNamespace
import pytest

from privileged.helper_server import handle_request
from privileged.ssl_helper import SslHelperOps

class FakeOps:
    def ssl_status(self, domain): return {'domain':domain,'status':'NOT_ISSUED'}

def test_helper_rejects_unknown_and_arbitrary_fields():
    assert handle_request(json.dumps({'command':'ssl_status','domain':'dns.example.com','argv':['rm']}), FakeOps())['ok'] is False
    assert handle_request(json.dumps({'command':'wat'}), FakeOps())['ok'] is False

def test_helper_accepts_fixed_ssl_status():
    out=handle_request(json.dumps({'command':'ssl_status','domain':'dns.example.com'}), FakeOps())
    assert out['ok'] is True and out['domain']=='dns.example.com'

def test_nginx_apply_rolls_back_on_validation_failure(tmp_path):
    live=tmp_path/'ssl.conf'; live.write_text('old')
    le=tmp_path/'le'; d=le/'live'/'dns.example.com'; d.mkdir(parents=True); (d/'fullchain.pem').write_text('x'); (d/'privkey.pem').write_text('x')
    def runner(argv, **kwargs):
        if argv[:2]==['/usr/sbin/nginx','-t']: return SimpleNamespace(returncode=1,stderr='bad',stdout='')
        return SimpleNamespace(returncode=0,stderr='',stdout='')
    ops=SslHelperOps(live_nginx=live, letsencrypt_root=le, runner=runner)
    with pytest.raises(RuntimeError): ops.ssl_apply('dns.example.com', True)
    assert live.read_text()=='old'

def test_production_ssl_paths_are_domain_scoped():
    ops=SslHelperOps()
    assert ops._live_path('a.example.com').name=='dns-manager-ssl-a.example.com.conf'
    assert ops._live_path('b.example.com').name=='dns-manager-ssl-b.example.com.conf'
    assert ops._live_path('a.example.com') != ops._live_path('b.example.com')

def test_ssl_delete_uses_domain_scoped_path(tmp_path):
    from types import SimpleNamespace
    def runner(argv, **kwargs): return SimpleNamespace(returncode=0,stdout='ok',stderr='')
    ops=SslHelperOps(live_nginx=tmp_path/'one.conf',runner=runner)
    (tmp_path/'one.conf').write_text('x')
    assert ops.ssl_delete('dns.example.com')['deleted'] is True
    assert not (tmp_path/'one.conf').exists()


def test_ssl_status_returns_certificate_metadata(tmp_path):
    from datetime import datetime, timedelta, timezone
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    domain='dns.example.com'
    live=tmp_path/'le'/'live'/domain
    live.mkdir(parents=True)
    key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    now=datetime.now(timezone.utc)
    subject=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,domain)])
    cert=(x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key()).serial_number(42)
          .not_valid_before(now-timedelta(days=1)).not_valid_after(now+timedelta(days=84))
          .sign(key,hashes.SHA256()))
    (live/'fullchain.pem').write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (live/'privkey.pem').write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.TraditionalOpenSSL,serialization.NoEncryption()))

    out=SslHelperOps(letsencrypt_root=tmp_path/'le').ssl_status(domain)
    assert out['certificate_present'] is True
    assert out['status']=='ISSUED'
    assert out['issuer']
    assert out['issued_at'].endswith('+00:00')
    assert out['expires_at'].endswith('+00:00')
    assert out['days_remaining'] >= 82


def test_ssl_status_missing_certificate_returns_not_issued(tmp_path):
    out=SslHelperOps(letsencrypt_root=tmp_path/'le').ssl_status('dns.example.com')
    assert out == {
        'domain':'dns.example.com',
        'certificate_present':False,
        'status':'NOT_ISSUED',
        'issuer':None,
        'issued_at':None,
        'expires_at':None,
        'days_remaining':None,
    }


def test_ssl_apply_adopts_existing_legacy_management_vhost(tmp_path):
    confd=tmp_path/'conf.d'; confd.mkdir()
    legacy=confd/'dns-manager-https.conf'
    legacy.write_text('server { listen 443 ssl; server_name dns.example.com; }\n')
    le=tmp_path/'le'; live=le/'live'/'dns.example.com'; live.mkdir(parents=True)
    (live/'fullchain.pem').write_text('cert')
    (live/'privkey.pem').write_text('key')
    calls=[]
    def runner(argv, **kwargs):
        calls.append(list(argv))
        return SimpleNamespace(returncode=0,stdout='ok',stderr='')
    ops=SslHelperOps(nginx_conf_dir=confd, letsencrypt_root=le, runner=runner)
    out=ops.ssl_apply('dns.example.com', True)
    assert out['applied'] is True
    assert out['config_path']==str(legacy)
    assert 'server_name dns.example.com;' in legacy.read_text()
    assert not (confd/'dns-manager-ssl-dns.example.com.conf').exists()
    assert ['/usr/sbin/nginx','-t'] in calls

def test_ssl_apply_keeps_domain_scoped_path_when_legacy_vhost_is_for_other_domain(tmp_path):
    confd=tmp_path/'conf.d'; confd.mkdir()
    legacy=confd/'dns-manager-https.conf'
    legacy.write_text('server { listen 443 ssl; server_name other.example.com; }\n')
    le=tmp_path/'le'; live=le/'live'/'dns.example.com'; live.mkdir(parents=True)
    (live/'fullchain.pem').write_text('cert')
    (live/'privkey.pem').write_text('key')
    def runner(argv, **kwargs): return SimpleNamespace(returncode=0,stdout='ok',stderr='')
    ops=SslHelperOps(nginx_conf_dir=confd, letsencrypt_root=le, runner=runner)
    out=ops.ssl_apply('dns.example.com', True)
    expected=confd/'dns-manager-ssl-dns.example.com.conf'
    assert out['config_path']==str(expected)
    assert expected.exists()
    assert 'other.example.com' in legacy.read_text()


def test_managed_https_vhost_allows_long_running_ssl_api_requests():
    text = SslHelperOps()._nginx_text('dns.example.com', True)
    assert 'proxy_read_timeout 360s;' in text
    assert 'proxy_send_timeout 360s;' in text


def test_acme_delegation_issue_uses_manual_dns_hooks(tmp_path):
    from privileged.ssl_helper import SslHelperOps
    calls=[]
    class R:
        returncode=0; stdout='ok'; stderr=''
    def runner(argv,**kwargs): calls.append(list(argv)); return R()
    ops=SslHelperOps(letsencrypt_root=tmp_path/'le',work_root=tmp_path/'work',runner=runner)
    result=ops.ssl_issue('example.com','acme_delegation')
    argv=calls[-1]
    assert result['issued'] is True
    assert '--manual' in argv
    assert '--preferred-challenges' in argv and 'dns' in argv
    assert '--manual-auth-hook' in argv
    assert '/usr/local/libexec/dns-manager-acme-dns-hook auth' in argv
    assert '--manual-cleanup-hook' in argv
    assert '/usr/local/libexec/dns-manager-acme-dns-hook cleanup' in argv


def test_acme_delegation_test_renewal_is_dry_run(tmp_path):
    from privileged.ssl_helper import SslHelperOps
    calls=[]
    class R:
        returncode=0; stdout='ok'; stderr=''
    def runner(argv,**kwargs): calls.append(list(argv)); return R()
    ops=SslHelperOps(letsencrypt_root=tmp_path/'le',work_root=tmp_path/'work',runner=runner)
    result=ops.ssl_test_renewal('example.com','acme_delegation')
    assert result['tested'] is True
    assert '--dry-run' in calls[-1]


def test_hosted_acme_issue_uses_hosted_hooks(tmp_path):
    calls=[]
    class R:
        returncode=0; stdout='ok'; stderr=''
    def runner(argv,**kwargs): calls.append(list(argv)); return R()
    ops=SslHelperOps(letsencrypt_root=tmp_path/'le',work_root=tmp_path/'work',runner=runner)
    out=ops.ssl_issue('example.com','acme_dns_hosted')
    argv=calls[-1]
    assert out['issued'] is True
    assert '/usr/local/libexec/dns-manager-hosted-acme-hook auth' in argv
    assert '/usr/local/libexec/dns-manager-hosted-acme-hook cleanup' in argv


def test_hosted_acme_test_renewal_is_dry_run(tmp_path):
    calls=[]
    class R:
        returncode=0; stdout='ok'; stderr=''
    def runner(argv,**kwargs): calls.append(list(argv)); return R()
    ops=SslHelperOps(letsencrypt_root=tmp_path/'le',work_root=tmp_path/'work',runner=runner)
    out=ops.ssl_test_renewal('example.com','acme_dns_hosted')
    assert out['tested'] is True
    assert '--dry-run' in calls[-1]


def test_ssl_apply_https_vhost_uses_mapping_upstream(tmp_path):
    le=tmp_path/'le'; live=le/'live'/'vm226.connect3.net.bd'; live.mkdir(parents=True)
    (live/'fullchain.pem').write_text('cert')
    (live/'privkey.pem').write_text('key')
    conf=tmp_path/'ssl.conf'
    def runner(argv, **kwargs): return SimpleNamespace(returncode=0,stdout='ok',stderr='')
    ops=SslHelperOps(live_nginx=conf,letsencrypt_root=le,runner=runner)
    upstream={
        'scheme':'https',
        'host':'192.168.255.226',
        'port':443,
        'preserve_host':True,
        'websocket_enabled':True,
        'timeout':60,
    }
    out=ops.ssl_apply('vm226.connect3.net.bd',True,upstream=upstream)
    assert out['applied'] is True
    text=conf.read_text()
    assert 'proxy_pass https://192.168.255.226:443;' in text
    assert 'proxy_pass http://127.0.0.1:8500;' not in text
    assert 'proxy_set_header Host $host;' in text
    assert 'proxy_set_header Upgrade $http_upgrade;' in text
    assert 'proxy_read_timeout 60s;' in text


def test_helper_accepts_validated_ssl_apply_upstream_payload():
    class ApplyOps:
        def ssl_apply(self, domain, redirect_http=True, upstream=None):
            return {'domain':domain,'upstream':upstream,'redirect_http':redirect_http}
    payload={
        'command':'ssl_apply',
        'domain':'vm226.connect3.net.bd',
        'redirect_http':True,
        'upstream':{'scheme':'https','host':'192.168.255.226','port':443,'preserve_host':True,'websocket_enabled':True,'timeout':60},
    }
    out=handle_request(json.dumps(payload),ApplyOps())
    assert out['ok'] is True
    assert out['upstream']['host']=='192.168.255.226'


def test_ssl_apply_rejects_malformed_mapping_upstream_before_writing(tmp_path):
    le=tmp_path/'le'; live=le/'live'/'bad.example.com'; live.mkdir(parents=True)
    (live/'fullchain.pem').write_text('cert')
    (live/'privkey.pem').write_text('key')
    conf=tmp_path/'ssl.conf'
    ops=SslHelperOps(live_nginx=conf,letsencrypt_root=le,runner=lambda *a,**k: SimpleNamespace(returncode=0,stdout='',stderr=''))
    with pytest.raises(ValueError, match='invalid upstream host'):
        ops.ssl_apply('bad.example.com',True,upstream={
            'scheme':'https','host':'192.168.1.2; return 200','port':443,
            'preserve_host':True,'websocket_enabled':True,'timeout':60,
        })
    assert not conf.exists()


def test_ssl_management_vhost_still_defaults_to_local_app():
    text=SslHelperOps()._nginx_text('dns.connect3.net.bd',True,upstream=None)
    assert 'proxy_pass http://127.0.0.1:8500;' in text
    assert 'proxy_read_timeout 360s;' in text
