from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import threading
import ipaddress
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from cryptography import x509
from app.schemas.mapping import validate_upstream_host
from privileged.helper_lib import PRIVATE_ROOT, ensure_private_dir

_DOMAIN_RE=re.compile(r'^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$',re.I)
_LOCKS: dict[str, threading.Lock]={}


def _domain(value:str)->str:
    v=value.strip().rstrip('.').lower()
    if not _DOMAIN_RE.fullmatch(v): raise ValueError('invalid domain')
    return v


def _run_default(argv, **kwargs): return subprocess.run(argv,text=True,capture_output=True,**kwargs)


# Cloudflare API tokens are URL-safe strings; anything else (notably a newline)
# could add settings to the certbot credentials file the token is written into.
_CLOUDFLARE_TOKEN_RE=re.compile(r'[A-Za-z0-9_.-]{1,256}')


class SslHelperOps:
    def __init__(self, *, live_nginx: Path | None=None, nginx_conf_dir: Path=Path('/etc/nginx/conf.d'), letsencrypt_root: Path=Path('/etc/letsencrypt'), work_root: Path=PRIVATE_ROOT/'acme', runner:Callable=_run_default):
        self.live_nginx=Path(live_nginx) if live_nginx is not None else None; self.nginx_conf_dir=Path(nginx_conf_dir); self.letsencrypt_root=Path(letsencrypt_root); self.work_root=Path(work_root); self.runner=runner

    def _live_path(self, domain: str) -> Path:
        return self.live_nginx if self.live_nginx is not None else self.nginx_conf_dir / f'dns-manager-ssl-{domain}.conf'

    def _legacy_live_path(self, domain: str) -> Path | None:
        if self.live_nginx is not None:
            return None
        path=self.nginx_conf_dir/'dns-manager-https.conf'
        if not path.is_file():
            return None
        try:
            text=path.read_text(errors='ignore')
        except OSError:
            return None
        for match in re.finditer(r'\bserver_name\s+([^;]+);', text):
            if domain in match.group(1).split():
                return path
        return None

    def _apply_live_path(self, domain: str) -> Path:
        return self._legacy_live_path(domain) or self._live_path(domain)

    def _state_dir(self, d: str) -> Path:
        ensure_private_dir(self.work_root)
        return ensure_private_dir(self.work_root/d)

    def _run(self, argv, timeout=120):
        r=self.runner(list(argv),check=False,timeout=timeout)
        if r.returncode!=0: raise RuntimeError((r.stderr or r.stdout or 'command failed').strip())
        return r

    def ssl_status(self, domain):
        d=_domain(domain); base=self.letsencrypt_root/'live'/d
        cert_path=base/'fullchain.pem'; key_path=base/'privkey.pem'
        present=cert_path.is_file() and key_path.is_file()
        if not present:
            return {'domain':d,'certificate_present':False,'status':'NOT_ISSUED','issuer':None,'issued_at':None,'expires_at':None,'days_remaining':None}
        try:
            cert=x509.load_pem_x509_certificate(cert_path.read_bytes())
            now=datetime.now(timezone.utc)
            not_before=cert.not_valid_before_utc
            not_after=cert.not_valid_after_utc
            days=(not_after-now).days
            if not_after <= now:
                status='EXPIRED'
            elif days <= 30:
                status='EXPIRING'
            else:
                status='ISSUED'
            return {
                'domain':d,
                'certificate_present':True,
                'status':status,
                'issuer':cert.issuer.rfc4514_string(),
                'issued_at':not_before.isoformat(),
                'expires_at':not_after.isoformat(),
                'days_remaining':days,
            }
        except Exception as exc:
            return {'domain':d,'certificate_present':True,'status':'ERROR','issuer':None,'issued_at':None,'expires_at':None,'days_remaining':None,'error':str(exc)}

    def _validated_upstream(self, upstream):
        if upstream is None:
            return None
        if not isinstance(upstream, dict):
            raise ValueError('invalid SSL upstream')
        allowed={'scheme','host','port','preserve_host','websocket_enabled','timeout'}
        if set(upstream)-allowed:
            raise ValueError('invalid SSL upstream')
        scheme=upstream.get('scheme')
        if scheme not in {'http','https'}:
            raise ValueError('invalid SSL upstream scheme')
        host=validate_upstream_host(str(upstream.get('host','')))
        try:
            port=int(upstream.get('port'))
        except (TypeError, ValueError) as exc:
            raise ValueError('invalid SSL upstream port') from exc
        if not 1 <= port <= 65535:
            raise ValueError('invalid SSL upstream port')
        try:
            timeout=int(upstream.get('timeout',60))
        except (TypeError, ValueError) as exc:
            raise ValueError('invalid SSL upstream timeout') from exc
        if not 1 <= timeout <= 3600:
            raise ValueError('invalid SSL upstream timeout')
        return {
            'scheme':scheme, 'host':host, 'port':port,
            'preserve_host':bool(upstream.get('preserve_host',True)),
            'websocket_enabled':bool(upstream.get('websocket_enabled',True)),
            'timeout':timeout,
        }

    @staticmethod
    def _url_host(host):
        try:
            address=ipaddress.ip_address(host)
        except ValueError:
            return host
        return f'[{address.compressed}]' if address.version == 6 else address.compressed

    def _nginx_text(self, d, redirect, upstream=None):
        http=(f'server {{ listen 80; server_name {d}; return 301 https://$host$request_uri; }}\n' if redirect else '')
        target=self._validated_upstream(upstream)
        if target is None:
            proxy_pass='http://127.0.0.1:8500'
            send_timeout=read_timeout=360
            preserve_host=True
            websocket=False
        else:
            proxy_pass=f"{target['scheme']}://{self._url_host(target['host'])}:{target['port']}"
            send_timeout=60
            read_timeout=target['timeout']
            preserve_host=target['preserve_host']
            websocket=target['websocket_enabled']
        lines=[
            'server {',
            '    listen 443 ssl;',
            f'    server_name {d};',
            f'    ssl_certificate {self.letsencrypt_root}/live/{d}/fullchain.pem;',
            f'    ssl_certificate_key {self.letsencrypt_root}/live/{d}/privkey.pem;',
            '    ssl_protocols TLSv1.2 TLSv1.3;',
            '    location / {',
            f'        proxy_pass {proxy_pass};',
            '        proxy_http_version 1.1;',
        ]
        if preserve_host:
            lines.append('        proxy_set_header Host $host;')
        lines.extend([
            '        proxy_set_header X-Real-IP $remote_addr;',
            '        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;',
            '        proxy_set_header X-Forwarded-Proto https;',
        ])
        if websocket:
            lines.extend([
                '        proxy_set_header Upgrade $http_upgrade;',
                '        proxy_set_header Connection "upgrade";',
            ])
        lines.extend([
            '        proxy_connect_timeout 15s;',
            f'        proxy_send_timeout {send_timeout}s;',
            f'        proxy_read_timeout {read_timeout}s;',
            '    }',
            '}',
        ])
        return http+'\n'.join(lines)+'\n'

    def ssl_apply(self, domain, redirect_http=True, upstream=None):
        d=_domain(domain); base=self.letsencrypt_root/'live'/d
        if not (base/'fullchain.pem').is_file() or not (base/'privkey.pem').is_file(): raise FileNotFoundError('certificate files missing')
        lock=_LOCKS.setdefault(d,threading.Lock())
        if not lock.acquire(blocking=False): raise RuntimeError('SSL operation already in progress')
        live_path=self._apply_live_path(d)
        old=live_path.read_bytes() if live_path.exists() else None
        try:
            live_path.parent.mkdir(parents=True,exist_ok=True)
            fd,tmp=tempfile.mkstemp(prefix='.dns-manager-ssl.',dir=live_path.parent)
            with os.fdopen(fd,'w') as f: f.write(self._nginx_text(d,bool(redirect_http),upstream=upstream)); f.flush(); os.fsync(f.fileno())
            os.replace(tmp,live_path)
            try:
                self._run(['/usr/sbin/nginx','-t'])
                self._run(['/usr/bin/systemctl','reload','nginx'])
            except Exception:
                if old is None:
                    live_path.unlink(missing_ok=True)
                else: live_path.write_bytes(old)
                raise
            return {'applied':True,'domain':d,'config_path':str(live_path)}
        finally: lock.release()


    def _renewal_authenticator(self, domain: str) -> str | None:
        d=_domain(domain)
        path=self.letsencrypt_root/'renewal'/f'{d}.conf'
        try:
            text=path.read_text(errors='strict')
        except (FileNotFoundError, PermissionError, OSError):
            return None
        match=re.search(r'(?m)^\s*authenticator\s*=\s*([^\s#;]+)\s*$', text)
        return match.group(1).strip() if match else None

    def _cloudflare_run(self, domain, token, *, dry_run=False, force=False):
        if not isinstance(token,str) or not _CLOUDFLARE_TOKEN_RE.fullmatch(token): raise ValueError('invalid Cloudflare API token')
        d=_domain(domain)
        fd,path=tempfile.mkstemp(prefix='cf-',dir=ensure_private_dir(self.work_root))
        try:
            os.write(fd, f'dns_cloudflare_api_token = {token}\n'.encode()); os.close(fd); os.chmod(path,0o600)
            argv=['/usr/bin/certbot','certonly','--non-interactive','--agree-tos','--register-unsafely-without-email','--dns-cloudflare','--dns-cloudflare-credentials',path,'-d',d]
            if dry_run: argv.append('--dry-run')
            if force: argv.append('--force-renewal')
            r=self.runner(argv,check=False,timeout=300)
            if r.returncode!=0:
                msg=(r.stderr or r.stdout or 'certbot failed').replace(token,'[REDACTED]')
                raise RuntimeError(msg.strip())
            result={'domain':d,'issued':not dry_run,'tested':dry_run}
            if not dry_run:
                authenticator=self._renewal_authenticator(d)
                if authenticator != 'dns-cloudflare':
                    raise RuntimeError('renewal lineage is not configured for dns-cloudflare')
                result['renewal_authenticator']=authenticator
            return result
        finally:
            try: os.unlink(path)
            except FileNotFoundError: pass


    def _hosted_run(self, domain, *, dry_run=False, force=False):
        d=_domain(domain)
        argv=[
            '/usr/bin/certbot','certonly','--non-interactive','--agree-tos',
            '--register-unsafely-without-email','--manual','--preferred-challenges','dns',
            '--manual-auth-hook','/usr/local/libexec/dns-manager-hosted-acme-hook auth',
            '--manual-cleanup-hook','/usr/local/libexec/dns-manager-hosted-acme-hook cleanup',
            '-d',d,
        ]
        if dry_run: argv.append('--dry-run')
        if force: argv.append('--force-renewal')
        r=self.runner(argv,check=False,timeout=300)
        if r.returncode!=0:
            raise RuntimeError((r.stderr or r.stdout or 'certbot failed').strip())
        return {'domain':d,'issued':not dry_run,'tested':dry_run,'renewed':bool(force and not dry_run)}

    def _delegation_run(self, domain, *, dry_run=False, force=False):
        d=_domain(domain)
        argv=[
            '/usr/bin/certbot','certonly','--non-interactive','--agree-tos',
            '--register-unsafely-without-email','--manual','--preferred-challenges','dns',
            '--manual-auth-hook','/usr/local/libexec/dns-manager-acme-dns-hook auth',
            '--manual-cleanup-hook','/usr/local/libexec/dns-manager-acme-dns-hook cleanup',
            '-d',d,
        ]
        if dry_run: argv.append('--dry-run')
        if force: argv.append('--force-renewal')
        r=self.runner(argv,check=False,timeout=300)
        if r.returncode!=0:
            raise RuntimeError((r.stderr or r.stdout or 'certbot failed').strip())
        return {'domain':d,'issued':not dry_run,'tested':dry_run,'renewed':bool(force and not dry_run)}

    def ssl_issue(self, domain, provider, token=None):
        d=_domain(domain)
        if provider=='cloudflare':
            if not token: raise ValueError('missing DNS provider credential')
            return self._cloudflare_run(d,token)
        if provider=='acme_delegation':
            return self._delegation_run(d)
        if provider=='acme_dns_hosted':
            return self._hosted_run(d)
        if provider=='manual':
            state=self._state_dir(d)
            for name in ('challenge.json','continue'):
                (state/name).unlink(missing_ok=True)
            env=os.environ.copy(); env['DNS_MANAGER_ACME_STATE_DIR']=str(self.work_root)
            subprocess.Popen(['/usr/bin/certbot','certonly','--non-interactive','--agree-tos','--register-unsafely-without-email','--manual','--preferred-challenges','dns','--manual-auth-hook','/usr/local/libexec/dns-manager-manual-dns-hook','-d',d],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True)
            return {'domain':d,'started':True,'status':'PENDING'}
        raise ValueError('unsupported DNS provider')

    def ssl_manual_status(self, domain):
        d=_domain(domain); path=self._state_dir(d)/'challenge.json'
        if not path.is_file(): return {'domain':d,'status':'PENDING'}
        import json
        return json.loads(path.read_text())

    def ssl_manual_continue(self, domain):
        d=_domain(domain); state=self._state_dir(d)
        if not (state/'challenge.json').is_file(): raise RuntimeError('manual DNS challenge is not ready')
        (state/'continue').write_text('continue\n')
        return {'domain':d,'continued':True}

    def ssl_renew(self, domain, provider, token=None, force=False):
        if provider=='acme_delegation':
            result=self._delegation_run(domain,force=bool(force)); result['renewed']=True; return result
        if provider=='acme_dns_hosted':
            result=self._hosted_run(domain,force=bool(force)); result['renewed']=True; return result
        if provider!='cloudflare' or not token: raise ValueError('unsupported or missing DNS provider credential')
        result=self._cloudflare_run(domain,token,force=bool(force)); result['renewed']=True; return result

    def ssl_test_renewal(self, domain, provider, token=None):
        if provider=='acme_delegation':
            return self._delegation_run(domain,dry_run=True)
        if provider=='acme_dns_hosted':
            return self._hosted_run(domain,dry_run=True)
        if provider!='cloudflare' or not token: raise ValueError('unsupported or missing DNS provider credential')
        return self._cloudflare_run(domain,token,dry_run=True)

    def ssl_delete(self, domain):
        d=_domain(domain); live_path=self._live_path(d); old=live_path.read_bytes() if live_path.exists() else None; live_path.unlink(missing_ok=True)
        try:
            self._run(['/usr/sbin/nginx','-t']); self._run(['/usr/bin/systemctl','reload','nginx'])
        except Exception:
            if old is not None: live_path.write_bytes(old)
            raise
        return {'deleted':True,'domain':d}
