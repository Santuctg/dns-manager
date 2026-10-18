from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import socket
import time
from urllib.parse import urlsplit

import httpx


def validate_hosted_acme_server_url(url: str) -> str:
    raw = str(url).strip()
    parts = urlsplit(raw)
    if parts.scheme.lower() != 'https' or not parts.hostname:
        raise ValueError('Hosted ACME server URL must use HTTPS')
    if parts.username is not None or parts.password is not None:
        raise ValueError('Hosted ACME server URL must not contain credentials')
    if parts.fragment or parts.query:
        raise ValueError('Hosted ACME server URL must not contain query or fragment')
    host = parts.hostname.rstrip('.').lower()
    if host == 'localhost' or host.endswith('.localhost'):
        raise ValueError('Hosted ACME server URL must not target localhost')
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if ip is not None and (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_unspecified or ip.is_reserved):
        raise ValueError('Hosted ACME server URL must target a public host')
    port = f':{parts.port}' if parts.port else ''
    path = parts.path.rstrip('/')
    return f'https://{host}{port}{path}'


@dataclass(frozen=True)
class HostedAcmeRegistration:
    username: str
    password: str
    subdomain: str
    fulldomain: str


class HostedAcmeError(RuntimeError):
    pass


class HostedAcmeClient:
    def __init__(self, server_url: str, timeout: float = 15.0, transport=None):
        self.server_url = validate_hosted_acme_server_url(server_url)
        self.timeout = timeout
        self.transport = transport

    def _client(self):
        return httpx.Client(timeout=self.timeout, verify=True, follow_redirects=False, transport=self.transport)

    def _ensure_public_resolution(self) -> None:
        parts=urlsplit(self.server_url)
        host=parts.hostname
        port=parts.port or 443
        try:
            infos=socket.getaddrinfo(host,port,type=socket.SOCK_STREAM)
        except OSError as exc:
            raise HostedAcmeError('Hosted ACME provider DNS resolution failed') from exc
        if not infos:
            raise HostedAcmeError('Hosted ACME provider DNS resolution failed')
        for info in infos:
            address=info[4][0]
            try:
                ip=ipaddress.ip_address(address)
            except ValueError:
                raise HostedAcmeError('Hosted ACME provider must resolve to a public address')
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_unspecified or ip.is_reserved or ip.is_multicast:
                raise HostedAcmeError('Hosted ACME provider must resolve to a public address')

    def register(self) -> HostedAcmeRegistration:
        if self.transport is None:
            self._ensure_public_resolution()
        try:
            with self._client() as client:
                response = client.post(f'{self.server_url}/register')
            if response.is_redirect:
                raise HostedAcmeError('Hosted ACME registration redirect rejected')
            response.raise_for_status()
            data = response.json()
        except HostedAcmeError:
            raise
        except Exception as exc:
            raise HostedAcmeError('Hosted ACME registration failed') from exc
        required = ('username', 'password', 'subdomain', 'fulldomain')
        if not isinstance(data, dict) or any(not isinstance(data.get(k), str) or not data[k].strip() for k in required):
            raise HostedAcmeError('Hosted ACME registration returned an invalid response')
        return HostedAcmeRegistration(*(data[k].strip() for k in required))

    def update_txt(self, username: str, password: str, subdomain: str, value: str) -> None:
        if self.transport is None:
            self._ensure_public_resolution()
        headers={'X-Api-User': username, 'X-Api-Key': password}
        payload={'subdomain': subdomain, 'txt': value}
        last_error=None
        for attempt in range(3):
            try:
                with self._client() as client:
                    response=client.post(f'{self.server_url}/update', headers=headers, json=payload)
                if response.is_redirect:
                    raise HostedAcmeError('Hosted ACME update redirect rejected')
                response.raise_for_status()
                return
            except HostedAcmeError:
                raise
            except Exception as exc:
                last_error=exc
                if attempt < 2:
                    time.sleep(2 ** attempt)
        raise HostedAcmeError('Hosted ACME TXT update failed') from last_error


def challenge_domain_for(domain: str) -> str:
    from app.services.ssl_service import normalize_ssl_domain
    return f'_acme-challenge.{normalize_ssl_domain(domain)}'


def _normalize_dns_name(value: str) -> str:
    return str(value).strip().rstrip('.').lower()


def verify_hosted_cname(challenge_domain: str, expected_fqdn: str, resolvers: tuple[str, str] = ('1.1.1.1','8.8.8.8')) -> dict:
    import dns.resolver
    challenge = _normalize_dns_name(challenge_domain)
    expected = _normalize_dns_name(expected_fqdn)
    observed: list[str] = []
    errors: list[str] = []
    for nameserver in resolvers:
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = [nameserver]
        resolver.timeout = 3.0
        resolver.lifetime = 5.0
        try:
            answer = resolver.resolve(challenge, 'CNAME')
            values = [_normalize_dns_name(str(r.target)) for r in answer]
            observed.extend(values)
            if expected not in values:
                errors.append(f'CNAME mismatch via {nameserver}')
        except Exception:
            errors.append(f'CNAME lookup failed via {nameserver}')
    return {'verified': not errors and len(observed) >= len(resolvers), 'observed': sorted(set(observed)), 'error': '; '.join(errors) if errors else None}


def wait_for_hosted_txt(fulldomain: str, expected: str, timeout: int = 120, interval: int = 2, resolvers: tuple[str, str] = ('1.1.1.1','8.8.8.8')) -> None:
    import dns.resolver
    deadline=time.monotonic()+timeout
    while time.monotonic() < deadline:
        success=True
        for nameserver in resolvers:
            resolver=dns.resolver.Resolver(configure=False)
            resolver.nameservers=[nameserver]
            resolver.timeout=min(3.0, float(interval)+1.0)
            resolver.lifetime=min(5.0, float(interval)+3.0)
            try:
                answer=resolver.resolve(_normalize_dns_name(fulldomain), 'TXT')
                values=[]
                for record in answer:
                    if hasattr(record, 'strings'):
                        values.append(b''.join(record.strings).decode())
                    else:
                        values.append(str(record).strip('"'))
                if expected not in values:
                    success=False
                    break
            except Exception:
                success=False
                break
        if success:
            return
        time.sleep(interval)
    raise HostedAcmeError('Hosted ACME TXT propagation timed out')
