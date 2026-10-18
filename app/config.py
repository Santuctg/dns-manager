from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    bind_host: str = "127.0.0.1"
    bind_port: int = 8500
    database_path: str = "/var/lib/dns-manager/dns-manager.db"
    internal_proxy_ip: str | None = None
    acme_dns_config_path: str = "/etc/dns-manager/acme-dns.conf"
    hosted_acme_config_path: str = "/etc/dns-manager/hosted-acme.conf"

    model_config = SettingsConfigDict(
        env_prefix="DNS_MANAGER_",
        case_sensitive=False,
        extra="ignore",
    )


@dataclass(frozen=True)
class AcmeDnsConfig:
    enabled: bool = False
    zone: str = "acme-dns.connect3.net.bd"
    nameserver: str = "ns1-acme.connect3.net.bd"
    listen_ip: str | None = None
    ttl: int = 30
    listen_port: int = 53


def _normalize_dns_name(value: str) -> str:
    return value.strip().rstrip('.').lower()


def load_acme_dns_config(path: str | Path | None = None) -> AcmeDnsConfig:
    path = Path(path or get_settings().acme_dns_config_path)
    values: dict[str, str] = {}
    if path.is_file():
        for raw in path.read_text().splitlines():
            line = raw.strip()
            if not line or line.startswith('#') or '=' not in line:
                continue
            key, value = line.split('=', 1)
            values[key.strip()] = value.strip().strip('"\'')
    enabled = values.get('ACME_DNS_ENABLED', 'false').lower() in {'1', 'true', 'yes', 'on'}
    zone = _normalize_dns_name(values.get('ACME_DNS_ZONE', 'acme-dns.connect3.net.bd'))
    nameserver = _normalize_dns_name(values.get('ACME_DNS_NS', 'ns1-acme.connect3.net.bd'))
    listen_ip = values.get('ACME_DNS_LISTEN_IP') or None
    ttl = int(values.get('ACME_DNS_TTL', '30'))
    listen_port = int(values.get('ACME_DNS_PORT', '53'))
    if ttl != 30:
        raise ValueError('ACME_DNS_TTL must be 30')
    if not 1 <= listen_port <= 65535:
        raise ValueError('ACME_DNS_PORT must be between 1 and 65535')
    return AcmeDnsConfig(enabled=enabled, zone=zone, nameserver=nameserver, listen_ip=listen_ip, ttl=ttl, listen_port=listen_port)


@lru_cache
def get_settings() -> Settings:
    return Settings()


@dataclass(frozen=True)
class HostedAcmeConfig:
    enabled: bool = False
    server_url: str = "https://auth.acme-dns.io"
    http_timeout: float = 15.0
    propagation_timeout: int = 120


def load_hosted_acme_config(path: str | Path | None = None) -> HostedAcmeConfig:
    from app.services.hosted_acme_service import validate_hosted_acme_server_url
    path = Path(path or get_settings().hosted_acme_config_path)
    values: dict[str, str] = {}
    if path.is_file():
        for raw in path.read_text().splitlines():
            line = raw.strip()
            if not line or line.startswith('#') or '=' not in line:
                continue
            key, value = line.split('=', 1)
            values[key.strip()] = value.strip().strip('"\'')
    enabled = values.get('HOSTED_ACME_ENABLED', 'false').lower() in {'1','true','yes','on'}
    server_url = validate_hosted_acme_server_url(values.get('HOSTED_ACME_SERVER_URL', 'https://auth.acme-dns.io'))
    http_timeout = float(values.get('HOSTED_ACME_HTTP_TIMEOUT', '15'))
    propagation_timeout = int(values.get('HOSTED_ACME_PROPAGATION_TIMEOUT', '120'))
    if http_timeout <= 0 or http_timeout > 60:
        raise ValueError('HOSTED_ACME_HTTP_TIMEOUT must be between 0 and 60')
    if propagation_timeout <= 0 or propagation_timeout > 600:
        raise ValueError('HOSTED_ACME_PROPAGATION_TIMEOUT must be between 1 and 600')
    return HostedAcmeConfig(enabled=enabled, server_url=server_url, http_timeout=http_timeout, propagation_timeout=propagation_timeout)
