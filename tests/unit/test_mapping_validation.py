import pytest
from pydantic import ValidationError

from app.schemas.mapping import MappingCreate


def test_valid_mapping_normalizes_domain_and_accepts_http():
    payload = MappingCreate(domain=' Panel.Example.com ', upstream_scheme='http', upstream_host='192.168.8.2', upstream_port=8082)
    assert payload.domain == 'panel.example.com'

@pytest.mark.parametrize('domain', ['http://example.com','example.com/path','example.com:8080','*.example.com','bad domain.example','bad\nserver_name x'])
def test_invalid_domains_are_rejected(domain):
    with pytest.raises(ValidationError):
        MappingCreate(domain=domain, upstream_scheme='http', upstream_host='192.168.8.2', upstream_port=8082)

@pytest.mark.parametrize('port', [0, 65536])
def test_invalid_ports_are_rejected(port):
    with pytest.raises(ValidationError):
        MappingCreate(domain='panel.example.com', upstream_scheme='http', upstream_host='192.168.8.2', upstream_port=port)


def test_only_http_and_https_schemes_are_allowed():
    with pytest.raises(ValidationError):
        MappingCreate(domain='panel.example.com', upstream_scheme='ftp', upstream_host='192.168.8.2', upstream_port=21)

@pytest.mark.parametrize('host', ['192.168.8.2;include /tmp/x','backend\nserver_name x','bad host'])
def test_unsafe_upstream_hosts_are_rejected(host):
    with pytest.raises(ValidationError):
        MappingCreate(domain='panel.example.com', upstream_scheme='http', upstream_host=host, upstream_port=8082)
