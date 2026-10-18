import re

import pytest

from app.services.acme_dns_service import (
    challenge_domain_for,
    delegated_fqdn_for,
    generate_delegation_id,
    validate_delegation_id,
)


def test_generate_delegation_id_is_random_dns_prefixed_hex():
    first = generate_delegation_id()
    second = generate_delegation_id()
    assert re.fullmatch(r"dns-[0-9a-f]{12}", first)
    assert re.fullmatch(r"dns-[0-9a-f]{12}", second)
    assert first != second


def test_challenge_domain_for_normalizes_domain():
    assert challenge_domain_for("Example.COM.") == "_acme-challenge.example.com"


def test_delegated_fqdn_for_normalizes_zone():
    assert delegated_fqdn_for("dns-a1b2c3d4e5f6", "ACME-DNS.Connect3.Net.BD.") == (
        "dns-a1b2c3d4e5f6.acme-dns.connect3.net.bd"
    )


@pytest.mark.parametrize(
    "value",
    ["dns-short", "DNS-a1b2c3d4e5f6", "dns-a1b2c3d4e5fg", "../dns-a1b2c3d4e5f6", "dns-a1b2c3d4e5f6.extra"],
)
def test_validate_delegation_id_rejects_malformed_values(value):
    with pytest.raises(ValueError, match="invalid delegation id"):
        validate_delegation_id(value)


def test_configured_acme_zone_uses_sanitized_helper_status():
    from app.services.acme_dns_service import configured_acme_zone
    class Helper:
        def acme_dns_status(self):
            return {'zone':'custom-acme.example.net','configured':True}
    assert configured_acme_zone(Helper()) == 'custom-acme.example.net'
