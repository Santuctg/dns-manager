from __future__ import annotations

import re
import secrets

from app.services.ssl_service import normalize_ssl_domain

_DELEGATION_ID_RE = re.compile(r"^dns-[0-9a-f]{12}$")


def generate_delegation_id() -> str:
    return f"dns-{secrets.token_hex(6)}"


def validate_delegation_id(value: str) -> str:
    if not _DELEGATION_ID_RE.fullmatch(value):
        raise ValueError("invalid delegation id")
    return value


def challenge_domain_for(domain: str) -> str:
    return f"_acme-challenge.{normalize_ssl_domain(domain)}"


def delegated_fqdn_for(delegation_id: str, zone: str) -> str:
    delegation_id = validate_delegation_id(delegation_id)
    normalized_zone = normalize_ssl_domain(zone)
    return f"{delegation_id}.{normalized_zone}"



def configured_acme_zone(helper=None) -> str:
    """Return the root-configured ACME zone through the sanitized helper status."""
    from app.config import AcmeDnsConfig
    if helper is None:
        try:
            from app.services.privileged_helper import PrivilegedHelper
            helper = PrivilegedHelper()
        except Exception:
            helper = None
    if helper is not None:
        try:
            status = helper.acme_dns_status()
            zone = status.get("zone") if isinstance(status, dict) else None
            if isinstance(zone, str) and zone.strip():
                return normalize_ssl_domain(zone)
        except Exception:
            pass
    return normalize_ssl_domain(AcmeDnsConfig().zone)

def verify_delegation(challenge_domain: str, expected_target: str, resolvers: tuple[str, str] | None = None) -> dict:
    """Verify the exact public CNAME through two independent recursive resolvers."""
    import dns.resolver

    challenge = normalize_ssl_domain(challenge_domain)
    expected = normalize_ssl_domain(expected_target)
    nameservers = resolvers or ("1.1.1.1", "8.8.8.8")
    observed: list[str] = []
    errors: list[str] = []
    for nameserver in nameservers:
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = [nameserver]
        resolver.timeout = 3.0
        resolver.lifetime = 5.0
        try:
            answer = resolver.resolve(challenge, "CNAME")
            values = [normalize_ssl_domain(str(r.target)) for r in answer]
            observed.extend(values)
            if expected not in values:
                errors.append(f"CNAME mismatch via {nameserver}")
        except Exception:
            errors.append(f"CNAME lookup failed via {nameserver}")
    return {
        "verified": not errors and len(observed) >= len(nameservers),
        "observed": sorted(set(observed)),
        "error": "; ".join(errors) if errors else None,
    }
