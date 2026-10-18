from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
import pytest

from app.database import Base, build_engine
from app.models import SslAcmeDelegation, SslCertificate


def _db(tmp_path):
    engine = build_engine(str(tmp_path / "acme.db"))
    Base.metadata.create_all(engine)
    return Session(engine)


def test_acme_delegation_persists_and_relates_to_certificate(tmp_path):
    db = _db(tmp_path)
    cert = SslCertificate(domain="example.com", provider="acme_delegation")
    db.add(cert)
    db.flush()
    delegation = SslAcmeDelegation(
        certificate_id=cert.id,
        domain="example.com",
        challenge_domain="_acme-challenge.example.com",
        delegation_id="dns-a1b2c3d4e5f6",
        delegated_fqdn="dns-a1b2c3d4e5f6.acme-dns.connect3.net.bd",
        verified=True,
    )
    db.add(delegation)
    db.commit()
    db.refresh(cert)

    assert cert.delegation is not None
    assert cert.delegation.delegation_id == "dns-a1b2c3d4e5f6"
    assert cert.delegation.verified is True


def test_only_one_delegation_is_allowed_per_certificate(tmp_path):
    db = _db(tmp_path)
    cert = SslCertificate(domain="example.com", provider="acme_delegation")
    db.add(cert)
    db.flush()
    db.add_all([
        SslAcmeDelegation(
            certificate_id=cert.id,
            domain="example.com",
            challenge_domain="_acme-challenge.example.com",
            delegation_id="dns-a1b2c3d4e5f6",
            delegated_fqdn="dns-a1b2c3d4e5f6.acme-dns.connect3.net.bd",
        ),
        SslAcmeDelegation(
            certificate_id=cert.id,
            domain="example.com",
            challenge_domain="_acme-challenge.example.com",
            delegation_id="dns-111111111111",
            delegated_fqdn="dns-111111111111.acme-dns.connect3.net.bd",
        ),
    ])
    with pytest.raises(IntegrityError):
        db.commit()
