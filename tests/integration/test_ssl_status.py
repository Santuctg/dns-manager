from datetime import datetime, timedelta, timezone
from pathlib import Path
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from app.services.ssl_service import normalize_ssl_domain, inspect_certificate

@pytest.mark.parametrize('bad', ['http://x.com','x.com:443','x.com/path','*.x.com','x.com;rm','../x.com','x com','com',''])
def test_invalid_ssl_domains_rejected(bad):
    with pytest.raises(ValueError): normalize_ssl_domain(bad)

def test_normalize_domain():
    assert normalize_ssl_domain('DNS.Example.COM.') == 'dns.example.com'

def test_missing_certificate_is_not_issued(tmp_path):
    s=inspect_certificate('dns.example.com', letsencrypt_root=tmp_path)
    assert s['status']=='NOT_ISSUED'

def test_certificate_expiring_status(tmp_path):
    domain='dns.example.com'; live=tmp_path/'live'/domain; live.mkdir(parents=True)
    key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    now=datetime.now(timezone.utc)
    subject=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,domain)])
    cert=(x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key()).serial_number(1)
          .not_valid_before(now-timedelta(days=1)).not_valid_after(now+timedelta(days=10))
          .sign(key,hashes.SHA256()))
    (live/'fullchain.pem').write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    assert inspect_certificate(domain, letsencrypt_root=tmp_path)['status']=='EXPIRING'

def test_reconcile_all_marks_missing_lineage_not_issued(tmp_path):
    from sqlalchemy.orm import Session
    from app.database import Base, build_engine
    from app.models.ssl import SslCertificate
    from app.services.ssl_service import reconcile_all_certificates
    engine=build_engine(str(tmp_path/'reconcile.db')); Base.metadata.create_all(engine)
    with Session(engine) as db:
        db.add(SslCertificate(domain='dns.example.com',provider='manual',status='ISSUED')); db.commit()
        reconcile_all_certificates(db,letsencrypt_root=tmp_path/'le')
        row=db.query(SslCertificate).one(); assert row.status=='NOT_ISSUED' and row.expires_at is None


def test_reconcile_all_uses_privileged_helper_by_default(tmp_path):
    from sqlalchemy.orm import Session
    from app.database import Base, build_engine
    from app.models.ssl import SslCertificate
    from app.services.ssl_service import reconcile_all_certificates

    class Helper:
        def ssl_status(self, domain):
            return {
                'domain': domain,
                'certificate_present': True,
                'status': 'ISSUED',
                'issuer': "CN=Let's Encrypt",
                'issued_at': '2026-10-10T07:30:51+00:00',
                'expires_at': '2027-01-08T07:30:50+00:00',
                'days_remaining': 84,
            }

    engine=build_engine(str(tmp_path/'helper-reconcile.db')); Base.metadata.create_all(engine)
    with Session(engine) as db:
        db.add(SslCertificate(domain='dns.example.com',provider='manual',status='NOT_ISSUED')); db.commit()
        result=reconcile_all_certificates(db, helper=Helper())
        row=db.query(SslCertificate).one()
        assert result[0]['status']=='ISSUED'
        assert row.status=='ISSUED'
        assert row.issuer=="CN=Let's Encrypt"
        assert row.expires_at.replace(tzinfo=None).isoformat()=='2027-01-08T07:30:50'


def test_reconcile_all_keeps_the_list_when_one_certificate_cannot_be_read(tmp_path):
    from sqlalchemy.orm import Session
    from app.database import Base, build_engine
    from app.models.ssl import SslCertificate
    from app.services.ssl_service import reconcile_all_certificates

    class Helper:
        def ssl_status(self, domain):
            if domain == 'broken.example.com':
                raise OSError('helper socket missing')
            return {'domain': domain, 'certificate_present': True, 'status': 'ISSUED'}

    engine = build_engine(str(tmp_path / 'partial-reconcile.db'))
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        db.add(SslCertificate(domain='broken.example.com', provider='manual', status='ISSUED'))
        db.add(SslCertificate(domain='good.example.com', provider='manual', status='NOT_ISSUED'))
        db.commit()
        result = reconcile_all_certificates(db, helper=Helper())
        rows = {row.domain: row for row in db.query(SslCertificate).all()}

    assert {item['domain']: item['status'] for item in result} == {
        'broken.example.com': 'ERROR',
        'good.example.com': 'ISSUED',
    }
    assert rows['broken.example.com'].status == 'ERROR'
    assert 'helper socket missing' in rows['broken.example.com'].last_error
    assert rows['good.example.com'].status == 'ISSUED'
