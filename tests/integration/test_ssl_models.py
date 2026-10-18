from sqlalchemy.orm import Session

from app.database import Base, build_engine
from app.models import SslCertificate, SslOperation, SslProviderCredential


def test_ssl_models_persist_normalized_domain_and_ciphertext(tmp_path):
    engine = build_engine(str(tmp_path / 'ssl.db'))
    Base.metadata.create_all(engine)
    db = Session(engine)
    cert = SslCertificate(domain='DNS.Example.COM.', provider='cloudflare', auto_renew=True, redirect_http=True)
    db.add(cert); db.flush()
    db.add(SslProviderCredential(certificate_id=cert.id, provider='cloudflare', token_ciphertext='gAAAA-test', token_last4='abcd'))
    db.add(SslOperation(domain='dns.example.com', action='issue', status='PENDING'))
    db.commit(); db.refresh(cert)
    assert cert.domain == 'dns.example.com'
    cred = db.query(SslProviderCredential).one()
    assert cred.token_ciphertext == 'gAAAA-test'
    assert not hasattr(cred, 'token_plaintext')
