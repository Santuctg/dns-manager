from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, event
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class SslCertificate(Base):
    __tablename__ = 'ssl_certificates'

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    domain: Mapped[str] = mapped_column(String(253), unique=True, nullable=False, index=True)
    provider: Mapped[str] = mapped_column(String(32), nullable=False, default='manual')
    auto_renew: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    redirect_http: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default='NOT_ISSUED')
    issuer: Mapped[str | None] = mapped_column(String(255), nullable=True)
    issued_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_renewal_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_renewal_status: Mapped[str | None] = mapped_column(String(32), nullable=True)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow)

    credential: Mapped['SslProviderCredential | None'] = relationship(back_populates='certificate', cascade='all, delete-orphan', uselist=False)
    delegation: Mapped['SslAcmeDelegation | None'] = relationship(back_populates='certificate', cascade='all, delete-orphan', uselist=False)
    hosted_acme: Mapped['SslHostedAcmeCredential | None'] = relationship(back_populates='certificate', cascade='all, delete-orphan', uselist=False)


@event.listens_for(SslCertificate, 'before_insert')
@event.listens_for(SslCertificate, 'before_update')
def _normalize_domain(_mapper, _connection, target: SslCertificate) -> None:
    target.domain = target.domain.strip().lower().rstrip('.')


class SslProviderCredential(Base):
    __tablename__ = 'ssl_provider_credentials'

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    certificate_id: Mapped[int] = mapped_column(ForeignKey('ssl_certificates.id', ondelete='CASCADE'), unique=True, nullable=False)
    provider: Mapped[str] = mapped_column(String(32), nullable=False)
    token_ciphertext: Mapped[str] = mapped_column(Text, nullable=False)
    token_last4: Mapped[str | None] = mapped_column(String(4), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow)

    certificate: Mapped[SslCertificate] = relationship(back_populates='credential')

    def __repr__(self) -> str:
        return f"<SslProviderCredential id={self.id!r} provider={self.provider!r} token_last4={self.token_last4!r}>"


class SslOperation(Base):
    __tablename__ = 'ssl_operations'

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    domain: Mapped[str] = mapped_column(String(253), nullable=False, index=True)
    action: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default='PENDING')
    challenge_name: Mapped[str | None] = mapped_column(String(512), nullable=True)
    challenge_value: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
