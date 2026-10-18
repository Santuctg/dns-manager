from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base
from app.models.ssl import utcnow


class SslHostedAcmeCredential(Base):
    __tablename__ = 'ssl_acme_dns_credentials'

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    certificate_id: Mapped[int] = mapped_column(ForeignKey('ssl_certificates.id', ondelete='CASCADE'), unique=True, nullable=False)
    server_url: Mapped[str] = mapped_column(String(512), nullable=False, default='https://auth.acme-dns.io')
    username_ciphertext: Mapped[str] = mapped_column(Text, nullable=False)
    password_ciphertext: Mapped[str] = mapped_column(Text, nullable=False)
    subdomain: Mapped[str] = mapped_column(String(255), nullable=False)
    fulldomain: Mapped[str] = mapped_column(String(512), nullable=False)
    challenge_domain: Mapped[str] = mapped_column(String(512), nullable=False)
    verified: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_verification_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow)

    certificate = relationship('SslCertificate', back_populates='hosted_acme')
