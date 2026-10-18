from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base
from app.models.ssl import utcnow


class SslAcmeDelegation(Base):
    __tablename__ = "ssl_acme_delegations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    certificate_id: Mapped[int] = mapped_column(
        ForeignKey("ssl_certificates.id", ondelete="CASCADE"), unique=True, nullable=False
    )
    domain: Mapped[str] = mapped_column(String(253), nullable=False, index=True)
    challenge_domain: Mapped[str] = mapped_column(String(512), nullable=False)
    delegation_id: Mapped[str] = mapped_column(String(32), nullable=False, unique=True)
    delegated_fqdn: Mapped[str] = mapped_column(String(512), nullable=False, unique=True)
    verified: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_verification_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow)

    certificate = relationship("SslCertificate", back_populates="delegation")
