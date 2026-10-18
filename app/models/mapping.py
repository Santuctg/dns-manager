from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Integer, String, Text, event
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Mapping(Base):
    __tablename__ = "mappings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    domain: Mapped[str] = mapped_column(String(253), unique=True, nullable=False, index=True)
    upstream_scheme: Mapped[str] = mapped_column(String(8), nullable=False)
    upstream_host: Mapped[str] = mapped_column(String(255), nullable=False)
    upstream_port: Mapped[int] = mapped_column(Integer, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    websocket_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    preserve_host: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    tls_verify: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    custom_timeout: Mapped[int | None] = mapped_column(Integer, nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_by: Mapped[int | None] = mapped_column(Integer, nullable=True)
    updated_by: Mapped[int | None] = mapped_column(Integer, nullable=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow)


@event.listens_for(Mapping.domain, "set", retval=True)
def _normalize_domain(_target, value: str, _oldvalue, _initiator) -> str:
    return value.strip().lower()
