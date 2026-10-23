from __future__ import annotations

from datetime import datetime
from pydantic import BaseModel, Field, field_validator


class SslCertificateCreate(BaseModel):
    domain: str
    provider: str = 'manual'
    api_token: str | None = Field(default=None, exclude=True)
    auto_renew: bool = False
    redirect_http: bool = True

    @field_validator('api_token')
    @classmethod
    def _api_token(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip()
        # Mirrors the helper's check; see privileged/ssl_helper.py.
        if not value or len(value) > 256 or any(not (ch.isascii() and (ch.isalnum() or ch in '_-.')) for ch in value):
            raise ValueError('invalid Cloudflare API token')
        return value


class SslCertificateOut(BaseModel):
    domain: str
    provider: str
    auto_renew: bool
    redirect_http: bool
    status: str
    issuer: str | None = None
    issued_at: datetime | None = None
    expires_at: datetime | None = None
    last_renewal_status: str | None = None
