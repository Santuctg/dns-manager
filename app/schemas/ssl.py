from __future__ import annotations

from datetime import datetime
from pydantic import BaseModel, Field


class SslCertificateCreate(BaseModel):
    domain: str
    provider: str = 'manual'
    api_token: str | None = Field(default=None, exclude=True)
    auto_renew: bool = False
    redirect_http: bool = True


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
