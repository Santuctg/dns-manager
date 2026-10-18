from __future__ import annotations

from datetime import datetime
from pydantic import BaseModel


class HostedAcmeStatus(BaseModel):
    server_url: str
    subdomain: str
    fulldomain: str
    challenge_domain: str
    verified: bool
    verified_at: datetime | None = None
    last_verification_error: str | None = None
