from __future__ import annotations

from datetime import datetime
from pydantic import BaseModel


class AcmeDelegationOut(BaseModel):
    domain: str
    challenge_domain: str
    delegation_id: str
    delegated_fqdn: str
    verified: bool
    verified_at: datetime | None = None
    last_verification_error: str | None = None
