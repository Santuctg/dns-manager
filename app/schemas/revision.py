from datetime import datetime

from pydantic import BaseModel, ConfigDict


class RevisionRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    revision: str
    status: str
    created_by: int | None
    created_at: datetime


class PendingChanges(BaseModel):
    count: int
