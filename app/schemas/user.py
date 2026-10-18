from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator


class RoleSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    name: str


class UserRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    username: str
    email: str | None
    is_active: bool
    role: RoleSummary
    failed_login_count: int
    locked_until: datetime | None
    last_login_at: datetime | None
    created_at: datetime
    updated_at: datetime


class UserCreate(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    email: str | None = Field(default=None, max_length=255)
    password: str = Field(min_length=12, max_length=512)
    role_id: int

    @field_validator('username')
    @classmethod
    def clean_username(cls, value: str) -> str:
        value = value.strip()
        if not value or any(ch.isspace() for ch in value):
            raise ValueError('username must not contain whitespace')
        return value

    @field_validator('email')
    @classmethod
    def clean_email(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip().lower()
        return value or None


class UserUpdate(BaseModel):
    username: str | None = Field(default=None, min_length=1, max_length=64)
    email: str | None = Field(default=None, max_length=255)
    role_id: int | None = None
    is_active: bool | None = None

    @field_validator('username')
    @classmethod
    def clean_username(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip()
        if not value or any(ch.isspace() for ch in value):
            raise ValueError('username must not contain whitespace')
        return value

    @field_validator('email')
    @classmethod
    def clean_email(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip().lower()
        return value or None


class PasswordReset(BaseModel):
    password: str = Field(min_length=12, max_length=512)


class PasswordResetResult(BaseModel):
    success: bool = True


class RoleCreate(BaseModel):
    name: str = Field(min_length=2, max_length=64, pattern=r"^[a-z][a-z0-9_-]{1,63}$")
    description: str | None = Field(default=None, max_length=255)
    permissions: list[str] = Field(min_length=1)


class RoleRead(BaseModel):
    id: int
    name: str
    description: str | None
    permissions: list[str]


class RolePermissionsUpdate(BaseModel):
    permissions: list[str] = Field(min_length=1)
