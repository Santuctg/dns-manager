from __future__ import annotations

import ipaddress
import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

_HOST_RE = re.compile(r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(?:\.(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?))*$")


def normalize_domain(value: str) -> str:
    value = value.strip().lower().rstrip(".")
    if not value or len(value) > 253 or "://" in value or "/" in value or ":" in value or "*" in value:
        raise ValueError("invalid domain")
    if not _HOST_RE.fullmatch(value) or "." not in value:
        raise ValueError("invalid domain")
    return value


def validate_upstream_host(value: str) -> str:
    value = value.strip()
    if not value or any(ch in value for ch in "\r\n;{}'\"`$\\/ "):
        raise ValueError("invalid upstream host")
    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        pass
    host = value.lower().rstrip(".")
    if not _HOST_RE.fullmatch(host):
        raise ValueError("invalid upstream host")
    return host


class MappingBase(BaseModel):
    domain: str
    upstream_scheme: Literal["http", "https"]
    upstream_host: str
    upstream_port: int = Field(ge=1, le=65535)
    enabled: bool = True
    websocket_enabled: bool = True
    preserve_host: bool = True
    tls_verify: bool = True
    custom_timeout: int | None = Field(default=None, ge=1, le=3600)
    description: str | None = Field(default=None, max_length=2000)

    @field_validator("domain")
    @classmethod
    def _domain(cls, value: str) -> str:
        return normalize_domain(value)

    @field_validator("upstream_host")
    @classmethod
    def _host(cls, value: str) -> str:
        return validate_upstream_host(value)


class MappingCreate(MappingBase):
    pass


class MappingUpdate(MappingBase):
    version: int = Field(ge=1)


class MappingRead(MappingBase):
    model_config = ConfigDict(from_attributes=True)
    id: int
    version: int
    created_by: int | None
    updated_by: int | None
    ssl_status: str | None = None
