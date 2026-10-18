from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta, timezone

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError

_password_hasher = PasswordHasher()

SESSION_COOKIE = "dns_manager_session"
CSRF_COOKIE = "dns_manager_csrf"
SESSION_LIFETIME = timedelta(hours=8)
SESSION_IDLE_TIMEOUT = timedelta(minutes=30)
ACCOUNT_LOCK_DURATION = timedelta(minutes=15)
IP_RATE_WINDOW = timedelta(minutes=10)
IP_RATE_LIMIT = 5


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def hash_password(password: str) -> str:
    return _password_hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return _password_hasher.verify(password_hash, password)
    except (VerifyMismatchError, InvalidHashError):
        return False


def generate_token() -> str:
    return secrets.token_urlsafe(48)


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def normalize_datetime(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def validate_csrf_tokens(cookie_token: str | None, submitted_token: str | None) -> bool:
    if not cookie_token or not submitted_token:
        return False
    return secrets.compare_digest(cookie_token, submitted_token)
