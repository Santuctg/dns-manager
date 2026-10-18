from __future__ import annotations

from functools import lru_cache
from pathlib import Path
import os

from cryptography.fernet import Fernet


@lru_cache
def load_ssl_secret_key() -> bytes:
    path = os.environ.get('DNS_MANAGER_SSL_SECRET_KEY_FILE', '/etc/dns-manager/ssl-secret.key')
    try:
        key = Path(path).read_bytes().strip()
        Fernet(key)
    except Exception as exc:
        raise RuntimeError('SSL secret key is missing or invalid') from exc
    return key


def encrypt_secret(plaintext: str) -> str:
    return Fernet(load_ssl_secret_key()).encrypt(plaintext.encode()).decode()


def decrypt_secret(ciphertext: str) -> str:
    return Fernet(load_ssl_secret_key()).decrypt(ciphertext.encode()).decode()
