from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

from app.core.config import get_settings

PASSWORD_HASHER = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4, hash_len=32, salt_len=16)


@dataclass(frozen=True)
class PasswordPolicy:
    minimum_length: int = 12
    maximum_length: int = 128
    require_uppercase: bool = False
    require_lowercase: bool = False
    require_number: bool = False
    require_symbol: bool = False


PASSWORD_POLICY = PasswordPolicy()


def normalize_email(email: str) -> str:
    return email.strip().lower()


def password_hashing_strategy() -> str:
    return 'Argon2id'


def hash_password(password: str) -> str:
    return PASSWORD_HASHER.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return PASSWORD_HASHER.verify(password_hash, password)
    except VerifyMismatchError:
        return False


def create_access_token(subject: str) -> str:
    settings = get_settings()
    now = datetime.now(timezone.utc)
    payload = {
        'sub': subject,
        'iat': int(now.timestamp()),
        'exp': int((now + timedelta(minutes=settings.access_token_expire_minutes)).timestamp()),
        'type': 'access',
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def decode_access_token(token: str) -> dict[str, Any]:
    settings = get_settings()
    return jwt.decode(
        token,
        settings.jwt_secret,
        algorithms=[settings.jwt_algorithm],
        options={'require': ['exp', 'iat', 'sub', 'type']},
    )


def get_bearer_token(header_value: str | None) -> str | None:
    if not header_value:
        return None
    parts = header_value.split()
    if len(parts) != 2 or parts[0].lower() != 'bearer':
        return None
    return parts[1]
