from __future__ import annotations

from datetime import datetime, timedelta, timezone

import jwt

from app.core.config import settings


def create_admin_token(admin_username: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "iss": settings.jwt_issuer,
        "sub": f"admin:{admin_username}",
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=settings.jwt_expires_seconds)).timestamp()),
        "role": "admin",
        "username": admin_username,
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm="HS256")


def create_user_token(user_id: int, username: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "iss": settings.jwt_issuer,
        "sub": f"user:{user_id}",
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=settings.jwt_expires_seconds)).timestamp()),
        "role": "user",
        "user_id": int(user_id),
        "username": username,
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm="HS256")


def decode_token(token: str) -> dict:
    return jwt.decode(token, settings.jwt_secret, algorithms=["HS256"], issuer=settings.jwt_issuer)
