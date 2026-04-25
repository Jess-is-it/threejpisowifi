import os
from datetime import datetime, timedelta, timezone

import jwt
from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from passlib.context import CryptContext

from .db import fetch_one

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
bearer = HTTPBearer()


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    return pwd_context.verify(password, password_hash)


def create_token(admin: dict) -> str:
    expires = datetime.now(timezone.utc) + timedelta(minutes=int(os.getenv("JWT_EXPIRE_MINUTES", "720")))
    payload = {"sub": str(admin["id"]), "username": admin["username"], "role": admin["role"], "exp": expires}
    return jwt.encode(payload, os.environ["JWT_SECRET"], algorithm="HS256")


def current_admin(credentials: HTTPAuthorizationCredentials = Depends(bearer)) -> dict:
    try:
        payload = jwt.decode(credentials.credentials, os.environ["JWT_SECRET"], algorithms=["HS256"])
    except jwt.PyJWTError as exc:
        raise HTTPException(status_code=401, detail="Invalid or expired token") from exc
    admin = fetch_one("SELECT id, username, role, status FROM admins WHERE id = %s", (payload["sub"],))
    if not admin or admin["status"] != "active":
        raise HTTPException(status_code=401, detail="Admin account is not active")
    return admin
