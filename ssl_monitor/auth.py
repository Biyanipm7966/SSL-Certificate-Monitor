"""JWT authentication — separate access (15 min) and refresh (7 day) tokens."""
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from typing import Optional

import bcrypt
import jwt
from fastapi import Cookie, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from .db import User, get_db

_SECRET = os.environ.get("JWT_SECRET_KEY", "dev-secret-change-in-production")
_ALGO = "HS256"

ACCESS_EXPIRE_MINUTES = 15
REFRESH_EXPIRE_DAYS = 7


# ------------------------------------------------------------------ #
# Password hashing
# ------------------------------------------------------------------ #

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode(), hashed.encode())


# ------------------------------------------------------------------ #
# Token creation
# ------------------------------------------------------------------ #

def _make_token(user_id: str, email: str, token_type: str, delta: timedelta) -> str:
    payload = {
        "sub": user_id,
        "email": email,
        "type": token_type,
        "exp": datetime.now(timezone.utc) + delta,
    }
    return jwt.encode(payload, _SECRET, algorithm=_ALGO)


def create_access_token(user_id: str, email: str) -> str:
    return _make_token(user_id, email, "access", timedelta(minutes=ACCESS_EXPIRE_MINUTES))


def create_refresh_token(user_id: str, email: str) -> str:
    return _make_token(user_id, email, "refresh", timedelta(days=REFRESH_EXPIRE_DAYS))


def decode_token(token: str, expected_type: str) -> Optional[dict]:
    """Decode and validate a JWT.  Returns None if invalid or wrong type."""
    try:
        data = jwt.decode(token, _SECRET, algorithms=[_ALGO])
        if data.get("type") != expected_type:
            return None
        return data
    except Exception:  # noqa: BLE001
        return None


# ------------------------------------------------------------------ #
# FastAPI dependencies
# ------------------------------------------------------------------ #

async def get_current_user(
    access_token: Optional[str] = Cookie(default=None),
    db: AsyncSession = Depends(get_db),
) -> User:
    """Require a valid access token — raises 401 otherwise."""
    exc = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    if not access_token:
        raise exc
    data = decode_token(access_token, "access")
    if not data:
        raise exc
    user = await db.get(User, data["sub"])
    if not user:
        raise exc
    return user


async def get_optional_user(
    access_token: Optional[str] = Cookie(default=None),
    db: AsyncSession = Depends(get_db),
) -> Optional[User]:
    """Return the current user or None — never raises."""
    if not access_token:
        return None
    data = decode_token(access_token, "access")
    if not data:
        return None
    return await db.get(User, data["sub"])
