"""
JWT handling — issue, verify, and decode access + refresh tokens.

Roles (from least to most privileged):
  read_only        — view-only access to all dashboards
  billing_admin    — monetization + license views + billing actions
  security_analyst — defense mesh, policy mesh, simulation read + run
  super_admin      — full system access including tenant management

Role hierarchy (each role includes all permissions of roles below it):
  super_admin > security_analyst > billing_admin > read_only
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from typing import Any, Callable, Literal

from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from pydantic import BaseModel

from frothiq_control_center.config import get_settings

logger = logging.getLogger(__name__)

Role = Literal["super_admin", "security_analyst", "billing_admin", "read_only"]

# Privilege level for role comparison (higher = more privileged)
ROLE_LEVEL: dict[str, int] = {
    "read_only": 1,
    "billing_admin": 2,
    "security_analyst": 3,
    "super_admin": 4,
}

TOKEN_TYPE_ACCESS = "access"
TOKEN_TYPE_REFRESH = "refresh"
TOKEN_TYPE_MFA_CHALLENGE = "mfa_challenge"


class TokenPayload(BaseModel):
    sub: str          # user_id
    role: Role
    type: str         # "access" | "refresh"
    iat: datetime
    exp: datetime
    jti: str | None = None  # token ID for revocation


def create_access_token(user_id: str, role: Role, extra: dict[str, Any] | None = None) -> str:
    settings = get_settings()
    now = datetime.now(UTC)
    expire = now + timedelta(minutes=settings.access_token_expire_minutes)
    payload: dict[str, Any] = {
        "sub": user_id,
        "role": role,
        "type": TOKEN_TYPE_ACCESS,
        "iat": now,
        "exp": expire,
    }
    if extra:
        payload.update(extra)
    return jwt.encode(payload, settings.secret_key, algorithm=settings.jwt_algorithm)


def create_refresh_token(user_id: str, role: Role) -> str:
    settings = get_settings()
    now = datetime.now(UTC)
    expire = now + timedelta(days=settings.refresh_token_expire_days)
    payload: dict[str, Any] = {
        "sub": user_id,
        "role": role,
        "type": TOKEN_TYPE_REFRESH,
        "iat": now,
        "exp": expire,
    }
    return jwt.encode(payload, settings.secret_key, algorithm=settings.jwt_algorithm)


def create_mfa_challenge_token(user_id: str, jti: str) -> str:
    """Short-lived (5 min) token issued after password auth when 2FA is required.
    The frontend holds this and exchanges it + a valid TOTP code for a full JWT."""
    settings = get_settings()
    now = datetime.now(UTC)
    expire = now + timedelta(minutes=5)
    payload: dict[str, Any] = {
        "sub": user_id,
        "role": "read_only",   # placeholder — real role issued after TOTP verify
        "type": TOKEN_TYPE_MFA_CHALLENGE,
        "jti": jti,
        "iat": now,
        "exp": expire,
    }
    return jwt.encode(payload, settings.secret_key, algorithm=settings.jwt_algorithm)


def decode_token(token: str) -> TokenPayload:
    """Decode and validate a JWT. Raises JWTError on failure."""
    settings = get_settings()
    try:
        raw = jwt.decode(token, settings.secret_key, algorithms=[settings.jwt_algorithm])
    except JWTError:
        raise
    return TokenPayload(**raw)


def role_at_least(user_role: str, required_role: str) -> bool:
    """Return True if user_role has equal or greater privilege than required_role."""
    return ROLE_LEVEL.get(user_role, 0) >= ROLE_LEVEL.get(required_role, 999)


# ---------------------------------------------------------------------------
# FastAPI dependency helpers
# ---------------------------------------------------------------------------

_bearer = HTTPBearer()


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(_bearer),
) -> TokenPayload:
    """FastAPI dependency: extract and validate the Bearer JWT."""
    try:
        return decode_token(credentials.credentials)
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")


def require_role(minimum_role: str) -> Callable:
    """Return a FastAPI dependency that enforces a minimum role level."""
    async def _checker(
        current_user: TokenPayload = Depends(get_current_user),
    ) -> TokenPayload:
        if not role_at_least(current_user.role, minimum_role):
            raise HTTPException(
                status_code=403,
                detail=(
                    f"Role '{current_user.role}' is insufficient. "
                    f"Required: {minimum_role} or above."
                ),
            )
        return current_user
    return _checker
