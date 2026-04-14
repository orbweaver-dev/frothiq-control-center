"""
FastAPI dependency injection for authentication + authorization.

Usage:
  from frothiq_control_center.auth.dependencies import (
      get_current_user, require_role, require_super_admin,
      require_security_analyst, require_billing_admin,
  )
"""

from __future__ import annotations

import logging

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError

from .jwt_handler import Role, TokenPayload, decode_token, role_at_least

logger = logging.getLogger(__name__)

_bearer = HTTPBearer(auto_error=False)

CREDENTIALS_EXCEPTION = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Invalid or missing authentication token",
    headers={"WWW-Authenticate": "Bearer"},
)


async def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
) -> TokenPayload:
    """
    Extract and validate the JWT from the Authorization header.
    Also accepts token via ?token= query param (WebSocket use).
    """
    token: str | None = None

    if credentials:
        token = credentials.credentials
    else:
        # WebSocket / query-param fallback
        token = request.query_params.get("token")

    if not token:
        raise CREDENTIALS_EXCEPTION

    try:
        payload = decode_token(token)
    except JWTError as exc:
        logger.warning("JWT decode failed: %s", exc)
        raise CREDENTIALS_EXCEPTION

    if payload.type != "access":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh tokens cannot be used for API access",
        )

    return payload


def require_role(minimum_role: Role):
    """
    Dependency factory — enforces a minimum role level.

    Example:
        @router.get("/admin-only")
        async def endpoint(user: TokenPayload = Depends(require_role("super_admin"))):
            ...
    """
    async def _check(user: TokenPayload = Depends(get_current_user)) -> TokenPayload:
        if not role_at_least(user.role, minimum_role):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires {minimum_role} role or above. Your role: {user.role}",
            )
        return user
    return _check


# Convenience aliases
require_super_admin = require_role("super_admin")
require_security_analyst = require_role("security_analyst")
require_billing_admin = require_role("billing_admin")
require_read_only = require_role("read_only")


async def get_api_key_service(request: Request) -> str:
    """
    Validates a static service-to-service API key.
    Used by internal endpoints called from frothiq-core or other services.
    """
    from frothiq_control_center.config import get_settings

    settings = get_settings()
    key = request.headers.get("X-Service-Key") or request.headers.get("X-API-Key")
    if not key or key != settings.core_service_api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing service API key",
        )
    return key
