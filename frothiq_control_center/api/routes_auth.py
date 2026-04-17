"""
Auth routes — login, logout, refresh, user management.
"""

import hashlib
import logging
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from jose import JWTError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from frothiq_control_center.middleware.rate_limiter import limiter
from frothiq_control_center.auth.jwt_handler import create_mfa_challenge_token
from frothiq_control_center.api.routes_mfa import _verify_device_token

from frothiq_control_center.auth import (
    TokenPayload,
    create_access_token,
    create_refresh_token,
    decode_token,
    get_current_user,
    hash_password,
    require_super_admin,
    verify_password,
)
from frothiq_control_center.models.schemas import (
    LoginRequest,
    RefreshRequest,
    TokenResponse,
    UserCreate,
    UserResponse,
    UserUpdate,
)
from frothiq_control_center.models.user import CCUser
from frothiq_control_center.services.audit_service import log_action

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/auth", tags=["auth"])

_MFA_CHALLENGE_PREFIX = "cc:mfa_challenge:"
_MFA_CHALLENGE_TTL = 300  # 5 minutes

# ---------------------------------------------------------------------------
# Account lockout constants
# ---------------------------------------------------------------------------
_LOCKOUT_MAX_FAILURES = 5        # failures before lockout
_LOCKOUT_WINDOW_SECONDS = 900    # 15-minute rolling window
_LOCKOUT_DURATION_SECONDS = 900  # lockout duration (15 minutes)


def _lockout_key(email: str) -> str:
    """Redis key for tracking login failures. Hashed to avoid PII in key names."""
    digest = hashlib.sha256(email.lower().encode()).hexdigest()[:16]
    return f"cc:login_failures:{digest}"


async def _check_lockout(email: str, redis) -> None:
    """Raise 429 if the account is currently locked out."""
    key = _lockout_key(email)
    raw = await redis.get(key)
    if raw and int(raw) >= _LOCKOUT_MAX_FAILURES:
        ttl = await redis.ttl(key)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Account temporarily locked due to too many failed attempts. "
                   f"Try again in {max(ttl, 1)} seconds.",
            headers={"Retry-After": str(max(ttl, 1))},
        )


async def _record_failure(email: str, redis) -> None:
    """Increment failure counter; set/refresh TTL on first failure."""
    key = _lockout_key(email)
    count = await redis.incr(key)
    if count == 1:
        await redis.expire(key, _LOCKOUT_WINDOW_SECONDS)
    logger.warning("Login failure #%d for account (hash %s)", count, key[-8:])


async def _clear_failures(email: str, redis) -> None:
    """Clear failure counter on successful login."""
    await redis.delete(_lockout_key(email))


def _get_db(request: Request) -> AsyncSession:
    return request.state.db


def _get_redis(request: Request):
    return request.state.redis


# ---------------------------------------------------------------------------
# Login / Logout / Refresh
# ---------------------------------------------------------------------------

@router.post("/login", response_model=TokenResponse)
@limiter.limit("10/minute")
async def login(
    request: Request,
    payload: LoginRequest,
):
    """Authenticate with email + password. Returns JWT access + refresh tokens."""
    db: AsyncSession = _get_db(request)
    redis = _get_redis(request)
    client_ip = request.client.host if request.client else None

    # Check account lockout before touching the DB
    await _check_lockout(payload.email, redis)

    result = await db.execute(select(CCUser).where(CCUser.email == payload.email))
    user = result.scalar_one_or_none()

    if not user or not verify_password(payload.password, user.hashed_password):
        # Record failure against this email regardless of whether account exists
        # (avoids user enumeration via timing difference in lockout behavior)
        await _record_failure(payload.email, redis)
        await log_action(
            action="auth.login.failed",
            user_id=None,
            user_email=payload.email,
            detail="Invalid credentials",
            ip_address=client_ip,
            status="failure",
            db=db,
            redis=redis,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is disabled. Contact your administrator.",
        )

    # Success — clear any accumulated failures and update last_login
    await _clear_failures(payload.email, redis)
    user.last_login = datetime.now(timezone.utc).replace(tzinfo=None)
    await db.commit()

    # If 2FA is enabled, check for a trusted device token before issuing a challenge
    if user.totp_enabled:
        if payload.device_token and await _verify_device_token(user.id, payload.device_token, redis):
            # Trusted device — skip 2FA, issue full JWT directly
            await log_action(
                action="auth.login.success",
                user_id=user.id,
                user_email=user.email,
                ip_address=client_ip,
                detail="trusted device — 2FA skipped",
                db=db,
                redis=redis,
            )
            return TokenResponse(
                access_token=create_access_token(user.id, user.role),
                refresh_token=create_refresh_token(user.id, user.role),
                role=user.role,
                user_id=user.id,
                full_name=user.full_name,
            )
        jti = str(uuid.uuid4())
        challenge_token = create_mfa_challenge_token(user.id, jti)
        await redis.setex(f"{_MFA_CHALLENGE_PREFIX}{jti}", _MFA_CHALLENGE_TTL, "1")

        await log_action(
            action="auth.login.mfa_required",
            user_id=user.id,
            user_email=user.email,
            ip_address=client_ip,
            db=db,
            redis=redis,
        )

        return TokenResponse(
            access_token="",
            refresh_token="",
            role=user.role,
            user_id=user.id,
            full_name=user.full_name,
            mfa_required=True,
            mfa_challenge_token=challenge_token,
        )

    access_token = create_access_token(user.id, user.role)
    refresh_token = create_refresh_token(user.id, user.role)

    await log_action(
        action="auth.login.success",
        user_id=user.id,
        user_email=user.email,
        ip_address=client_ip,
        db=db,
        redis=redis,
    )

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        role=user.role,
        user_id=user.id,
        full_name=user.full_name,
    )


@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(payload: RefreshRequest, request: Request):
    """Exchange a refresh token for a new access token."""
    try:
        token_data = decode_token(payload.refresh_token)
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
        )

    if token_data.type != "refresh":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not a refresh token",
        )

    db: AsyncSession = _get_db(request)
    result = await db.execute(select(CCUser).where(CCUser.id == token_data.sub))
    user = result.scalar_one_or_none()

    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or account disabled",
        )

    return TokenResponse(
        access_token=create_access_token(user.id, user.role),
        refresh_token=create_refresh_token(user.id, user.role),
        role=user.role,
        user_id=user.id,
        full_name=user.full_name,
    )


@router.get("/me", response_model=UserResponse)
async def get_me(
    request: Request,
    current_user: TokenPayload = Depends(get_current_user),
):
    """Return the current user's profile."""
    db: AsyncSession = _get_db(request)
    result = await db.execute(select(CCUser).where(CCUser.id == current_user.sub))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return UserResponse.model_validate(user)


# ---------------------------------------------------------------------------
# User management (super_admin only)
# ---------------------------------------------------------------------------

@router.get("/users", response_model=list[UserResponse])
async def list_users(
    request: Request,
    _: TokenPayload = Depends(require_super_admin),
):
    """List all Control Center users."""
    db: AsyncSession = _get_db(request)
    result = await db.execute(select(CCUser).order_by(CCUser.created_at))
    return [UserResponse.model_validate(u) for u in result.scalars().all()]


@router.post("/users", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def create_user(
    payload: UserCreate,
    request: Request,
    current_user: TokenPayload = Depends(require_super_admin),
):
    """Create a new Control Center admin user."""
    db: AsyncSession = _get_db(request)
    redis = _get_redis(request)

    # Check for duplicate email
    existing = await db.execute(select(CCUser).where(CCUser.email == payload.email))
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"User with email {payload.email} already exists",
        )

    user = CCUser(
        email=payload.email,
        hashed_password=hash_password(payload.password),
        full_name=payload.full_name,
        role=payload.role,
        ip_allowlist=payload.ip_allowlist,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)

    await log_action(
        action="user.create",
        user_id=current_user.sub,
        user_email=current_user.sub,
        resource=user.id,
        detail=f"Created user {payload.email} with role {payload.role}",
        ip_address=request.client.host if request.client else None,
        db=db,
        redis=redis,
    )

    return UserResponse.model_validate(user)


@router.patch("/users/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: str,
    payload: UserUpdate,
    request: Request,
    current_user: TokenPayload = Depends(require_super_admin),
):
    """Update a Control Center user's role, status, or name."""
    db: AsyncSession = _get_db(request)
    redis = _get_redis(request)

    result = await db.execute(select(CCUser).where(CCUser.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    if payload.full_name is not None:
        user.full_name = payload.full_name
    if payload.role is not None:
        user.role = payload.role
    if payload.is_active is not None:
        user.is_active = payload.is_active
    if payload.ip_allowlist is not None:
        user.ip_allowlist = payload.ip_allowlist

    await db.commit()
    await db.refresh(user)

    await log_action(
        action="user.update",
        user_id=current_user.sub,
        user_email=current_user.sub,
        resource=user_id,
        detail=f"Updated user {user.email}",
        db=db,
        redis=redis,
    )

    return UserResponse.model_validate(user)


@router.delete("/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(
    user_id: str,
    request: Request,
    current_user: TokenPayload = Depends(require_super_admin),
):
    """Deactivate a Control Center user (soft delete)."""
    db: AsyncSession = _get_db(request)
    redis = _get_redis(request)

    result = await db.execute(select(CCUser).where(CCUser.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    # Prevent self-deletion
    if user_id == current_user.sub:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot deactivate your own account",
        )

    user.is_active = False
    await db.commit()

    await log_action(
        action="user.deactivate",
        user_id=current_user.sub,
        user_email=current_user.sub,
        resource=user_id,
        detail=f"Deactivated user {user.email}",
        db=db,
        redis=redis,
    )
