"""
2FA / TOTP routes — Google Authenticator compatible.

Endpoints:
  POST /auth/2fa/setup          — generate secret + QR code for authenticated user
  POST /auth/2fa/verify-setup   — verify code and activate 2FA
  POST /auth/2fa/disable        — deactivate 2FA (requires password + TOTP code)
  POST /auth/2fa/challenge      — exchange challenge token + TOTP code for full JWT

Login flow when 2FA is enabled:
  1. POST /auth/login  → returns {mfa_required: true, mfa_challenge_token: "<5-min JWT>"}
  2. POST /auth/2fa/challenge  → returns full access + refresh tokens
"""

from __future__ import annotations

import base64
import io
import logging
import uuid

import pyotp
import qrcode
from fastapi import APIRouter, Depends, HTTPException, Request, status
from jose import JWTError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from frothiq_control_center.auth import (
    TokenPayload,
    create_access_token,
    create_refresh_token,
    decode_token,
    get_current_user,
    verify_password,
)
from frothiq_control_center.auth.jwt_handler import create_mfa_challenge_token
from frothiq_control_center.models.schemas import (
    MFAChallengeRequest,
    TOTPDisableRequest,
    TOTPSetupResponse,
    TOTPVerifySetupRequest,
    TokenResponse,
)
from frothiq_control_center.models.user import CCUser
from frothiq_control_center.services.audit_service import log_action

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/auth/2fa", tags=["2fa"])

# Redis key prefix for pending (not yet verified) TOTP secrets during setup
_PENDING_SECRET_PREFIX = "cc:totp_pending:"
_PENDING_SECRET_TTL = 600  # 10 minutes to complete setup
# Redis key prefix for MFA challenge tokens (revoked once used)
_MFA_CHALLENGE_PREFIX = "cc:mfa_challenge:"
_MFA_CHALLENGE_TTL = 300   # 5 minutes


def _get_db(request: Request) -> AsyncSession:
    return request.state.db


def _get_redis(request: Request):
    return request.state.redis


def _totp_for_secret(secret: str) -> pyotp.TOTP:
    return pyotp.TOTP(secret)


def _qr_png_b64(uri: str) -> str:
    """Render the otpauth:// URI as a base64-encoded PNG."""
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode()


# ---------------------------------------------------------------------------
# Setup — generate secret + QR code
# ---------------------------------------------------------------------------

@router.post("/setup", response_model=TOTPSetupResponse)
async def setup_2fa(
    request: Request,
    current_user: TokenPayload = Depends(get_current_user),
):
    """
    Generate a new TOTP secret and QR code for the authenticated user.
    The secret is stored in Redis as pending until /verify-setup confirms it.
    Call this endpoint to begin the enrollment flow.
    """
    db: AsyncSession = _get_db(request)
    redis = _get_redis(request)

    result = await db.execute(select(CCUser).where(CCUser.id == current_user.sub))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    if user.totp_enabled:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="2FA is already enabled. Disable it first to re-enroll.",
        )

    secret = pyotp.random_base32()
    totp = _totp_for_secret(secret)
    uri = totp.provisioning_uri(name=user.email, issuer_name="FrothIQ MC³")

    # Store pending secret in Redis — not committed to DB until verified
    await redis.setex(f"{_PENDING_SECRET_PREFIX}{current_user.sub}", _PENDING_SECRET_TTL, secret)

    return TOTPSetupResponse(
        provisioning_uri=uri,
        qr_code_png_b64=_qr_png_b64(uri),
        secret=secret,
    )


# ---------------------------------------------------------------------------
# Verify setup — confirm code and activate 2FA
# ---------------------------------------------------------------------------

@router.post("/verify-setup", status_code=status.HTTP_200_OK)
async def verify_setup_2fa(
    payload: TOTPVerifySetupRequest,
    request: Request,
    current_user: TokenPayload = Depends(get_current_user),
):
    """
    Verify a TOTP code from Google Authenticator and activate 2FA on the account.
    Must be called after /setup while the pending secret is still in Redis.
    """
    db: AsyncSession = _get_db(request)
    redis = _get_redis(request)

    secret = await redis.get(f"{_PENDING_SECRET_PREFIX}{current_user.sub}")
    if not secret:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No pending 2FA setup found. Call /auth/2fa/setup first.",
        )

    if isinstance(secret, bytes):
        secret = secret.decode()

    totp = _totp_for_secret(secret)
    if not totp.verify(payload.totp_code, valid_window=1):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid verification code. Check your authenticator app and try again.",
        )

    # Activate — write secret to DB and clear pending Redis key
    result = await db.execute(select(CCUser).where(CCUser.id == current_user.sub))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    user.totp_secret = secret
    user.totp_enabled = True
    await db.commit()
    await redis.delete(f"{_PENDING_SECRET_PREFIX}{current_user.sub}")

    await log_action(
        action="auth.2fa.enabled",
        user_id=current_user.sub,
        user_email=current_user.sub,
        ip_address=request.client.host if request.client else None,
        db=db,
        redis=redis,
    )

    return {"ok": True, "message": "Two-factor authentication has been enabled."}


# ---------------------------------------------------------------------------
# Disable 2FA
# ---------------------------------------------------------------------------

@router.post("/disable", status_code=status.HTTP_200_OK)
async def disable_2fa(
    payload: TOTPDisableRequest,
    request: Request,
    current_user: TokenPayload = Depends(get_current_user),
):
    """
    Disable 2FA on the account. Requires the current password and a valid TOTP code.
    """
    db: AsyncSession = _get_db(request)
    redis = _get_redis(request)

    result = await db.execute(select(CCUser).where(CCUser.id == current_user.sub))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    if not user.totp_enabled or not user.totp_secret:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="2FA is not enabled on this account.",
        )

    if not verify_password(payload.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect password.",
        )

    totp = _totp_for_secret(user.totp_secret)
    if not totp.verify(payload.totp_code, valid_window=1):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid TOTP code.",
        )

    user.totp_secret = None
    user.totp_enabled = False
    await db.commit()

    await log_action(
        action="auth.2fa.disabled",
        user_id=current_user.sub,
        user_email=current_user.sub,
        ip_address=request.client.host if request.client else None,
        db=db,
        redis=redis,
    )

    return {"ok": True, "message": "Two-factor authentication has been disabled."}


# ---------------------------------------------------------------------------
# MFA challenge — exchange challenge token + TOTP code for full JWT
# ---------------------------------------------------------------------------

@router.post("/challenge", response_model=TokenResponse)
async def mfa_challenge(
    payload: MFAChallengeRequest,
    request: Request,
):
    """
    Complete login when 2FA is required.
    Accepts the mfa_challenge_token from the initial login response and a
    valid 6-digit TOTP code. Returns full access + refresh tokens on success.
    """
    db: AsyncSession = _get_db(request)
    redis = _get_redis(request)
    client_ip = request.client.host if request.client else None

    # Decode and validate the challenge token
    try:
        token_data = decode_token(payload.mfa_challenge_token)
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired MFA challenge token.",
        )

    if token_data.type != "mfa_challenge":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not an MFA challenge token.",
        )

    if not token_data.jti:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Malformed challenge token.",
        )

    # Verify the challenge is still alive in Redis (single-use)
    redis_key = f"{_MFA_CHALLENGE_PREFIX}{token_data.jti}"
    still_valid = await redis.exists(redis_key)
    if not still_valid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="MFA challenge has expired or was already used.",
        )

    # Load user and verify TOTP
    result = await db.execute(select(CCUser).where(CCUser.id == token_data.sub))
    user = result.scalar_one_or_none()
    if not user or not user.is_active or not user.totp_enabled or not user.totp_secret:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid MFA challenge.",
        )

    totp = _totp_for_secret(user.totp_secret)
    if not totp.verify(payload.totp_code, valid_window=1):
        await log_action(
            action="auth.2fa.challenge.failed",
            user_id=user.id,
            user_email=user.email,
            ip_address=client_ip,
            status="failure",
            db=db,
            redis=redis,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authenticator code.",
        )

    # Single-use: delete challenge from Redis
    await redis.delete(redis_key)

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
