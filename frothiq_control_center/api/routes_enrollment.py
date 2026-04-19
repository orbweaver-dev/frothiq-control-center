"""
IP enrollment flow — default-deny IP allowlist with credential+MFA+admin-email approval.

Flow:
  1. POST /auth/enroll/start    — validate email+password; if TOTP enabled issue enroll challenge
  2. POST /auth/enroll/complete — validate enroll_challenge+totp_code; send admin approval email
  3. GET  /auth/approve-ip/{token} — admin clicks link; IP added to allowlist

All three endpoints bypass the IP allowlist middleware (listed in _PUBLIC_PREFIXES).
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import secrets
import smtplib
import uuid
from datetime import datetime, timedelta, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import pyotp
from fastapi import APIRouter, HTTPException, Request, status
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, EmailStr
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from frothiq_control_center.auth import verify_password
from frothiq_control_center.config import get_settings
from frothiq_control_center.middleware.ip_allowlist import build_allowlist, _ip_in_allowlist, _LOCALHOST_IPS
from frothiq_control_center.models.enrollment import IPAllowlist, IPEnrollmentPending
from frothiq_control_center.models.user import CCUser
from frothiq_control_center.services.audit_service import log_action

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/auth", tags=["enrollment"])

_ENROLL_CHALLENGE_PREFIX = "cc:enroll_challenge:"
_ENROLL_CHALLENGE_TTL = 300   # 5 minutes to complete MFA step
_TOTP_USED_PREFIX = "cc:totp_used:"
_TOTP_USED_TTL = 90
_TOKEN_EXPIRY_HOURS = 24
_IP_CACHE_KEY = "cc:ip_allowlist_cache"

# ---------------------------------------------------------------------------
# Request / response schemas
# ---------------------------------------------------------------------------

class EnrollStartRequest(BaseModel):
    email: str
    password: str


class EnrollCompleteRequest(BaseModel):
    enroll_token: str
    totp_code: str


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _hash_token(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def _get_db(request: Request) -> AsyncSession:
    return request.state.db


def _get_redis(request: Request):
    return request.state.redis


def _get_smtp_cfg():
    """Return SMTP config from the settings file, falling back to env vars."""
    from pathlib import Path as _Path
    import os as _os
    _smtp_file = _Path(_os.environ.get("CC_PORTAL_SETTINGS_DIR", "/var/lib/frothiq/control-center")) / "smtp_settings.json"
    if _smtp_file.exists():
        try:
            import json as _json
            data = _json.loads(_smtp_file.read_text())
            return data
        except Exception:
            pass
    s = get_settings()
    return {"smtp_host": s.smtp_host, "smtp_port": s.smtp_port, "smtp_from": s.smtp_from, "admin_email": s.admin_email}


async def _send_approval_email(ip: str, user_email: str, raw_token: str) -> None:
    """Send admin approval email in a thread pool to avoid blocking the event loop."""
    smtp_cfg = _get_smtp_cfg()
    if not smtp_cfg.get("admin_email"):
        logger.warning("admin_email not configured — skipping approval email")
        return
    settings = get_settings()

    admin_email = smtp_cfg["admin_email"]
    smtp_host = smtp_cfg.get("smtp_host", settings.smtp_host)
    smtp_port = smtp_cfg.get("smtp_port", settings.smtp_port)
    smtp_from = smtp_cfg.get("smtp_from", settings.smtp_from)

    approval_url = f"https://mc3.orbweaver.dev/api/v1/cc/auth/approve-ip/{raw_token}"
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    html = f"""<!DOCTYPE html>
<html>
<body style="font-family:sans-serif;color:#1a1a2e;max-width:560px;margin:0 auto;padding:24px">
  <div style="background:#0f1629;border-radius:8px;padding:24px;color:#e2e8f0">
    <h2 style="color:#4f8ef7;margin:0 0 16px">FrothIQ MC³ — IP Access Request</h2>
    <p style="margin:0 0 12px">A new IP address is requesting access to the control center.</p>
    <table style="border-collapse:collapse;width:100%;margin:0 0 20px">
      <tr><td style="padding:6px 12px 6px 0;color:#94a3b8;white-space:nowrap">IP Address</td>
          <td style="padding:6px 0;font-family:monospace;color:#f1f5f9">{ip}</td></tr>
      <tr><td style="padding:6px 12px 6px 0;color:#94a3b8">User</td>
          <td style="padding:6px 0;color:#f1f5f9">{user_email}</td></tr>
      <tr><td style="padding:6px 12px 6px 0;color:#94a3b8">Requested</td>
          <td style="padding:6px 0;color:#f1f5f9">{timestamp}</td></tr>
    </table>
    <p style="margin:0 0 20px;color:#94a3b8;font-size:14px">
      If you recognise this request and want to approve access, click below.
      This link expires in 24 hours and can only be used once.
    </p>
    <a href="{approval_url}"
       style="display:inline-block;background:#4f8ef7;color:#fff;text-decoration:none;
              padding:12px 24px;border-radius:6px;font-weight:600;font-size:15px">
      Approve IP Access
    </a>
    <p style="margin:20px 0 0;color:#64748b;font-size:12px">
      If you did not request this, ignore this email. The link will expire automatically.
    </p>
  </div>
</body>
</html>"""

    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"[MC³] IP Access Request — {ip}"
    msg["From"] = smtp_from
    msg["To"] = admin_email
    msg.attach(MIMEText(html, "html"))

    def _send():
        try:
            with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as srv:
                srv.sendmail(smtp_from, [admin_email], msg.as_string())
            logger.info("Approval email sent to %s for IP %s", admin_email, ip)
        except Exception as exc:
            logger.error("Failed to send approval email: %s", exc)

    await asyncio.get_event_loop().run_in_executor(None, _send)


def _approval_html(success: bool, ip: str = "", message: str = "") -> str:
    color = "#22c55e" if success else "#ef4444"
    title = "IP Approved" if success else "Approval Failed"
    body = f"IP <code style='font-family:monospace'>{ip}</code> has been added to the access list." if success else message
    return f"""<!DOCTYPE html>
<html>
<body style="font-family:sans-serif;background:#060b14;color:#e2e8f0;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0">
  <div style="background:#0f1629;border:1px solid #1e2d4a;border-radius:12px;padding:40px 48px;max-width:480px;text-align:center">
    <div style="font-size:48px;margin-bottom:16px">{"✅" if success else "❌"}</div>
    <h2 style="color:{color};margin:0 0 12px">{title}</h2>
    <p style="color:#94a3b8;margin:0 0 24px">{body}</p>
    <a href="https://mc3.orbweaver.dev" style="color:#4f8ef7;text-decoration:none;font-size:14px">← Return to MC³</a>
  </div>
</body>
</html>"""


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/ip-status")
async def ip_status(request: Request):
    """
    Public endpoint — returns whether the requesting IP is on the allowlist.
    Called by the Next.js middleware on every page load to decide /login vs /enroll.
    """
    client_ip = _client_ip(request)
    if client_ip in _LOCALHOST_IPS:
        return {"allowed": True, "ip": client_ip}

    redis = _get_redis(request)
    db = _get_db(request)
    allowlist = await build_allowlist(redis, db)
    allowed = bool(allowlist) and _ip_in_allowlist(client_ip, allowlist)
    return {"allowed": allowed, "ip": client_ip}


@router.post("/enroll/start")
async def enroll_start(payload: EnrollStartRequest, request: Request):
    """
    Step 1: Validate email + password.
    - If IP already approved → return already_approved.
    - If TOTP enabled → issue enroll challenge token for step 2.
    - If no TOTP → immediately send admin email and return pending.
    """
    db = _get_db(request)
    redis = _get_redis(request)
    client_ip = _client_ip(request)

    # Load user
    result = await db.execute(select(CCUser).where(CCUser.email == payload.email))
    user = result.scalar_one_or_none()

    if not user or not verify_password(payload.password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect email or password. Check your credentials and try again.")

    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account is disabled")

    # Check if IP already approved
    existing = await db.execute(select(IPAllowlist).where(IPAllowlist.ip == client_ip))
    if existing.scalar_one_or_none():
        return {"status": "already_approved", "message": "This IP is already in the access list."}

    # Check if a pending enrollment already exists for this IP
    pending = await db.execute(
        select(IPEnrollmentPending).where(
            IPEnrollmentPending.ip == client_ip,
            IPEnrollmentPending.used == False,  # noqa: E712
            IPEnrollmentPending.expires_at > datetime.utcnow(),
        )
    )
    if pending.scalar_one_or_none():
        return {"status": "pending", "message": "An approval request is already pending for this IP."}

    if user.totp_enabled:
        # Issue a short-lived enroll challenge so the client can supply the TOTP code
        jti = str(uuid.uuid4())
        challenge_data = json.dumps({"user_id": user.id, "ip": client_ip, "user_email": user.email})
        await redis.setex(f"{_ENROLL_CHALLENGE_PREFIX}{jti}", _ENROLL_CHALLENGE_TTL, challenge_data)

        await log_action(
            action="enrollment.mfa_required",
            user_id=user.id,
            user_email=user.email,
            ip_address=client_ip,
            db=db,
            redis=redis,
        )
        return {"status": "mfa_required", "enroll_token": jti}

    # No TOTP — proceed directly to email approval
    raw_token = secrets.token_hex(32)
    token_hash = _hash_token(raw_token)
    expires_at = datetime.utcnow() + timedelta(hours=_TOKEN_EXPIRY_HOURS)

    db.add(IPEnrollmentPending(
        id=str(uuid.uuid4()),
        token_hash=token_hash,
        ip=client_ip,
        user_email=user.email,
        expires_at=expires_at,
    ))
    await db.commit()

    await _send_approval_email(client_ip, user.email, raw_token)

    await log_action(
        action="enrollment.requested",
        user_id=user.id,
        user_email=user.email,
        ip_address=client_ip,
        detail="No TOTP — approval email sent",
        db=db,
        redis=redis,
    )
    return {"status": "pending", "message": "Approval request sent. You will be notified when your IP is approved."}


@router.post("/enroll/complete")
async def enroll_complete(payload: EnrollCompleteRequest, request: Request):
    """
    Step 2 (TOTP users only): Validate TOTP code then send admin approval email.
    """
    db = _get_db(request)
    redis = _get_redis(request)
    client_ip = _client_ip(request)

    # Retrieve enroll challenge
    challenge_raw = await redis.get(f"{_ENROLL_CHALLENGE_PREFIX}{payload.enroll_token}")
    if not challenge_raw:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Enroll session expired. Please start again.")

    try:
        challenge = json.loads(challenge_raw if isinstance(challenge_raw, str) else challenge_raw.decode())
    except Exception:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid enroll session.")

    if challenge.get("ip") != client_ip:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="IP address changed during enrollment.")

    user_id = challenge["user_id"]
    user_email = challenge["user_email"]

    result = await db.execute(select(CCUser).where(CCUser.id == user_id))
    user = result.scalar_one_or_none()
    if not user or not user.totp_secret:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid enrollment session.")

    # Replay guard
    totp_used_key = f"{_TOTP_USED_PREFIX}{user_id}:{payload.totp_code}"
    if await redis.exists(totp_used_key):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Authenticator code already used. Wait for a new code.")

    totp = pyotp.TOTP(user.totp_secret)
    if not totp.verify(payload.totp_code, valid_window=1):
        await log_action(action="enrollment.mfa_failed", user_id=user_id, user_email=user_email, ip_address=client_ip, db=db, redis=redis)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authenticator code.")

    await redis.setex(totp_used_key, _TOTP_USED_TTL, "1")
    await redis.delete(f"{_ENROLL_CHALLENGE_PREFIX}{payload.enroll_token}")

    # Check if IP already approved or pending
    existing = await db.execute(select(IPAllowlist).where(IPAllowlist.ip == client_ip))
    if existing.scalar_one_or_none():
        return {"status": "already_approved", "message": "This IP is already in the access list."}

    pending_q = await db.execute(
        select(IPEnrollmentPending).where(
            IPEnrollmentPending.ip == client_ip,
            IPEnrollmentPending.used == False,  # noqa: E712
            IPEnrollmentPending.expires_at > datetime.utcnow(),
        )
    )
    if pending_q.scalar_one_or_none():
        return {"status": "pending", "message": "An approval request is already pending for this IP."}

    # Generate approval token
    raw_token = secrets.token_hex(32)
    token_hash = _hash_token(raw_token)
    expires_at = datetime.utcnow() + timedelta(hours=_TOKEN_EXPIRY_HOURS)

    db.add(IPEnrollmentPending(
        id=str(uuid.uuid4()),
        token_hash=token_hash,
        ip=client_ip,
        user_email=user_email,
        expires_at=expires_at,
    ))
    await db.commit()

    await _send_approval_email(client_ip, user_email, raw_token)

    await log_action(
        action="enrollment.requested",
        user_id=user_id,
        user_email=user_email,
        ip_address=client_ip,
        detail="TOTP verified — approval email sent",
        db=db,
        redis=redis,
    )
    return {"status": "pending", "message": "Approval request sent. You will be notified when your IP is approved."}


@router.get("/approve-ip/{raw_token}", response_class=HTMLResponse)
async def approve_ip(raw_token: str, request: Request):
    """
    Admin clicks email link — validates token, adds IP to allowlist, marks token used.
    Returns an HTML confirmation page.
    """
    db = _get_db(request)
    redis = _get_redis(request)

    if len(raw_token) != 64 or not all(c in "0123456789abcdef" for c in raw_token):
        return HTMLResponse(_approval_html(False, message="Invalid approval link."), status_code=400)

    token_hash = _hash_token(raw_token)

    result = await db.execute(
        select(IPEnrollmentPending).where(IPEnrollmentPending.token_hash == token_hash)
    )
    pending = result.scalar_one_or_none()

    if not pending:
        return HTMLResponse(_approval_html(False, message="Approval link not found or already used."), status_code=404)

    if pending.used:
        return HTMLResponse(_approval_html(False, message="This approval link has already been used."), status_code=410)

    if pending.expires_at < datetime.utcnow():
        return HTMLResponse(_approval_html(False, message="This approval link has expired. Ask the user to re-enroll."), status_code=410)

    # Check if already in allowlist (double-approval prevention)
    existing = await db.execute(select(IPAllowlist).where(IPAllowlist.ip == pending.ip))
    if not existing.scalar_one_or_none():
        db.add(IPAllowlist(
            id=str(uuid.uuid4()),
            ip=pending.ip,
            user_email=pending.user_email,
            approved_at=datetime.utcnow(),
        ))

    pending.used = True
    await db.commit()

    # Invalidate IP allowlist cache so middleware picks up new IP immediately
    await redis.delete(_IP_CACHE_KEY)

    await log_action(
        action="enrollment.approved",
        user_id=None,
        user_email=pending.user_email,
        ip_address=request.client.host if request.client else None,
        detail=f"IP {pending.ip} approved by admin",
        db=db,
        redis=redis,
    )
    logger.info("IP %s approved for user %s", pending.ip, pending.user_email)

    return HTMLResponse(_approval_html(True, ip=pending.ip))
