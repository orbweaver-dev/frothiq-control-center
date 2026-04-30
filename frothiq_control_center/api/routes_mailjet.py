"""
Mailjet integration — account status, statistics, senders, and test sends.

All credentials come from CC_MAILJET_API_KEY / CC_MAILJET_API_SECRET env vars.
Endpoints return a `configured: false` payload when credentials are absent
so the UI can show a helpful setup prompt instead of an error.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, EmailStr

from frothiq_control_center.auth import TokenPayload, require_super_admin
from frothiq_control_center.config import get_settings

router = APIRouter(prefix="/mailjet", tags=["mailjet"])

_MJ_BASE = "https://api.mailjet.com/v3/REST"
_MJ_SEND = "https://api.mailjet.com/v3.1/send"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _auth() -> tuple[str, str] | None:
    s = get_settings()
    if s.mailjet_api_key and s.mailjet_api_secret:
        return (s.mailjet_api_key, s.mailjet_api_secret)
    return None


async def _get(path: str, params: dict | None = None) -> dict:
    creds = _auth()
    if creds is None:
        raise HTTPException(status_code=503, detail="Mailjet credentials not configured")
    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.get(f"{_MJ_BASE}{path}", auth=creds, params=params or {})
        r.raise_for_status()
        return r.json()


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class TestSendRequest(BaseModel):
    to_email: EmailStr
    to_name: str = ""
    subject: str = "FrothIQ Control Center — Test Message"
    text: str = "This is a test message sent from the FrothIQ Control Center Mailjet integration."


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.get("/account")
async def get_account(_: TokenPayload = Depends(require_super_admin)) -> dict[str, Any]:
    """Return Mailjet account / API-key info, or a not-configured marker."""
    creds = _auth()
    if creds is None:
        return {"configured": False}
    try:
        # /apikey/me doesn't exist; /apikey returns the key(s) for this credential
        data = await _get("/apikey")
        record = data.get("Data", [{}])[0]
        return {
            "configured": True,
            "name": record.get("Name", ""),
            "is_active": record.get("IsActive", False),
            "quota_allowed": record.get("QuotaAllowed", 0),
            "quota_used": record.get("QuotaUsed", 0),
            "sender_email": get_settings().mailjet_sender_email,
        }
    except httpx.HTTPStatusError as exc:
        raise HTTPException(status_code=exc.response.status_code, detail=str(exc))


@router.get("/stats")
async def get_stats(_: TokenPayload = Depends(require_super_admin)) -> dict[str, Any]:
    """Return aggregate sending statistics for the past 30 days."""
    creds = _auth()
    if creds is None:
        return {"configured": False}
    try:
        now = datetime.now(timezone.utc)
        from_ts = int((now - timedelta(days=30)).timestamp())
        to_ts = int(now.timestamp())
        data = await _get("/statcounters", {
            "CounterSource": "APIKey",
            "CounterTiming": "Message",
            "CounterResolution": "Day",
            "FromTS": from_ts,
            "ToTS": to_ts,
        })
        rows = data.get("Data") or []
        sent = sum(r.get("MessageSentCount", 0) for r in rows)
        bounced = sum(r.get("MessageBounceCount", 0) for r in rows)
        delivered_raw = sum(r.get("MessageDeliveredCount", 0) for r in rows)
        delivered = delivered_raw or max(sent - bounced, 0)
        spam = sum(r.get("MessageSpamCount", 0) for r in rows)
        opened = sum(r.get("MessageOpenedCount", 0) for r in rows)
        clicked = sum(r.get("MessageClickedCount", 0) for r in rows)
        return {
            "configured": True,
            "period_days": 30,
            "sent": sent,
            "delivered": delivered,
            "bounced": bounced,
            "spam": spam,
            "opened": opened,
            "clicked": clicked,
            "open_rate": round(opened / sent * 100, 1) if sent else 0,
            "click_rate": round(clicked / sent * 100, 1) if sent else 0,
            "bounce_rate": round(bounced / sent * 100, 1) if sent else 0,
        }
    except httpx.HTTPStatusError as exc:
        raise HTTPException(status_code=exc.response.status_code, detail=str(exc))


@router.get("/senders")
async def get_senders(_: TokenPayload = Depends(require_super_admin)) -> dict[str, Any]:
    """Return list of verified sender addresses."""
    creds = _auth()
    if creds is None:
        return {"configured": False, "senders": []}
    try:
        data = await _get("/sender")
        senders = [
            {
                "email": s.get("Email", ""),
                "name": s.get("Name", ""),
                "status": s.get("Status", ""),
                "is_default_sender": s.get("IsDefaultSender", False),
                "email_type": s.get("EmailType", ""),
            }
            for s in (data.get("Data") or [])
        ]
        return {"configured": True, "senders": senders}
    except httpx.HTTPStatusError as exc:
        raise HTTPException(status_code=exc.response.status_code, detail=str(exc))


@router.post("/send-test")
async def send_test(
    body: TestSendRequest,
    _: TokenPayload = Depends(require_super_admin),
) -> dict[str, Any]:
    """Send a test message via Mailjet v3.1 Send API."""
    creds = _auth()
    if creds is None:
        raise HTTPException(status_code=503, detail="Mailjet credentials not configured")
    s = get_settings()
    payload = {
        "Messages": [
            {
                "From": {"Email": s.mailjet_sender_email, "Name": s.mailjet_sender_name},
                "To": [{"Email": body.to_email, "Name": body.to_name or body.to_email}],
                "Subject": body.subject,
                "TextPart": body.text,
            }
        ]
    }
    try:
        async with httpx.AsyncClient(timeout=20) as client:
            r = await client.post(_MJ_SEND, auth=creds, json=payload)
            r.raise_for_status()
            result = r.json()
        msg = (result.get("Messages") or [{}])[0]
        return {
            "status": msg.get("Status", "unknown"),
            "message_id": (msg.get("To") or [{}])[0].get("MessageID"),
        }
    except httpx.HTTPStatusError as exc:
        raise HTTPException(status_code=exc.response.status_code, detail=exc.response.text)
