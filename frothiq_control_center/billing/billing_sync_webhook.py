"""
Billing Sync Webhook Receiver.

Receives subscription lifecycle events from ERPNext (or Stripe via ERPNext proxy).
Security:
  - HMAC-SHA256 signature validation (shared secret CC_BILLING_WEBHOOK_SECRET)
  - Replay protection via Redis (event_id TTL=24h)
  - Strict idempotency: duplicate event_id → 200 OK, no re-processing

Payload format (sent by frothiq_frappe billing bridge):
{
    "event_id":    "<uuid>",          // unique per event for replay protection
    "event_type":  "subscription.updated" | "subscription.cancelled" | ...,
    "tenant_id":   "<tenant>",
    "timestamp":   1234567890,        // unix seconds
    "data": {
        "subscription_status": "active" | "past_due" | ...,
        "plan":                "free" | "pro" | "enterprise",
        ...
    }
}

The HMAC signature is sent in the header:
    X-FrothIQ-Signature: t=<timestamp>,v1=<hmac_hex>
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import time
from typing import Any

from frothiq_control_center.billing.billing_sync_client import (
    _apply_and_persist,
)
from frothiq_control_center.integrations.redis_client import get_cache_client

logger = logging.getLogger(__name__)

_REPLAY_TTL = 86400          # 24h — keep processed event IDs
_REPLAY_KEY_PREFIX = "frothiq:webhook:seen:"
_MAX_CLOCK_SKEW = 300        # 5 minutes of allowed clock drift


class WebhookValidationError(ValueError):
    """Raised when a webhook fails security checks."""


async def process_webhook(
    raw_body: bytes,
    signature_header: str,
    webhook_secret: str,
) -> dict[str, Any]:
    """
    Validate and process a billing webhook.

    Args:
        raw_body:          The raw request body bytes.
        signature_header:  Value of X-FrothIQ-Signature header.
        webhook_secret:    Shared HMAC secret from CC_BILLING_WEBHOOK_SECRET.

    Returns:
        {"status": "ok", "event_id": ..., "tenant_id": ..., "action": "processed"|"duplicate"}

    Raises:
        WebhookValidationError on signature failure or replay.
    """
    import json

    # 1. Validate signature
    _verify_signature(raw_body, signature_header, webhook_secret)

    # 2. Parse payload
    try:
        payload: dict[str, Any] = json.loads(raw_body)
    except Exception:
        raise WebhookValidationError("webhook body is not valid JSON")

    event_id = payload.get("event_id")
    tenant_id = payload.get("tenant_id")

    if not event_id:
        raise WebhookValidationError("missing event_id")
    if not tenant_id:
        raise WebhookValidationError("missing tenant_id")

    # 3. Clock skew check
    ts = payload.get("timestamp", 0)
    if abs(time.time() - float(ts)) > _MAX_CLOCK_SKEW:
        raise WebhookValidationError(
            f"timestamp skew too large: {abs(time.time() - float(ts)):.0f}s"
        )

    # 4. Replay protection
    replay_key = f"{_REPLAY_KEY_PREFIX}{event_id}"
    try:
        redis = await get_cache_client()
        already_seen = await redis.get(replay_key)
        if already_seen:
            logger.info("Webhook duplicate: event_id=%s tenant=%s", event_id, tenant_id)
            return {
                "status": "ok",
                "event_id": event_id,
                "tenant_id": tenant_id,
                "action": "duplicate",
            }
        # Mark as seen immediately to prevent race conditions
        await redis.setex(replay_key, _REPLAY_TTL, "1")
    except Exception as exc:
        logger.warning("Replay check Redis error (proceeding): %s", exc)

    # 5. Apply state update
    event_type = payload.get("event_type", "")
    data = payload.get("data") or {}

    # Merge top-level fields into data dict for compatibility
    merged_data = {
        "subscription_status": data.get("subscription_status", "active"),
        "plan":                data.get("plan", "free"),
        "effective_plan":      data.get("effective_plan", data.get("plan", "free")),
        "enforcement_mode":    data.get("enforcement_mode", "alert_only"),
        "features":            data.get("features") or {},
        "limits":              data.get("limits") or {},
        "stripe_customer_id":  data.get("stripe_customer_id"),
        "erpnext_customer":    data.get("erpnext_customer"),
        "erpnext_subscription": data.get("erpnext_subscription"),
        "expiry":              data.get("expiry"),
        "grace_until":         data.get("grace_until"),
    }

    await _apply_and_persist(tenant_id, merged_data, "webhook")
    logger.info(
        "Webhook processed: event_id=%s type=%s tenant=%s status=%s",
        event_id, event_type, tenant_id, merged_data["subscription_status"],
    )

    return {
        "status": "ok",
        "event_id": event_id,
        "tenant_id": tenant_id,
        "action": "processed",
    }


def _verify_signature(
    raw_body: bytes,
    header: str,
    secret: str,
) -> None:
    """
    Validate the X-FrothIQ-Signature header.

    Expected format:  t=<unix_ts>,v1=<hex_digest>
    Signed payload:   f"{timestamp}.{raw_body_as_string}"
    """
    if not header:
        raise WebhookValidationError("missing X-FrothIQ-Signature header")

    parts: dict[str, str] = {}
    for part in header.split(","):
        if "=" in part:
            k, v = part.split("=", 1)
            parts[k.strip()] = v.strip()

    ts = parts.get("t")
    v1 = parts.get("v1")

    if not ts or not v1:
        raise WebhookValidationError("malformed X-FrothIQ-Signature header")

    # Reconstruct signed string
    signed_payload = f"{ts}.{raw_body.decode('utf-8', errors='replace')}"
    expected = hmac.new(
        secret.encode("utf-8"),
        signed_payload.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    if not hmac.compare_digest(expected, v1):
        raise WebhookValidationError("signature mismatch")
