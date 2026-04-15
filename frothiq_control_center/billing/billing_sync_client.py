"""
Billing Sync Client — pulls subscription state from ERPNext (via frothiq_frappe
billing bridge) with exponential backoff and drift correction.

Pull endpoint:
    GET {FRAPPE_SITE_URL}/api/method/frothiq_frappe.frothiq_billing_bridge.subscription_state_api
        ?tenant_id={tenant_id}

The bridge returns a dict matching SubscriptionState shape.
If the bridge is unreachable, the client returns a fallback "free/active" state
so that edge plugins are never left without a decision.
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from typing import Any

import httpx

from frothiq_control_center.billing.license_state_cache import (
    get_billing_state,
    get_all_billing_states,
    set_billing_state,
)
from frothiq_control_center.billing.subscription_state_machine import (
    SubscriptionState,
    apply_event,
    erpnext_status_to_state,
)

logger = logging.getLogger(__name__)

_FRAPPE_BASE = os.getenv("FRAPPE_SITE_URL", "http://localhost:8000")
_FRAPPE_API_KEY = os.getenv("FRAPPE_API_KEY", "")
_FRAPPE_API_SECRET = os.getenv("FRAPPE_API_SECRET", "")
_SUB_STATE_API = (
    "/api/method/frothiq_frappe.frothiq_billing_bridge.subscription_state_api"
)

# Retry config
_MAX_RETRIES = 4
_BASE_BACKOFF = 1.0   # seconds
_MAX_BACKOFF = 60.0   # seconds

# Free plan fallback
_FREE_FALLBACK: dict[str, Any] = {
    "subscription_status": "active",
    "plan": "free",
    "effective_plan": "free",
    "enforcement_mode": "alert_only",
    "features": {"waf": True, "rate_limiting": True, "geo_blocking": False, "ai_detection": False},
    "limits": {"requests_per_minute": 60, "blocked_ips": 100},
    "stripe_customer_id": None,
    "erpnext_customer": None,
    "erpnext_subscription": None,
    "expiry": None,
    "grace_until": None,
    "source": "fallback",
}


def _build_headers() -> dict[str, str]:
    if _FRAPPE_API_KEY and _FRAPPE_API_SECRET:
        return {"Authorization": f"token {_FRAPPE_API_KEY}:{_FRAPPE_API_SECRET}"}
    return {}


async def pull_tenant_state(tenant_id: str) -> dict[str, Any]:
    """
    Pull the latest subscription state for *tenant_id* from ERPNext.

    Applies the state machine to prevent illegal regressions, then
    persists to cache + DB.

    Returns the resolved state dict. Never raises.
    """
    url = f"{_FRAPPE_BASE}{_SUB_STATE_API}"
    params = {"tenant_id": tenant_id}
    headers = _build_headers()

    raw: dict[str, Any] | None = None
    backoff = _BASE_BACKOFF

    for attempt in range(1, _MAX_RETRIES + 1):
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(url, params=params, headers=headers)
                resp.raise_for_status()
                body = resp.json()
                raw = body.get("message") or body
                break
        except httpx.HTTPStatusError as exc:
            logger.warning(
                "pull_tenant_state: HTTP %d for %s (attempt %d/%d)",
                exc.response.status_code, tenant_id, attempt, _MAX_RETRIES,
            )
        except Exception as exc:
            logger.warning(
                "pull_tenant_state: error for %s (attempt %d/%d): %s",
                tenant_id, attempt, _MAX_RETRIES, exc,
            )

        if attempt < _MAX_RETRIES:
            await asyncio.sleep(min(backoff, _MAX_BACKOFF))
            backoff *= 2

    if raw is None:
        logger.error("pull_tenant_state: all retries failed for %s — using fallback", tenant_id)
        existing = await get_billing_state(tenant_id)
        if existing:
            return existing
        # No cached state at all — write free fallback
        fallback = {**_FREE_FALLBACK, "tenant_id": tenant_id, "last_updated": time.time()}
        return await _persist(tenant_id, fallback, "fallback")

    return await _apply_and_persist(tenant_id, raw, "erpnext_fresh")


async def pull_all_tenants() -> dict[str, Any]:
    """
    Pull state for every known tenant (used by scheduled refresh).
    Returns a summary dict {total, updated, failed}.
    """
    all_states = await get_all_billing_states()
    tenant_ids = [s["tenant_id"] for s in all_states]

    if not tenant_ids:
        # Also try to discover tenants from ERPNext
        tenant_ids = await _discover_tenants()

    total = len(tenant_ids)
    updated = 0
    failed = 0

    for tenant_id in tenant_ids:
        try:
            await pull_tenant_state(tenant_id)
            updated += 1
        except Exception as exc:
            logger.error("pull_all_tenants: failed for %s: %s", tenant_id, exc)
            failed += 1

    return {"total": total, "updated": updated, "failed": failed}


async def _discover_tenants() -> list[str]:
    """Ask ERPNext for all known FrothIQ tenants."""
    url = f"{_FRAPPE_BASE}/api/method/frothiq_frappe.frothiq_billing_bridge.subscription_state_api.get_all_tenant_ids"
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(url, headers=_build_headers())
            resp.raise_for_status()
            body = resp.json()
            return body.get("message") or []
    except Exception as exc:
        logger.warning("_discover_tenants: failed: %s", exc)
        return []


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

async def _apply_and_persist(
    tenant_id: str, raw: dict[str, Any], source: str
) -> dict[str, Any]:
    """Apply state machine rules to *raw* data then persist."""
    # Get current state from cache/DB
    current_data = await get_billing_state(tenant_id)
    current_state = SubscriptionState(
        current_data["subscription_status"]
        if current_data
        else "active"
    )
    current_version = int(current_data["state_version"]) if current_data else 0

    proposed_status = raw.get("subscription_status", raw.get("status", "active"))
    proposed_state = erpnext_status_to_state(proposed_status)

    new_state, new_version, log_msg = apply_event(
        current_state, current_version, proposed_state, source
    )
    logger.info("billing sync [%s]: %s", tenant_id, log_msg)

    merged: dict[str, Any] = {
        **raw,
        "tenant_id": tenant_id,
        "subscription_status": new_state.value,
        "state_version": new_version,
        "source": source,
    }
    return await _persist(tenant_id, merged, source)


async def _persist(
    tenant_id: str, data: dict[str, Any], source: str
) -> dict[str, Any]:
    return await set_billing_state(
        tenant_id=tenant_id,
        subscription_status=data.get("subscription_status", "active"),
        plan=data.get("plan", "free"),
        effective_plan=data.get("effective_plan", data.get("plan", "free")),
        enforcement_mode=data.get("enforcement_mode", "alert_only"),
        features=data.get("features") or {},
        limits=data.get("limits") or {},
        state_version=data.get("state_version", 0),
        source=source,
        stripe_customer_id=data.get("stripe_customer_id"),
        erpnext_customer=data.get("erpnext_customer"),
        erpnext_subscription=data.get("erpnext_subscription"),
        expiry=data.get("expiry"),
        grace_until=data.get("grace_until"),
    )
