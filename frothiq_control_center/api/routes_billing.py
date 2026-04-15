"""
Billing Sync API Routes.

Endpoints:
  POST /api/v1/cc/billing/webhook/subscription   — receive ERPNext billing events
  GET  /api/v1/cc/billing/state/{tenant_id}      — current billing state for a tenant
  POST /api/v1/cc/billing/sync/{tenant_id}       — force-pull state from ERPNext
  GET  /api/v1/cc/billing/sync/pull-all          — force-pull all tenants (admin)
  GET  /api/v1/cc/billing/drift-report           — compare cache vs ERPNext for all tenants
  GET  /api/v1/cc/billing/sync-health            — health of webhook + pull channels

Architecture rules enforced here:
  - No Stripe calls
  - No billing mutations (read + sync only)
  - ERPNext is sole source of truth; MC3 only caches state
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from frothiq_control_center.auth import (
    require_billing_admin,
    require_read_only,
    require_super_admin,
)
from frothiq_control_center.billing.billing_event_publisher import publish_billing_update
from frothiq_control_center.billing.billing_sync_client import (
    pull_all_tenants,
    pull_tenant_state,
)
from frothiq_control_center.billing.billing_sync_webhook import (
    WebhookValidationError,
    process_webhook,
)
from frothiq_control_center.billing.license_state_cache import (
    get_all_billing_states,
    get_billing_state,
    invalidate_cache,
)
from frothiq_control_center.config import get_settings

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/billing", tags=["Billing Sync"])


# ---------------------------------------------------------------------------
# Webhook receiver
# ---------------------------------------------------------------------------

@router.post("/webhook/subscription", status_code=200)
async def webhook_subscription(
    request: Request,
    x_frothiq_signature: Annotated[str | None, Header(alias="X-FrothIQ-Signature")] = None,
) -> dict[str, Any]:
    """
    Receive a subscription lifecycle event from ERPNext.

    Validates HMAC-SHA256 signature, deduplicates by event_id,
    applies state machine rules, and persists the updated state.
    """
    settings = get_settings()
    secret = getattr(settings, "billing_webhook_secret", "")

    if not secret:
        logger.error("billing webhook: CC_BILLING_WEBHOOK_SECRET not configured")
        raise HTTPException(status_code=500, detail="Webhook endpoint not configured")

    raw_body = await request.body()

    try:
        result = await process_webhook(
            raw_body=raw_body,
            signature_header=x_frothiq_signature or "",
            webhook_secret=secret,
        )
    except WebhookValidationError as exc:
        logger.warning("billing webhook validation failed: %s", exc)
        raise HTTPException(status_code=400, detail=str(exc))

    # Publish update to WS + edge nodes (best-effort, don't block response)
    if result.get("action") == "processed":
        tenant_id = result["tenant_id"]
        state = await get_billing_state(tenant_id)
        if state:
            try:
                await publish_billing_update(
                    tenant_id, state, "billing.webhook_received"
                )
            except Exception as exc:
                logger.warning("billing event publish failed: %s", exc)

            # Fire predictive confirmation listener as a background task.
            # It checks whether any staged (pre-predicted) contract matches
            # the confirmed state and activates or invalidates it on edges.
            try:
                from frothiq_control_center.predictive_sync.confirmation_listener import (
                    on_billing_confirmed,
                )
                asyncio.create_task(
                    on_billing_confirmed(tenant_id, state),
                    name=f"confirm_prediction_{tenant_id}",
                )
            except Exception as exc:
                logger.debug("confirmation_listener fire failed: %s", exc)

    return result


# ---------------------------------------------------------------------------
# State query
# ---------------------------------------------------------------------------

@router.get("/state/{tenant_id}")
async def get_tenant_billing_state(
    tenant_id: str,
    _user: Any = Depends(require_read_only),
) -> dict[str, Any]:
    """Return the cached billing state for a tenant."""
    state = await get_billing_state(tenant_id)
    if state is None:
        raise HTTPException(
            status_code=404,
            detail=f"No billing state found for tenant {tenant_id!r}. "
                   "Run a sync to populate.",
        )
    return state


@router.get("/state")
async def list_all_billing_states(
    _user: Any = Depends(require_billing_admin),
) -> dict[str, Any]:
    """Return billing states for all tenants."""
    states = await get_all_billing_states()
    return {
        "total":   len(states),
        "tenants": states,
    }


# ---------------------------------------------------------------------------
# Force sync
# ---------------------------------------------------------------------------

@router.post("/sync/{tenant_id}")
async def force_sync_tenant(
    tenant_id: str,
    _user: Any = Depends(require_billing_admin),
) -> dict[str, Any]:
    """Force-pull the latest subscription state for *tenant_id* from ERPNext."""
    state = await pull_tenant_state(tenant_id)
    # Publish update
    try:
        await publish_billing_update(tenant_id, state, "billing.admin_sync")
    except Exception:
        pass
    return {"status": "synced", "tenant_id": tenant_id, "state": state}


@router.post("/sync/pull-all")
async def force_sync_all(
    _user: Any = Depends(require_super_admin),
) -> dict[str, Any]:
    """Force-pull billing state for all known tenants from ERPNext (admin only)."""
    result = await pull_all_tenants()
    return {"status": "ok", **result}


# ---------------------------------------------------------------------------
# Cache invalidation
# ---------------------------------------------------------------------------

class InvalidateCacheRequest(BaseModel):
    tenant_id: str | None = None


@router.post("/invalidate-cache")
async def invalidate_billing_cache(
    body: InvalidateCacheRequest,
    _user: Any = Depends(require_super_admin),
) -> dict[str, Any]:
    """
    Invalidate Redis billing cache for one tenant or all tenants.
    Next read will fall back to DB then re-populate Redis.
    """
    deleted = await invalidate_cache(body.tenant_id)
    scope = body.tenant_id or "all"
    return {"status": "ok", "scope": scope, "keys_deleted": deleted}


# ---------------------------------------------------------------------------
# Drift report
# ---------------------------------------------------------------------------

@router.get("/drift-report")
async def billing_drift_report(
    _user: Any = Depends(require_billing_admin),
) -> dict[str, Any]:
    """
    Compare cached billing state vs a fresh ERPNext pull for each tenant.
    Returns tenants whose cached state differs from ERPNext.

    This is a read-heavy operation — use sparingly in production.
    """
    cached_states = await get_all_billing_states()
    drifted = []
    in_sync = []

    for cached in cached_states:
        tenant_id = cached["tenant_id"]
        try:
            fresh = await pull_tenant_state(tenant_id)
            # Drift = different subscription_status or plan after state machine
            if (
                fresh.get("subscription_status") != cached.get("subscription_status")
                or fresh.get("effective_plan") != cached.get("effective_plan")
            ):
                drifted.append({
                    "tenant_id": tenant_id,
                    "cached":    {"status": cached.get("subscription_status"), "plan": cached.get("effective_plan")},
                    "fresh":     {"status": fresh.get("subscription_status"),  "plan": fresh.get("effective_plan")},
                })
            else:
                in_sync.append(tenant_id)
        except Exception as exc:
            drifted.append({
                "tenant_id": tenant_id,
                "error":     str(exc),
            })

    return {
        "checked":    len(cached_states),
        "in_sync":    len(in_sync),
        "drifted":    len(drifted),
        "drift_list": drifted,
        "generated_at": time.time(),
    }


# ---------------------------------------------------------------------------
# Sync health
# ---------------------------------------------------------------------------

@router.get("/sync-health")
async def billing_sync_health(
    _user: Any = Depends(require_read_only),
) -> dict[str, Any]:
    """
    Return health metrics for the billing sync subsystem.
    Checks Redis connectivity and DB row count.
    """
    from frothiq_control_center.integrations.redis_client import get_cache_client

    redis_ok = False
    cache_key_count = 0
    try:
        redis = await get_cache_client()
        await redis.ping()
        redis_ok = True
        keys = [k async for k in redis.scan_iter(match="frothiq:billing:*")]
        cache_key_count = len(keys)
    except Exception as exc:
        logger.warning("billing sync-health: Redis check failed: %s", exc)

    db_ok = False
    db_tenant_count = 0
    try:
        all_states = await get_all_billing_states()
        db_ok = True
        db_tenant_count = len(all_states)
    except Exception as exc:
        logger.warning("billing sync-health: DB check failed: %s", exc)

    overall = "healthy" if redis_ok and db_ok else "degraded" if (redis_ok or db_ok) else "offline"

    return {
        "status":           overall,
        "redis_ok":         redis_ok,
        "db_ok":            db_ok,
        "cached_tenants":   cache_key_count,
        "db_tenants":       db_tenant_count,
        "checked_at":       time.time(),
    }
