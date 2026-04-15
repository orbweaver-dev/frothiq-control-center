"""
License State Cache — two-tier persistence.

Layer 1: Redis  (TTL=300s, key frothiq:billing:{tenant_id})
Layer 2: MariaDB via SQLAlchemy async (durable fallback)

Writes always go to both layers so that a Redis flush or restart
does not create a billing data gap.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.dialects.mysql import insert as mysql_insert

from frothiq_control_center.integrations.database import get_session_factory
from frothiq_control_center.integrations.redis_client import get_cache_client
from frothiq_control_center.models.billing import TenantBillingState

logger = logging.getLogger(__name__)

_CACHE_TTL = 300          # seconds
_KEY_PREFIX = "frothiq:billing:"


def _cache_key(tenant_id: str) -> str:
    return f"{_KEY_PREFIX}{tenant_id}"


def _state_to_dict(state: TenantBillingState) -> dict[str, Any]:
    """Serialise a DB row to the wire format expected by edge plugins and the UI."""
    return {
        "tenant_id":            state.tenant_id,
        "subscription_status":  state.subscription_status,
        "plan":                 state.plan,
        "effective_plan":       state.effective_plan,
        "enforcement_mode":     state.enforcement_mode,
        "stripe_customer_id":   state.stripe_customer_id,
        "erpnext_customer":     state.erpnext_customer,
        "erpnext_subscription": state.erpnext_subscription,
        "expiry":               state.expiry,
        "grace_until":          state.grace_until,
        "features":             json.loads(state.features_json or "{}"),
        "limits":               json.loads(state.limits_json or "{}"),
        "state_version":        state.state_version,
        "last_updated":         state.last_updated,
        "source":               state.source,
    }


# ---------------------------------------------------------------------------
# Read
# ---------------------------------------------------------------------------

async def get_billing_state(tenant_id: str) -> dict[str, Any] | None:
    """
    Return the billing state for *tenant_id*, checking Redis first.
    Falls back to DB if Redis misses or is unavailable.
    Returns None if the tenant is completely unknown.
    """
    # --- L1: Redis ---
    try:
        redis = await get_cache_client()
        raw = await redis.get(_cache_key(tenant_id))
        if raw:
            data = json.loads(raw)
            data["source"] = "cache"
            return data
    except Exception as exc:
        logger.warning("Redis read failed for %s: %s", tenant_id, exc)

    # --- L2: DB ---
    try:
        async with get_session_factory()() as session:
            row = await session.scalar(
                select(TenantBillingState).where(
                    TenantBillingState.tenant_id == tenant_id
                )
            )
        if row:
            data = _state_to_dict(row)
            data["source"] = "db"
            # Repopulate Redis so next read is fast
            await _set_redis(tenant_id, data)
            return data
    except Exception as exc:
        logger.error("DB read failed for %s: %s", tenant_id, exc)

    return None


async def get_all_billing_states() -> list[dict[str, Any]]:
    """Return all persisted billing states (DB read, no Redis)."""
    try:
        async with get_session_factory()() as session:
            result = await session.execute(select(TenantBillingState))
            rows = result.scalars().all()
        return [_state_to_dict(r) for r in rows]
    except Exception as exc:
        logger.error("DB read all failed: %s", exc)
        return []


# ---------------------------------------------------------------------------
# Write
# ---------------------------------------------------------------------------

async def set_billing_state(
    tenant_id: str,
    subscription_status: str,
    plan: str,
    effective_plan: str,
    enforcement_mode: str,
    features: dict,
    limits: dict,
    state_version: int,
    source: str,
    stripe_customer_id: str | None = None,
    erpnext_customer: str | None = None,
    erpnext_subscription: str | None = None,
    expiry: float | None = None,
    grace_until: float | None = None,
) -> dict[str, Any]:
    """
    Upsert billing state for *tenant_id* into Redis + DB.
    Returns the dict representation of the saved state.
    """
    now = time.time()
    data: dict[str, Any] = {
        "tenant_id":            tenant_id,
        "subscription_status":  subscription_status,
        "plan":                 plan,
        "effective_plan":       effective_plan,
        "enforcement_mode":     enforcement_mode,
        "features":             features,
        "limits":               limits,
        "state_version":        state_version,
        "last_updated":         now,
        "source":               source,
        "stripe_customer_id":   stripe_customer_id,
        "erpnext_customer":     erpnext_customer,
        "erpnext_subscription": erpnext_subscription,
        "expiry":               expiry,
        "grace_until":          grace_until,
    }

    # --- L1: Redis ---
    await _set_redis(tenant_id, data)

    # --- L2: DB ---
    await _upsert_db(data)

    return data


async def invalidate_cache(tenant_id: str | None = None) -> int:
    """
    Invalidate Redis cache for one tenant or all tenants.
    Returns the number of keys deleted.
    """
    try:
        redis = await get_cache_client()
        if tenant_id:
            deleted = await redis.delete(_cache_key(tenant_id))
            return deleted
        else:
            # Scan for all billing keys
            keys = []
            async for key in redis.scan_iter(match=f"{_KEY_PREFIX}*"):
                keys.append(key)
            if keys:
                return await redis.delete(*keys)
            return 0
    except Exception as exc:
        logger.warning("Cache invalidation failed: %s", exc)
        return 0


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

async def _set_redis(tenant_id: str, data: dict[str, Any]) -> None:
    try:
        redis = await get_cache_client()
        await redis.setex(_cache_key(tenant_id), _CACHE_TTL, json.dumps(data))
    except Exception as exc:
        logger.warning("Redis write failed for %s: %s", tenant_id, exc)


async def _upsert_db(data: dict[str, Any]) -> None:
    """INSERT … ON DUPLICATE KEY UPDATE for MariaDB."""
    try:
        insert_stmt = mysql_insert(TenantBillingState).values(
            tenant_id=data["tenant_id"],
            subscription_status=data["subscription_status"],
            plan=data["plan"],
            effective_plan=data["effective_plan"],
            enforcement_mode=data["enforcement_mode"],
            features_json=json.dumps(data["features"]),
            limits_json=json.dumps(data["limits"]),
            state_version=data["state_version"],
            last_updated=data["last_updated"],
            source=data["source"],
            stripe_customer_id=data.get("stripe_customer_id"),
            erpnext_customer=data.get("erpnext_customer"),
            erpnext_subscription=data.get("erpnext_subscription"),
            expiry=data.get("expiry"),
            grace_until=data.get("grace_until"),
        )
        update_stmt = insert_stmt.on_duplicate_key_update(
            subscription_status=insert_stmt.inserted.subscription_status,
            plan=insert_stmt.inserted.plan,
            effective_plan=insert_stmt.inserted.effective_plan,
            enforcement_mode=insert_stmt.inserted.enforcement_mode,
            features_json=insert_stmt.inserted.features_json,
            limits_json=insert_stmt.inserted.limits_json,
            state_version=insert_stmt.inserted.state_version,
            last_updated=insert_stmt.inserted.last_updated,
            source=insert_stmt.inserted.source,
            stripe_customer_id=insert_stmt.inserted.stripe_customer_id,
            erpnext_customer=insert_stmt.inserted.erpnext_customer,
            erpnext_subscription=insert_stmt.inserted.erpnext_subscription,
            expiry=insert_stmt.inserted.expiry,
            grace_until=insert_stmt.inserted.grace_until,
            updated_at=insert_stmt.inserted.updated_at,
        )
        async with get_session_factory()() as session:
            await session.execute(update_stmt)
            await session.commit()
    except Exception as exc:
        logger.error("DB upsert failed for %s: %s", data.get("tenant_id"), exc)
