"""
Staged Contract Dispatcher.

Persists a generated staged contract to:
  1. Redis (TTL = valid_until — for fast access from confirmation_listener)
  2. MariaDB StagedContractRecord (durable store)

Then pushes it to all registered edge nodes for the tenant.

Edge plugins store the staged contract locally and obey the activation rules:
  - DO NOT apply until activation_timestamp OR MC3 confirmation arrives
  - Discard immediately on invalidation message
  - Hard-discard at max_valid_until regardless

Dispatch uses the same HTTP PATCH pattern as billing_event_publisher,
but to a dedicated edge endpoint for staged contracts.
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from typing import Any

import httpx

from frothiq_control_center.integrations.database import get_session_factory
from frothiq_control_center.integrations.redis_client import get_cache_client
from frothiq_control_center.models.predictive_sync import StagedContractRecord
from frothiq_control_center.predictive_sync.preemptive_state_builder import ProjectedState

logger = logging.getLogger(__name__)

_STAGED_KEY_PREFIX = "frothiq:staged:"
_DISPATCH_TIMEOUT  = 5.0   # seconds per edge node HTTP call


def _staged_redis_key(tenant_id: str) -> str:
    return f"{_STAGED_KEY_PREFIX}{tenant_id}"


# ---------------------------------------------------------------------------
# Persist + dispatch
# ---------------------------------------------------------------------------

async def dispatch_staged_contract(
    projected: ProjectedState,
    contract: dict[str, Any],
) -> dict[str, Any]:
    """
    Persist a staged contract and push it to all registered edge nodes.

    Returns a summary dict with dispatch results.
    """
    contract_id = contract["contract_id"]
    now = time.time()
    ttl = max(60, int(projected.valid_until - now))

    # ── L1: Redis (for fast confirmation_listener lookup) ──────────────
    await _set_redis(projected.tenant_id, contract, ttl)

    # ── L2: DB ─────────────────────────────────────────────────────────
    await _upsert_db(projected, contract)

    # ── Push to edge nodes ─────────────────────────────────────────────
    edges_notified = await _push_to_edges(projected.tenant_id, contract)

    # Update DB with dispatch info
    await _mark_dispatched(projected.tenant_id, edges_notified)

    logger.info(
        "staged_contract dispatched: tenant=%s contract_id=%s version=%d edges=%d confidence=%.2f",
        projected.tenant_id, contract_id, projected.predicted_version,
        len(edges_notified), projected.confidence_score,
    )

    return {
        "contract_id":     contract_id,
        "tenant_id":       projected.tenant_id,
        "version":         projected.predicted_version,
        "edges_notified":  edges_notified,
        "redis_ttl_sec":   ttl,
        "valid_until":     projected.valid_until,
        "activation_at":   projected.activation_at,
    }


async def get_staged_contract(tenant_id: str) -> dict[str, Any] | None:
    """
    Retrieve the current staged contract for a tenant.
    Checks Redis first, falls back to DB.
    """
    # L1: Redis
    try:
        redis = await get_cache_client()
        raw = await redis.get(_staged_redis_key(tenant_id))
        if raw:
            return json.loads(raw)
    except Exception as exc:
        logger.warning("get_staged_contract redis failed: %s", exc)

    # L2: DB
    try:
        from sqlalchemy import select
        async with get_session_factory()() as session:
            row = await session.scalar(
                select(StagedContractRecord).where(
                    StagedContractRecord.tenant_id == tenant_id,
                    StagedContractRecord.status.in_(["pending", "dispatched"]),
                )
            )
        if row:
            data = json.loads(row.contract_json)
            # Repopulate Redis
            ttl = max(60, int(row.valid_until - time.time()))
            await _set_redis(tenant_id, data, ttl)
            return data
    except Exception as exc:
        logger.warning("get_staged_contract db failed: %s", exc)

    return None


async def invalidate_staged_contract(tenant_id: str, reason: str = "explicit") -> bool:
    """
    Discard the staged contract for a tenant (Redis + DB).
    Called when a prediction is confirmed wrong or on MC3 restart.
    Returns True if a contract was found and invalidated.
    """
    found = False
    try:
        redis = await get_cache_client()
        deleted = await redis.delete(_staged_redis_key(tenant_id))
        found = bool(deleted)
    except Exception as exc:
        logger.warning("invalidate_staged_contract redis: %s", exc)

    try:
        from sqlalchemy import update
        from frothiq_control_center.models.user import _utcnow
        async with get_session_factory()() as session:
            await session.execute(
                update(StagedContractRecord)
                .where(
                    StagedContractRecord.tenant_id == tenant_id,
                    StagedContractRecord.status.in_(["pending", "dispatched"]),
                )
                .values(status="discarded", outcome="discarded", outcome_at=_utcnow())
            )
            await session.commit()
            found = True
    except Exception as exc:
        logger.warning("invalidate_staged_contract db: %s", exc)

    return found


async def get_all_staged_contracts() -> list[dict[str, Any]]:
    """Return all active staged contracts (for the /staged API endpoint)."""
    try:
        from sqlalchemy import select
        async with get_session_factory()() as session:
            result = await session.execute(
                select(StagedContractRecord).where(
                    StagedContractRecord.status.in_(["pending", "dispatched"])
                )
            )
            rows = result.scalars().all()
        return [_row_to_dict(r) for r in rows]
    except Exception as exc:
        logger.error("get_all_staged_contracts failed: %s", exc)
        return []


# ---------------------------------------------------------------------------
# Edge push
# ---------------------------------------------------------------------------

async def _push_to_edges(tenant_id: str, contract: dict[str, Any]) -> list[str]:
    """
    HTTP POST staged contract to each active edge node.
    Returns list of edge_ids that accepted.
    """
    from frothiq_control_center.billing.billing_event_publisher import (
        _get_edge_nodes,
        _build_edge_billing_url,
    )

    nodes = await _get_edge_nodes(tenant_id)
    notified: list[str] = []

    if not nodes:
        return notified

    async with httpx.AsyncClient(timeout=_DISPATCH_TIMEOUT) as client:
        for node in nodes:
            edge_id  = node.get("id") or "unknown"
            base_url = _build_edge_billing_url(node)
            if not base_url:
                continue
            # Staged contracts go to a dedicated sub-path
            url = base_url.replace("/billing-state", "/staged-contract")
            try:
                resp = await client.post(url, json=contract)
                if resp.status_code < 400:
                    notified.append(edge_id)
                else:
                    logger.warning(
                        "staged dispatch HTTP %d: tenant=%s edge=%s",
                        resp.status_code, tenant_id, edge_id,
                    )
            except Exception as exc:
                logger.warning(
                    "staged dispatch failed: tenant=%s edge=%s: %s",
                    tenant_id, edge_id, exc,
                )

    return notified


# ---------------------------------------------------------------------------
# Internal DB helpers
# ---------------------------------------------------------------------------

async def _set_redis(tenant_id: str, contract: dict[str, Any], ttl: int) -> None:
    try:
        redis = await get_cache_client()
        await redis.setex(_staged_redis_key(tenant_id), ttl, json.dumps(contract))
    except Exception as exc:
        logger.warning("staged_contract redis write failed: %s", exc)


async def _upsert_db(projected: ProjectedState, contract: dict[str, Any]) -> None:
    from sqlalchemy.dialects.mysql import insert as mysql_insert
    try:
        stmt = mysql_insert(StagedContractRecord).values(
            id=str(uuid.uuid4()),
            tenant_id=projected.tenant_id,
            predicted_state_json=json.dumps(projected.as_dict()),
            contract_json=json.dumps(contract),
            confidence_score=projected.confidence_score,
            predicted_from=(projected.source_state.get("subscription_status") or "active"),
            predicted_to=projected.predicted_status,
            contract_version=projected.predicted_version,
            activation_timestamp=projected.activation_at,
            valid_until=projected.valid_until,
            status="pending",
        )
        stmt = stmt.on_duplicate_key_update(
            predicted_state_json=stmt.inserted.predicted_state_json,
            contract_json=stmt.inserted.contract_json,
            confidence_score=stmt.inserted.confidence_score,
            predicted_from=stmt.inserted.predicted_from,
            predicted_to=stmt.inserted.predicted_to,
            contract_version=stmt.inserted.contract_version,
            activation_timestamp=stmt.inserted.activation_timestamp,
            valid_until=stmt.inserted.valid_until,
            status="pending",
        )
        async with get_session_factory()() as session:
            await session.execute(stmt)
            await session.commit()
    except Exception as exc:
        logger.error("staged_contract db upsert failed: %s", exc)


async def _mark_dispatched(tenant_id: str, edge_ids: list[str]) -> None:
    from sqlalchemy import update
    from frothiq_control_center.models.user import _utcnow
    try:
        async with get_session_factory()() as session:
            await session.execute(
                update(StagedContractRecord)
                .where(StagedContractRecord.tenant_id == tenant_id)
                .values(
                    status="dispatched",
                    dispatched_to_json=json.dumps(edge_ids),
                )
            )
            await session.commit()
    except Exception as exc:
        logger.warning("_mark_dispatched failed: %s", exc)


def _row_to_dict(r: StagedContractRecord) -> dict[str, Any]:
    return {
        "tenant_id":          r.tenant_id,
        "status":             r.status,
        "predicted_from":     r.predicted_from,
        "predicted_to":       r.predicted_to,
        "confidence_score":   r.confidence_score,
        "contract_version":   r.contract_version,
        "activation_at":      r.activation_timestamp,
        "valid_until":        r.valid_until,
        "dispatched_to":      json.loads(r.dispatched_to_json or "[]"),
        "outcome":            r.outcome,
        "erp_confirmed_state": r.erp_confirmed_state,
        "created_at":         r.created_at.isoformat() if r.created_at else None,
        "activated_at":       r.activated_at.isoformat() if r.activated_at else None,
    }
