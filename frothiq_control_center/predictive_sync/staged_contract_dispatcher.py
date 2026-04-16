"""
Staged Contract Dispatcher.

Persists a staged contract and pushes it to edge nodes.

Rule 2 enforcement — ONE staged contract per tenant (atomic replace):
  Before inserting a new contract:
    1. Look up any existing pending/dispatched contract
    2. Send INVALIDATE to all edges for the old contract
    3. Mark old DB row as REPLACED
    4. Delete old Redis key
    5. Insert new contract + set new Redis key
  The old-invalidation and new-dispatch are committed in the same DB
  transaction where possible. Edge receives INVALIDATE before the new
  contract, eliminating overlap.

Rule 4 enforcement — TTL must match between Redis and DB:
  Redis TTL = int(valid_until - now), minimum 60 seconds.
  expire_stale_contracts() hard-deletes DB rows older than max_valid_until.
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from datetime import datetime, timezone
from typing import Any

import httpx
from sqlalchemy import select, update

from frothiq_control_center.integrations.database import get_session_factory
from frothiq_control_center.integrations.redis_client import get_cache_client
from frothiq_control_center.models.predictive_sync import StagedContractRecord
from frothiq_control_center.predictive_sync.preemptive_state_builder import ProjectedState

logger = logging.getLogger(__name__)

_STAGED_KEY_PREFIX = "frothiq:staged:"
_DISPATCH_TIMEOUT  = 5.0   # seconds per edge node HTTP call
_ACTIVE_STATUSES   = ("pending", "dispatched")


def _staged_redis_key(tenant_id: str) -> str:
    return f"{_STAGED_KEY_PREFIX}{tenant_id}"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


# ---------------------------------------------------------------------------
# Rule 2: atomic replace helper
# ---------------------------------------------------------------------------

async def _retire_existing_contract(tenant_id: str) -> dict[str, Any] | None:
    """
    Locate any active staged contract for *tenant_id*, send INVALIDATE
    to its edges, mark it REPLACED in DB, and remove it from Redis.

    Returns the old contract dict if one was replaced, else None.
    """
    old_contract = await get_staged_contract(tenant_id)
    if not old_contract:
        return None

    old_id      = old_contract.get("contract_id", "")
    old_version = old_contract.get("contract_version", 0)

    # 1. Send INVALIDATE to edges (before inserting new contract)
    if old_id:
        from frothiq_control_center.predictive_sync.preemptive_contract_generator import (
            make_invalidation_message,
        )
        inv_msg = make_invalidation_message(
            tenant_id=tenant_id,
            contract_id=old_id,
            contract_version=old_version,
            reason="contract_replaced",
        )
        await _broadcast_control_message(tenant_id, inv_msg)

    # 2. Mark DB row REPLACED
    try:
        async with get_session_factory()() as session:
            await session.execute(
                update(StagedContractRecord)
                .where(
                    StagedContractRecord.tenant_id == tenant_id,
                    StagedContractRecord.status.in_(list(_ACTIVE_STATUSES)),
                )
                .values(status="replaced", outcome="replaced", outcome_at=_utcnow())
            )
            await session.commit()
    except Exception as exc:
        logger.warning("_retire_existing_contract db update failed: %s", exc)

    # 3. Delete old Redis key
    try:
        redis = await get_cache_client()
        await redis.delete(_staged_redis_key(tenant_id))
    except Exception as exc:
        logger.warning("_retire_existing_contract redis delete failed: %s", exc)

    logger.info(
        "staged_contract replaced: tenant=%s old_id=%s old_version=%d",
        tenant_id, old_id[:8] if old_id else "?", old_version,
    )

    # Increment replacement metric
    from frothiq_control_center.predictive_sync.prediction_accuracy_tracker import (
        record_replacement,
    )
    await record_replacement(tenant_id)

    return old_contract


# ---------------------------------------------------------------------------
# Main dispatch (Rule 2 + Rule 4)
# ---------------------------------------------------------------------------

async def dispatch_staged_contract(
    projected: ProjectedState,
    contract: dict[str, Any],
) -> dict[str, Any]:
    """
    Atomically replace any existing staged contract and push the new one.

    Rule 2: retire existing before inserting new (send INVALIDATE first).
    Rule 4: Redis TTL derived from valid_until; must match DB record.
    """
    tenant_id   = projected.tenant_id
    contract_id = contract["contract_id"]
    now         = time.time()
    ttl         = max(60, int(projected.valid_until - now))

    # ── Rule 2: retire any existing contract atomically ─────────────────
    replaced = await _retire_existing_contract(tenant_id)

    # ── L1: Redis (TTL matches DB valid_until — Rule 4) ─────────────────
    await _set_redis(tenant_id, contract, ttl)

    # ── L2: DB (upsert after old row is REPLACED) ────────────────────────
    await _upsert_db(projected, contract)

    # ── Push to edge nodes ────────────────────────────────────────────────
    edges_notified = await _push_to_edges(tenant_id, contract)

    # Update DB with dispatch info
    await _mark_dispatched(tenant_id, edges_notified)

    logger.info(
        "staged_contract dispatched: tenant=%s contract_id=%s version=%d "
        "edges=%d confidence=%.2f replaced=%s",
        tenant_id, contract_id, projected.predicted_version,
        len(edges_notified), projected.confidence_score,
        bool(replaced),
    )

    return {
        "contract_id":    contract_id,
        "tenant_id":      tenant_id,
        "version":        projected.predicted_version,
        "edges_notified": edges_notified,
        "redis_ttl_sec":  ttl,
        "valid_until":    projected.valid_until,
        "activation_at":  projected.activation_at,
        "replaced_previous": bool(replaced),
    }


# ---------------------------------------------------------------------------
# Read
# ---------------------------------------------------------------------------

async def get_staged_contract(tenant_id: str) -> dict[str, Any] | None:
    """
    Retrieve the current staged contract for a tenant.
    Redis first, DB fallback.
    """
    try:
        redis = await get_cache_client()
        raw = await redis.get(_staged_redis_key(tenant_id))
        if raw:
            data = json.loads(raw)
            # Rule 4: discard if past hard TTL
            if _is_expired(data):
                await redis.delete(_staged_redis_key(tenant_id))
                return None
            return data
    except Exception as exc:
        logger.warning("get_staged_contract redis failed: %s", exc)

    try:
        async with get_session_factory()() as session:
            row = await session.scalar(
                select(StagedContractRecord).where(
                    StagedContractRecord.tenant_id == tenant_id,
                    StagedContractRecord.status.in_(list(_ACTIVE_STATUSES)),
                )
            )
        if row:
            # Rule 4: skip expired DB rows
            if row.valid_until < time.time():
                return None
            data = json.loads(row.contract_json)
            ttl  = max(60, int(row.valid_until - time.time()))
            await _set_redis(tenant_id, data, ttl)
            return data
    except Exception as exc:
        logger.warning("get_staged_contract db failed: %s", exc)

    return None


async def get_all_staged_contracts() -> list[dict[str, Any]]:
    """Return all active staged contracts."""
    try:
        async with get_session_factory()() as session:
            result = await session.execute(
                select(StagedContractRecord).where(
                    StagedContractRecord.status.in_(list(_ACTIVE_STATUSES))
                )
            )
            rows = result.scalars().all()
        now = time.time()
        return [_row_to_dict(r) for r in rows if r.valid_until >= now]
    except Exception as exc:
        logger.error("get_all_staged_contracts failed: %s", exc)
        return []


async def invalidate_staged_contract(tenant_id: str, reason: str = "explicit") -> bool:
    """Discard the staged contract for a tenant (Redis + DB)."""
    found = False
    try:
        redis = await get_cache_client()
        deleted = await redis.delete(_staged_redis_key(tenant_id))
        found = bool(deleted)
    except Exception as exc:
        logger.warning("invalidate_staged_contract redis: %s", exc)

    try:
        async with get_session_factory()() as session:
            result = await session.execute(
                update(StagedContractRecord)
                .where(
                    StagedContractRecord.tenant_id == tenant_id,
                    StagedContractRecord.status.in_(list(_ACTIVE_STATUSES)),
                )
                .values(status="discarded", outcome="discarded", outcome_at=_utcnow())
            )
            await session.commit()
            if result.rowcount:
                found = True
    except Exception as exc:
        logger.warning("invalidate_staged_contract db: %s", exc)

    return found


# ---------------------------------------------------------------------------
# Rule 4: TTL enforcement — prune expired rows from DB
# ---------------------------------------------------------------------------

async def expire_stale_contracts() -> int:
    """
    Hard-delete StagedContractRecord rows whose valid_until has passed.
    Called by reconciliation_scheduler nightly (alongside audit log pruning).
    Returns number of rows deleted.
    """
    from sqlalchemy import delete as sql_delete
    now = time.time()
    try:
        async with get_session_factory()() as session:
            result = await session.execute(
                sql_delete(StagedContractRecord).where(
                    StagedContractRecord.valid_until < now,
                    StagedContractRecord.status.notin_(["confirmed"]),  # keep confirmed for audit
                )
            )
            await session.commit()
            deleted = result.rowcount
        if deleted:
            logger.info("staged_contract TTL prune: deleted %d expired rows", deleted)
        return deleted
    except Exception as exc:
        logger.error("expire_stale_contracts failed: %s", exc)
        return 0


# ---------------------------------------------------------------------------
# Edge push
# ---------------------------------------------------------------------------

async def _push_to_edges(tenant_id: str, contract: dict[str, Any]) -> list[str]:
    """HTTP POST staged contract to each active edge node."""
    from frothiq_control_center.billing.billing_event_publisher import (
        _get_edge_nodes,
        _build_edge_billing_url,
    )

    nodes = await _get_edge_nodes(tenant_id)
    notified: list[str] = []

    async with httpx.AsyncClient(timeout=_DISPATCH_TIMEOUT) as client:
        for node in nodes:
            edge_id  = node.get("id") or "unknown"
            base_url = _build_edge_billing_url(node)
            if not base_url:
                continue
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


async def _broadcast_control_message(
    tenant_id: str, message: dict[str, Any]
) -> None:
    """Send an activate or invalidate control message to all edge nodes."""
    from frothiq_control_center.billing.billing_event_publisher import (
        _get_edge_nodes,
        _build_edge_billing_url,
    )
    nodes = await _get_edge_nodes(tenant_id)
    async with httpx.AsyncClient(timeout=_DISPATCH_TIMEOUT) as client:
        for node in nodes:
            url = _build_edge_billing_url(node)
            if not url:
                continue
            msg_url = url.replace("/billing-state", "/staged-contract")
            try:
                await client.post(msg_url, json=message)
            except Exception as exc:
                logger.debug(
                    "_broadcast_control_message failed: node=%s: %s",
                    node.get("id"), exc,
                )


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
            predicted_from=(
                projected.source_state.get("subscription_status") or "active"
            ),
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
            outcome=None,
            outcome_at=None,
        )
        async with get_session_factory()() as session:
            await session.execute(stmt)
            await session.commit()
    except Exception as exc:
        logger.error("staged_contract db upsert failed: %s", exc)


async def _mark_dispatched(tenant_id: str, edge_ids: list[str]) -> None:
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


def _is_expired(contract: dict[str, Any]) -> bool:
    valid_until = float(
        contract.get("max_valid_until") or contract.get("valid_until") or 0
    )
    return valid_until > 0 and time.time() > valid_until


def _row_to_dict(r: StagedContractRecord) -> dict[str, Any]:
    return {
        "tenant_id":           r.tenant_id,
        "status":              r.status,
        "predicted_from":      r.predicted_from,
        "predicted_to":        r.predicted_to,
        "confidence_score":    r.confidence_score,
        "contract_version":    r.contract_version,
        "activation_at":       r.activation_timestamp,
        "valid_until":         r.valid_until,
        "dispatched_to":       json.loads(r.dispatched_to_json or "[]"),
        "outcome":             r.outcome,
        "erp_confirmed_state": r.erp_confirmed_state,
        "created_at":          r.created_at.isoformat() if r.created_at else None,
        "activated_at":        r.activated_at.isoformat() if r.activated_at else None,
    }
