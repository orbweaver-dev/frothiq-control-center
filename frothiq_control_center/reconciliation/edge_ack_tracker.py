"""
Edge ACK Tracker.

Tracks whether each edge plugin has acknowledged the latest FederationContract
that MC3 pushed to it.  An unacknowledged push is retried up to MAX_RETRIES
times with exponential backoff.

ACK payload format (from edge → MC3):
{
    "tenant_id":        "<tenant>",
    "edge_id":          "<edge_id>",
    "contract_version": <int>,
    "received_at":      <unix_float>,
    "signature":        "<hmac_hex>"  -- optional; validated when present
}

Edge state transitions:
  pending → synced          (ACK received, version matches)
  pending → retrying        (push timeout, retry scheduled)
  retrying → synced         (ACK received on retry)
  retrying → failed         (MAX_RETRIES exceeded)
  any → offline             (edge not reachable after MAX_RETRIES)
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import time
from typing import Any

from sqlalchemy import select
from sqlalchemy.dialects.mysql import insert as mysql_insert

from frothiq_control_center.integrations.database import get_session_factory
from frothiq_control_center.models.reconciliation import EdgeAckRecord
from frothiq_control_center.models.user import _utcnow

logger = logging.getLogger(__name__)

MAX_RETRIES       = 5
ACK_TIMEOUT_SEC   = 30    # seconds to wait for ACK before marking as retrying
OFFLINE_THRESHOLD = 3     # consecutive failures before marking edge as offline


# ---------------------------------------------------------------------------
# Record an incoming ACK from an edge plugin
# ---------------------------------------------------------------------------

async def record_ack(
    tenant_id:        str,
    edge_id:          str,
    contract_version: int,
    received_at:      float,
    signature:        str | None = None,
    signing_secret:   str | None = None,
) -> dict[str, Any]:
    """
    Process an ACK from an edge plugin.

    If *signing_secret* is provided, the signature is validated.
    Returns the updated ACK record as a dict.
    """
    # Optional signature validation
    if signing_secret and signature:
        _verify_ack_signature(tenant_id, edge_id, contract_version, received_at, signature, signing_secret)

    # Calculate latency from when we pushed
    existing = await _get_record(tenant_id, edge_id)
    pushed_at = existing.get("last_pushed_at_ts") if existing else None
    latency_ms: float | None = None
    if pushed_at:
        latency_ms = (received_at - pushed_at) * 1000

    await _upsert(
        tenant_id=tenant_id,
        edge_id=edge_id,
        last_ack_version=contract_version,
        last_ack_at=_utcnow(),
        ack_latency_ms=latency_ms,
        status="synced",
        retry_count=0,           # reset on successful ACK
    )

    from frothiq_control_center.reconciliation.reconciliation_audit_log import log_edge_ack
    await log_edge_ack(
        tenant_id=tenant_id,
        edge_id=edge_id,
        contract_version=contract_version,
        latency_ms=latency_ms or 0.0,
    )

    logger.info(
        "edge_ack: tenant=%s edge=%s version=%d latency=%.1fms",
        tenant_id, edge_id, contract_version, latency_ms or 0,
    )
    return await get_ack_status(tenant_id, edge_id)


# ---------------------------------------------------------------------------
# Record a push attempt (called by reconciliation_engine before pushing)
# ---------------------------------------------------------------------------

async def record_push(
    tenant_id:        str,
    edge_id:          str,
    pushed_version:   int,
) -> None:
    """Record that we pushed a FederationContract to an edge node."""
    await _upsert(
        tenant_id=tenant_id,
        edge_id=edge_id,
        last_pushed_version=pushed_version,
        last_pushed_at=_utcnow(),
        status="pending",
        increment_push=True,
    )


# ---------------------------------------------------------------------------
# Mark a push as failed / retrying
# ---------------------------------------------------------------------------

async def record_push_failure(
    tenant_id: str,
    edge_id:   str,
) -> dict[str, Any]:
    """
    Increment retry_count. Transition to 'failed' or 'offline' when
    MAX_RETRIES is exceeded.
    """
    existing = await _get_record(tenant_id, edge_id)
    retry_count = int((existing or {}).get("retry_count") or 0) + 1
    status = (
        "offline"  if retry_count >= MAX_RETRIES
        else "retrying"
    )
    await _upsert(
        tenant_id=tenant_id,
        edge_id=edge_id,
        retry_count=retry_count,
        status=status,
    )
    return await get_ack_status(tenant_id, edge_id)


# ---------------------------------------------------------------------------
# Query helpers
# ---------------------------------------------------------------------------

async def get_ack_status(tenant_id: str, edge_id: str) -> dict[str, Any]:
    """Return the current ACK record for (tenant_id, edge_id)."""
    record = await _get_record(tenant_id, edge_id)
    if not record:
        return {
            "tenant_id": tenant_id,
            "edge_id":   edge_id,
            "status":    "unknown",
            "last_ack_version": 0,
            "last_pushed_version": 0,
            "in_sync":   False,
        }
    in_sync = (record["last_ack_version"] >= record["last_pushed_version"]
               and record["status"] == "synced")
    return {**record, "in_sync": in_sync}


async def get_tenant_ack_status(tenant_id: str) -> list[dict[str, Any]]:
    """Return all edge ACK records for a tenant."""
    try:
        async with get_session_factory()() as session:
            result = await session.execute(
                select(EdgeAckRecord).where(
                    EdgeAckRecord.tenant_id == tenant_id
                )
            )
            rows = result.scalars().all()
        return [_record_to_dict(r) for r in rows]
    except Exception as exc:
        logger.error("get_tenant_ack_status failed: %s", exc)
        return []


async def get_pending_acks(timeout_sec: float = ACK_TIMEOUT_SEC) -> list[dict[str, Any]]:
    """
    Return edge records that are in 'pending' state and have exceeded
    *timeout_sec* since the last push — ready for retry.
    """
    from datetime import timedelta
    cutoff = _utcnow() - timedelta(seconds=timeout_sec)
    try:
        async with get_session_factory()() as session:
            result = await session.execute(
                select(EdgeAckRecord).where(
                    EdgeAckRecord.status.in_(["pending", "retrying"]),
                    EdgeAckRecord.last_pushed_at <= cutoff,
                    EdgeAckRecord.retry_count < MAX_RETRIES,
                )
            )
            rows = result.scalars().all()
        return [_record_to_dict(r) for r in rows]
    except Exception as exc:
        logger.error("get_pending_acks failed: %s", exc)
        return []


# ---------------------------------------------------------------------------
# Signature validation
# ---------------------------------------------------------------------------

def _verify_ack_signature(
    tenant_id: str,
    edge_id: str,
    contract_version: int,
    received_at: float,
    signature: str,
    secret: str,
) -> None:
    """
    Verify the HMAC-SHA256 signature on an edge ACK.

    Signed payload: "{tenant_id}:{edge_id}:{contract_version}:{received_at_int}"
    """
    payload = f"{tenant_id}:{edge_id}:{contract_version}:{int(received_at)}"
    expected = hmac.new(
        secret.encode("utf-8"),
        payload.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(expected, signature):
        raise ValueError(f"edge ACK signature mismatch for edge={edge_id!r}")


# ---------------------------------------------------------------------------
# Internal DB helpers
# ---------------------------------------------------------------------------

async def _get_record(tenant_id: str, edge_id: str) -> dict[str, Any] | None:
    try:
        async with get_session_factory()() as session:
            result = await session.execute(
                select(EdgeAckRecord).where(
                    EdgeAckRecord.tenant_id == tenant_id,
                    EdgeAckRecord.edge_id == edge_id,
                )
            )
            row = result.scalar_one_or_none()
        return _record_to_dict(row) if row else None
    except Exception as exc:
        logger.error("_get_record failed: %s", exc)
        return None


async def _upsert(tenant_id: str, edge_id: str, **fields) -> None:
    """INSERT … ON DUPLICATE KEY UPDATE for (tenant_id, edge_id)."""
    import uuid
    try:
        base_values = {
            "id":        str(uuid.uuid4()),
            "tenant_id": tenant_id,
            "edge_id":   edge_id,
            "status":    "pending",
        }
        increment_push = fields.pop("increment_push", False)
        base_values.update({k: v for k, v in fields.items() if v is not None})

        stmt = mysql_insert(EdgeAckRecord).values(**base_values)

        update_dict = {k: stmt.inserted[k] for k in fields if k in EdgeAckRecord.__table__.c}
        if increment_push:
            update_dict["push_count"] = EdgeAckRecord.push_count + 1

        if update_dict:
            stmt = stmt.on_duplicate_key_update(**update_dict)

        async with get_session_factory()() as session:
            await session.execute(stmt)
            await session.commit()
    except Exception as exc:
        logger.error("_upsert EdgeAckRecord failed: %s", exc)


def _record_to_dict(r: EdgeAckRecord) -> dict[str, Any]:
    return {
        "tenant_id":           r.tenant_id,
        "edge_id":             r.edge_id,
        "status":              r.status,
        "last_ack_version":    r.last_ack_version,
        "last_pushed_version": r.last_pushed_version,
        "ack_latency_ms":      r.ack_latency_ms,
        "retry_count":         r.retry_count,
        "push_count":          r.push_count,
        "last_pushed_at":      r.last_pushed_at.isoformat() if r.last_pushed_at else None,
        "last_ack_at":         r.last_ack_at.isoformat() if r.last_ack_at else None,
        "last_pushed_at_ts":   r.last_pushed_at.timestamp() if r.last_pushed_at else None,
        "updated_at":          r.updated_at.isoformat() if r.updated_at else None,
    }
