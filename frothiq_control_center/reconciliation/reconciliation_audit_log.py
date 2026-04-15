"""
Reconciliation Audit Log — append-only DB-backed audit trail.

Rules:
  - Rows are INSERT-only; never UPDATE or DELETE within retention window
  - Automated pruning removes entries older than RETENTION_DAYS (30)
  - All writes are best-effort: a logging failure must never block reconciliation

Schema lives in models/reconciliation.py → ReconciliationAuditLog
"""

from __future__ import annotations

import json
import logging
import time
from datetime import datetime, timezone, timedelta
from typing import Any

from sqlalchemy import delete, select

from frothiq_control_center.integrations.database import get_session_factory
from frothiq_control_center.models.reconciliation import ReconciliationAuditLog

logger = logging.getLogger(__name__)

RETENTION_DAYS = 30


# ---------------------------------------------------------------------------
# Write helpers
# ---------------------------------------------------------------------------

async def log_drift_detected(
    tenant_id: str,
    drift_type: str,
    severity: str,
    mc3_state: dict | None,
    erp_state: dict | None,
    edge_state: dict | None,
    detail: str = "",
) -> None:
    """Append a drift-detected event to the audit log."""
    await _insert(
        tenant_id=tenant_id,
        event_type="drift_detected",
        drift_type=drift_type,
        severity=severity,
        mc3_state=mc3_state,
        erp_state=erp_state,
        edge_state=edge_state,
        action_taken=detail,
        result=None,
    )


async def log_reconciled(
    tenant_id: str,
    drift_type: str,
    before_version: int,
    after_version: int,
    action_taken: str,
    mc3_state: dict | None = None,
    erp_state: dict | None = None,
    duration_ms: float | None = None,
) -> None:
    """Append a successful reconciliation event."""
    await _insert(
        tenant_id=tenant_id,
        event_type="reconciled",
        drift_type=drift_type,
        severity=None,
        mc3_state=mc3_state,
        erp_state=erp_state,
        edge_state=None,
        action_taken=action_taken,
        result="success",
        before_version=before_version,
        after_version=after_version,
        duration_ms=duration_ms,
        resolved_at=_utcnow(),
    )


async def log_deferred(
    tenant_id: str,
    drift_type: str,
    reason: str,
    mc3_state: dict | None = None,
) -> None:
    """Append a DEFERRED_RECONCILIATION event (ERPNext unreachable)."""
    await _insert(
        tenant_id=tenant_id,
        event_type="deferred",
        drift_type=drift_type,
        severity=None,
        mc3_state=mc3_state,
        erp_state=None,
        edge_state=None,
        action_taken=reason,
        result="deferred",
    )


async def log_edge_ack(
    tenant_id: str,
    edge_id: str,
    contract_version: int,
    latency_ms: float,
) -> None:
    """Append an edge ACK confirmation."""
    await _insert(
        tenant_id=tenant_id,
        event_type="edge_ack",
        drift_type=None,
        severity=None,
        mc3_state=None,
        erp_state=None,
        edge_state={"edge_id": edge_id, "contract_version": contract_version},
        action_taken=f"edge {edge_id!r} ACK'd contract v{contract_version}",
        result="success",
        after_version=contract_version,
        duration_ms=latency_ms,
        resolved_at=_utcnow(),
    )


async def log_error(
    tenant_id: str,
    event_type: str,
    error: str,
    drift_type: str | None = None,
) -> None:
    """Append an error event."""
    await _insert(
        tenant_id=tenant_id,
        event_type=event_type,
        drift_type=drift_type,
        severity="HIGH",
        mc3_state=None,
        erp_state=None,
        edge_state=None,
        action_taken=None,
        result="failed",
        error_detail=error,
    )


# ---------------------------------------------------------------------------
# Read helpers
# ---------------------------------------------------------------------------

async def get_recent_log(
    tenant_id: str | None = None,
    limit: int = 100,
    offset: int = 0,
    event_type: str | None = None,
) -> list[dict[str, Any]]:
    """Return recent audit log entries, newest first."""
    try:
        async with get_session_factory()() as session:
            q = select(ReconciliationAuditLog).order_by(
                ReconciliationAuditLog.detected_at.desc()
            )
            if tenant_id:
                q = q.where(ReconciliationAuditLog.tenant_id == tenant_id)
            if event_type:
                q = q.where(ReconciliationAuditLog.event_type == event_type)
            q = q.offset(offset).limit(limit)
            result = await session.execute(q)
            rows = result.scalars().all()
        return [_row_to_dict(r) for r in rows]
    except Exception as exc:
        logger.error("get_recent_log failed: %s", exc)
        return []


async def get_log_stats() -> dict[str, Any]:
    """Return aggregate stats over the last 24h."""
    from sqlalchemy import func
    try:
        cutoff = _utcnow() - timedelta(hours=24)
        async with get_session_factory()() as session:
            result = await session.execute(
                select(
                    ReconciliationAuditLog.event_type,
                    func.count(ReconciliationAuditLog.id).label("count"),
                )
                .where(ReconciliationAuditLog.detected_at >= cutoff)
                .group_by(ReconciliationAuditLog.event_type)
            )
            rows = result.all()
        return {
            "window_hours": 24,
            "by_event_type": {r.event_type: r.count for r in rows},
            "total": sum(r.count for r in rows),
        }
    except Exception as exc:
        logger.error("get_log_stats failed: %s", exc)
        return {}


# ---------------------------------------------------------------------------
# Retention pruning
# ---------------------------------------------------------------------------

async def prune_old_entries() -> int:
    """
    Delete audit log rows older than RETENTION_DAYS.
    Returns the number of rows deleted.
    Called by the nightly reconciliation scheduler.
    """
    cutoff = _utcnow() - timedelta(days=RETENTION_DAYS)
    try:
        async with get_session_factory()() as session:
            result = await session.execute(
                delete(ReconciliationAuditLog).where(
                    ReconciliationAuditLog.detected_at < cutoff
                )
            )
            await session.commit()
            deleted = result.rowcount
        logger.info("audit_log: pruned %d rows older than %d days", deleted, RETENTION_DAYS)
        return deleted
    except Exception as exc:
        logger.error("audit_log prune failed: %s", exc)
        return 0


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _json(d: Any) -> str | None:
    if d is None:
        return None
    try:
        return json.dumps(d, default=str)
    except Exception:
        return str(d)


async def _insert(**kwargs) -> None:
    """Insert one audit log row — best-effort (never raises)."""
    import uuid
    try:
        row = ReconciliationAuditLog(
            id=str(uuid.uuid4()),
            tenant_id=kwargs.get("tenant_id", ""),
            event_type=kwargs.get("event_type", ""),
            drift_type=kwargs.get("drift_type"),
            severity=kwargs.get("severity"),
            mc3_state_json=_json(kwargs.get("mc3_state")),
            erp_state_json=_json(kwargs.get("erp_state")),
            edge_state_json=_json(kwargs.get("edge_state")),
            action_taken=kwargs.get("action_taken"),
            result=kwargs.get("result"),
            error_detail=kwargs.get("error_detail"),
            before_version=kwargs.get("before_version"),
            after_version=kwargs.get("after_version"),
            detected_at=_utcnow(),
            resolved_at=kwargs.get("resolved_at"),
            duration_ms=kwargs.get("duration_ms"),
        )
        async with get_session_factory()() as session:
            session.add(row)
            await session.commit()
    except Exception as exc:
        logger.error("audit_log _insert failed: %s", exc)


def _row_to_dict(r: ReconciliationAuditLog) -> dict[str, Any]:
    import json as _json_mod
    def _parse(v):
        if v is None:
            return None
        try:
            return _json_mod.loads(v)
        except Exception:
            return v
    return {
        "id":             r.id,
        "tenant_id":      r.tenant_id,
        "event_type":     r.event_type,
        "drift_type":     r.drift_type,
        "severity":       r.severity,
        "mc3_state":      _parse(r.mc3_state_json),
        "erp_state":      _parse(r.erp_state_json),
        "edge_state":     _parse(r.edge_state_json),
        "action_taken":   r.action_taken,
        "result":         r.result,
        "error_detail":   r.error_detail,
        "before_version": r.before_version,
        "after_version":  r.after_version,
        "detected_at":    r.detected_at.isoformat() if r.detected_at else None,
        "resolved_at":    r.resolved_at.isoformat() if r.resolved_at else None,
        "duration_ms":    r.duration_ms,
    }
