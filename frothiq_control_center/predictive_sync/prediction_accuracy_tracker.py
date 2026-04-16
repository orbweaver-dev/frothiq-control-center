"""
Prediction Accuracy Tracker.

Tracks the prediction/confirmation loop outcomes and exposes accuracy
metrics for the /predictive/accuracy API endpoint.

Storage:
  - Redis hash frothiq:prediction:accuracy  — rolling counters (fast read)
  - DB PredictionRecord                     — append-only history (query/export)

Metrics produced:
  - total_predictions
  - correct_predictions
  - incorrect_predictions
  - timeout_predictions       (no confirmation arrived; auto-activated)
  - accuracy_rate             (correct / total)
  - mean_latency_saved_ms     (mean enforcement lag prevented by correct predictions)
  - drift_prevented_count     (= correct_predictions — states that would have drifted)
  - by_signal_type            (per-signal accuracy breakdown)
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from enum import Enum
from typing import Any
from datetime import datetime, timezone, timedelta

from sqlalchemy import func, select

from frothiq_control_center.integrations.database import get_session_factory
from frothiq_control_center.integrations.redis_client import get_cache_client
from frothiq_control_center.models.predictive_sync import PredictionRecord

logger = logging.getLogger(__name__)

_ACCURACY_REDIS_KEY  = "frothiq:prediction:accuracy"
_ACCURACY_REDIS_TTL  = 7 * 86400   # 7 days rolling window in Redis

# Rule 7 counter keys within the accuracy hash
_COUNTER_INCORRECT_AUTO_ACTIVATION = "incorrect_auto_activation_count"
_COUNTER_REPLACEMENTS               = "staged_contract_replacements"
_COUNTER_COLLISIONS                 = "prediction_collision_count"
_COUNTER_EDGE_REJECTIONS            = "edge_rejection_count"


class OutcomeType(str, Enum):
    CORRECT   = "correct"
    INCORRECT = "incorrect"
    TIMEOUT   = "timeout"
    CANCELLED = "cancelled"


# ---------------------------------------------------------------------------
# Write: record an outcome
# ---------------------------------------------------------------------------

async def record_outcome(
    tenant_id:        str,
    signal_type:      str,
    predicted_to:     str,
    confidence_score: float,
    outcome:          OutcomeType,
    confirmed_state:  str | None = None,
    latency_saved_ms: float | None = None,
) -> None:
    """
    Record the outcome of a prediction.
    Writes to both Redis counters and DB history.
    """
    # ── Redis counters ──────────────────────────────────────────────────
    await _increment_redis(outcome, signal_type, latency_saved_ms)

    # ── DB history ──────────────────────────────────────────────────────
    await _append_db(
        tenant_id=tenant_id,
        signal_type=signal_type,
        predicted_to=predicted_to,
        confidence_score=confidence_score,
        outcome=outcome,
        confirmed_state=confirmed_state,
        latency_saved_ms=latency_saved_ms,
    )


# ---------------------------------------------------------------------------
# Rule 7: safety counter increments
# ---------------------------------------------------------------------------

async def record_incorrect_auto_activation(tenant_id: str) -> None:
    """
    Increment the incorrect_auto_activation_count counter.
    Called when an edge activated a staged contract that later turned out wrong.
    """
    await _increment_safety_counter(_COUNTER_INCORRECT_AUTO_ACTIVATION, tenant_id)


async def record_replacement(tenant_id: str) -> None:
    """
    Increment the staged_contract_replacements counter.
    Called when a staged contract is atomically retired and replaced (Rule 2).
    """
    await _increment_safety_counter(_COUNTER_REPLACEMENTS, tenant_id)


async def record_collision(tenant_id: str) -> None:
    """
    Increment the prediction_collision_count counter.
    Called when multiple signals fire for the same tenant in one scan cycle (Rule 5).
    """
    await _increment_safety_counter(_COUNTER_COLLISIONS, tenant_id)


async def record_edge_rejection(tenant_id: str, edge_id: str) -> None:
    """
    Increment the edge_rejection_count counter.
    Called when an edge rejects a staged contract (activation guard check failed).
    """
    await _increment_safety_counter(_COUNTER_EDGE_REJECTIONS, tenant_id, edge_id=edge_id)


async def _increment_safety_counter(
    counter_key: str,
    tenant_id: str,
    edge_id: str | None = None,
) -> None:
    """Atomically increment a Rule-7 safety counter in the accuracy Redis hash."""
    try:
        redis = await get_cache_client()
        pipe  = redis.pipeline()
        pipe.hincrby(_ACCURACY_REDIS_KEY, counter_key, 1)
        # Also track per-tenant for debugging
        pipe.hincrby(_ACCURACY_REDIS_KEY, f"tenant:{tenant_id}:{counter_key}", 1)
        if edge_id:
            pipe.hincrby(_ACCURACY_REDIS_KEY, f"edge:{edge_id}:{counter_key}", 1)
        pipe.expire(_ACCURACY_REDIS_KEY, _ACCURACY_REDIS_TTL)
        await pipe.execute()
    except Exception as exc:
        logger.warning("_increment_safety_counter(%s) failed: %s", counter_key, exc)


# ---------------------------------------------------------------------------
# Read: accuracy metrics
# ---------------------------------------------------------------------------

async def get_accuracy_metrics(window_hours: int = 24) -> dict[str, Any]:
    """
    Return accuracy metrics for the given time window.
    Combines Redis rolling counters (fast) with DB aggregate queries.
    """
    # DB aggregate for the requested window
    cutoff = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(hours=window_hours)
    db_metrics = await _query_db_metrics(cutoff)

    # Redis for all-time rolling totals
    redis_totals = await _read_redis_counters()

    total       = db_metrics["total"]
    correct     = db_metrics["correct"]
    incorrect   = db_metrics["incorrect"]
    timeout     = db_metrics["timeout"]
    accuracy    = round(correct / total, 3) if total > 0 else 0.0
    mean_latency = db_metrics.get("mean_latency_saved_ms") or 0.0

    # Rule 7: read safety counters from Redis
    safety = await _read_safety_counters()

    return {
        "window_hours":          window_hours,
        "total_predictions":     total,
        "correct_predictions":   correct,
        "incorrect_predictions": incorrect,
        "timeout_predictions":   timeout,
        "accuracy_rate":         accuracy,
        "mean_latency_saved_ms": round(mean_latency, 1),
        "drift_prevented_count": correct,       # every correct prediction prevented a drift window
        "by_signal_type":        db_metrics.get("by_signal_type", {}),
        # Rule 7 safety counters (all-time rolling)
        "incorrect_auto_activation_count": safety.get(_COUNTER_INCORRECT_AUTO_ACTIVATION, 0),
        "staged_contract_replacements":    safety.get(_COUNTER_REPLACEMENTS, 0),
        "prediction_collision_count":      safety.get(_COUNTER_COLLISIONS, 0),
        "edge_rejection_count":            safety.get(_COUNTER_EDGE_REJECTIONS, 0),
        "rolling_totals":        redis_totals,
        "computed_at":           time.time(),
    }


async def get_accuracy_history(
    tenant_id: str | None = None,
    limit: int = 100,
) -> list[dict[str, Any]]:
    """Return raw prediction history records from DB."""
    try:
        async with get_session_factory()() as session:
            q = select(PredictionRecord).order_by(
                PredictionRecord.predicted_at.desc()
            )
            if tenant_id:
                q = q.where(PredictionRecord.tenant_id == tenant_id)
            q = q.limit(limit)
            result = await session.execute(q)
            rows = result.scalars().all()
        return [_row_to_dict(r) for r in rows]
    except Exception as exc:
        logger.error("get_accuracy_history failed: %s", exc)
        return []


# ---------------------------------------------------------------------------
# Internal: Redis counter operations
# ---------------------------------------------------------------------------

async def _increment_redis(
    outcome: OutcomeType,
    signal_type: str,
    latency_saved_ms: float | None,
) -> None:
    try:
        redis = await get_cache_client()
        pipe  = redis.pipeline()
        pipe.hincrby(_ACCURACY_REDIS_KEY, "total", 1)
        pipe.hincrby(_ACCURACY_REDIS_KEY, outcome.value, 1)
        pipe.hincrby(_ACCURACY_REDIS_KEY, f"signal:{signal_type}:total", 1)
        pipe.hincrby(_ACCURACY_REDIS_KEY, f"signal:{signal_type}:{outcome.value}", 1)
        if latency_saved_ms is not None and latency_saved_ms > 0:
            # Accumulate for mean calculation: sum + count
            pipe.hincrbyfloat(_ACCURACY_REDIS_KEY, "latency_sum_ms", latency_saved_ms)
            pipe.hincrby(_ACCURACY_REDIS_KEY, "latency_count", 1)
        pipe.expire(_ACCURACY_REDIS_KEY, _ACCURACY_REDIS_TTL)
        await pipe.execute()
    except Exception as exc:
        logger.warning("_increment_redis accuracy failed: %s", exc)


async def _read_safety_counters() -> dict[str, int]:
    """Read the four Rule-7 safety counters from Redis."""
    try:
        redis = await get_cache_client()
        keys  = [
            _COUNTER_INCORRECT_AUTO_ACTIVATION,
            _COUNTER_REPLACEMENTS,
            _COUNTER_COLLISIONS,
            _COUNTER_EDGE_REJECTIONS,
        ]
        values = await redis.hmget(_ACCURACY_REDIS_KEY, *keys)
        return {
            k: int(v or 0)
            for k, v in zip(keys, values)
        }
    except Exception as exc:
        logger.warning("_read_safety_counters failed: %s", exc)
        return {}


async def _read_redis_counters() -> dict[str, Any]:
    try:
        redis = await get_cache_client()
        raw = await redis.hgetall(_ACCURACY_REDIS_KEY)
        if not raw:
            return {}
        decoded = {k.decode() if isinstance(k, bytes) else k:
                   v.decode() if isinstance(v, bytes) else v
                   for k, v in raw.items()}
        total   = int(decoded.get("total", 0))
        correct = int(decoded.get("correct", 0))
        lat_sum = float(decoded.get("latency_sum_ms", 0))
        lat_cnt = int(decoded.get("latency_count", 0))
        return {
            "total":      total,
            "correct":    correct,
            "incorrect":  int(decoded.get("incorrect", 0)),
            "timeout":    int(decoded.get("timeout", 0)),
            "accuracy":   round(correct / total, 3) if total > 0 else 0.0,
            "mean_latency_saved_ms": round(lat_sum / lat_cnt, 1) if lat_cnt > 0 else 0.0,
        }
    except Exception as exc:
        logger.warning("_read_redis_counters failed: %s", exc)
        return {}


# ---------------------------------------------------------------------------
# Internal: DB operations
# ---------------------------------------------------------------------------

async def _append_db(
    tenant_id:        str,
    signal_type:      str,
    predicted_to:     str,
    confidence_score: float,
    outcome:          OutcomeType,
    confirmed_state:  str | None,
    latency_saved_ms: float | None,
) -> None:
    try:
        row = PredictionRecord(
            id=str(uuid.uuid4()),
            tenant_id=tenant_id,
            signal_type=signal_type,
            predicted_to=predicted_to,
            confidence_score=confidence_score,
            outcome=outcome.value,
            confirmed_state=confirmed_state,
            latency_saved_ms=latency_saved_ms,
            resolved_at=datetime.now(timezone.utc).replace(tzinfo=None),
        )
        async with get_session_factory()() as session:
            session.add(row)
            await session.commit()
    except Exception as exc:
        logger.error("_append_db accuracy failed: %s", exc)


async def _query_db_metrics(cutoff: datetime) -> dict[str, Any]:
    try:
        async with get_session_factory()() as session:
            # Total + per-outcome counts
            result = await session.execute(
                select(
                    PredictionRecord.outcome,
                    func.count(PredictionRecord.id).label("count"),
                    func.avg(PredictionRecord.latency_saved_ms).label("avg_latency"),
                )
                .where(PredictionRecord.predicted_at >= cutoff)
                .group_by(PredictionRecord.outcome)
            )
            outcome_rows = result.all()

            # Per-signal breakdown
            sig_result = await session.execute(
                select(
                    PredictionRecord.signal_type,
                    PredictionRecord.outcome,
                    func.count(PredictionRecord.id).label("count"),
                )
                .where(PredictionRecord.predicted_at >= cutoff)
                .group_by(PredictionRecord.signal_type, PredictionRecord.outcome)
            )
            sig_rows = sig_result.all()

        counts = {r.outcome: r.count for r in outcome_rows}
        latencies = {r.outcome: r.avg_latency for r in outcome_rows if r.avg_latency}
        total = sum(counts.values())

        by_signal: dict[str, dict] = {}
        for r in sig_rows:
            sig = r.signal_type
            if sig not in by_signal:
                by_signal[sig] = {"total": 0}
            by_signal[sig][r.outcome] = r.count
            by_signal[sig]["total"]   += r.count

        return {
            "total":     total,
            "correct":   counts.get("correct",   0),
            "incorrect": counts.get("incorrect", 0),
            "timeout":   counts.get("timeout",   0),
            "mean_latency_saved_ms": latencies.get("correct"),
            "by_signal_type": by_signal,
        }
    except Exception as exc:
        logger.error("_query_db_metrics failed: %s", exc)
        return {"total": 0, "correct": 0, "incorrect": 0, "timeout": 0}


def _row_to_dict(r: PredictionRecord) -> dict[str, Any]:
    return {
        "id":               r.id,
        "tenant_id":        r.tenant_id,
        "signal_type":      r.signal_type,
        "predicted_to":     r.predicted_to,
        "confidence_score": r.confidence_score,
        "outcome":          r.outcome,
        "confirmed_state":  r.confirmed_state,
        "latency_saved_ms": r.latency_saved_ms,
        "predicted_at":     r.predicted_at.isoformat() if r.predicted_at else None,
        "resolved_at":      r.resolved_at.isoformat() if r.resolved_at else None,
    }
