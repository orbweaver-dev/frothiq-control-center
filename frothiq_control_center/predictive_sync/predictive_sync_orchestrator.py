"""
Predictive Sync Orchestrator.

Ties the five sub-modules into a single callable pipeline:

  Signal detection
      ↓
  Projected state building       (state machine safety checks)
      ↓
  Staged contract generation     (PENDING flag, activation rules)
      ↓
  Staged contract dispatch       (Redis TTL + DB + HTTP to edges)
      ↓
  Confirmation listener          (called on next confirmed event)

Also provides the background scan loop launched from main.py.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

from frothiq_control_center.billing.license_state_cache import get_billing_state
from frothiq_control_center.predictive_sync.predictive_signal_detector import (
    detect_signals_all_tenants,
    detect_signals_for_tenant,
)
from frothiq_control_center.predictive_sync.preemptive_state_builder import (
    build_projected_state,
)
from frothiq_control_center.predictive_sync.preemptive_contract_generator import (
    generate_staged_contract,
)
from frothiq_control_center.predictive_sync.staged_contract_dispatcher import (
    dispatch_staged_contract,
    get_staged_contract,
)

logger = logging.getLogger(__name__)

# Only build a staged contract when confidence exceeds this threshold
_CONTRACT_THRESHOLD = 0.70

# Scan interval: run signal detection every N seconds
_SCAN_INTERVAL_SEC = 5 * 60   # 5 minutes


async def run_for_tenant(tenant_id: str) -> list[dict[str, Any]]:
    """
    Run the full predictive pipeline for one tenant.
    Returns a list of dispatch result dicts (one per actionable signal).

    Rule 2: atomic replacement is handled by dispatch_staged_contract()
    via _retire_existing_contract() — no need to skip here.
    """
    results: list[dict[str, Any]] = []

    signals = await detect_signals_for_tenant(tenant_id)
    if not signals:
        return results

    # Rule 5: pick highest-confidence signal; break ties by restrictiveness
    # then earliest expected activation window start
    best_signal = _select_best_signal(signals)
    if best_signal.confidence_score < _CONTRACT_THRESHOLD:
        return results

    current_state = await get_billing_state(tenant_id)
    if not current_state:
        return results

    projected = build_projected_state(current_state, best_signal)
    if projected is None:
        logger.debug(
            "run_for_tenant: state machine rejected projection for %s signal=%s",
            tenant_id, best_signal.signal_type.value,
        )
        return results

    from frothiq_control_center.config import get_settings
    signing_key = get_settings().gateway_signing_key

    contract = generate_staged_contract(projected, signing_key)
    dispatch_result = await dispatch_staged_contract(projected, contract)

    dispatch_result["signal_type"]     = best_signal.signal_type.value
    dispatch_result["predicted_to"]    = projected.predicted_status
    dispatch_result["confidence_score"] = projected.confidence_score
    results.append(dispatch_result)

    logger.info(
        "predictive_sync: staged contract for tenant=%s signal=%s predicted=%s conf=%.2f",
        tenant_id, best_signal.signal_type.value, projected.predicted_status,
        projected.confidence_score,
    )
    return results


async def run_all_tenants() -> dict[str, Any]:
    """
    Run the predictive pipeline for all known tenants.

    Rule 5 — Collision resolution:
      When multiple signals fire for the same tenant, choose the best one
      via _select_best_signal():
        1. Highest confidence score
        2. Tie-break: more restrictive transition wins
        3. Tie-break: earliest expected activation window start wins
    """
    signals  = await detect_signals_all_tenants()
    if not signals:
        return {"total": 0, "staged": 0, "skipped": 0}

    # Group by tenant
    by_tenant: dict[str, list[Any]] = {}
    for s in signals:
        by_tenant.setdefault(s.tenant_id, []).append(s)

    # Record collisions (Rule 7)
    from frothiq_control_center.predictive_sync.prediction_accuracy_tracker import (
        record_collision,
    )
    collision_tenants = [t for t, sigs in by_tenant.items() if len(sigs) > 1]
    for tenant_id in collision_tenants:
        await record_collision(tenant_id)

    staged  = 0
    skipped = 0
    for tenant_id in by_tenant:
        results = await run_for_tenant(tenant_id)
        if results:
            staged += 1
        else:
            skipped += 1

    return {
        "total":      len(by_tenant),
        "staged":     staged,
        "skipped":    skipped,
        "collisions": len(collision_tenants),
    }


def _select_best_signal(signals: list[Any]) -> Any:
    """
    Rule 5 — Choose the best signal from a list:
      1. Highest confidence score
      2. Tie-break: more restrictive transition (higher RESTRICTIVE_ORDER rank)
      3. Tie-break: earliest expected window start (smallest timestamp)
    """
    from frothiq_control_center.predictive_sync.preemptive_contract_generator import (
        RESTRICTIVE_ORDER,
    )

    def _sort_key(s: Any) -> tuple:
        to_state = (getattr(s, "predicted_status", None) or "").lower()
        restriction_rank = RESTRICTIVE_ORDER.get(to_state, 1)
        activation_ts = float(getattr(s, "expected_window_start", None) or time.time())
        # Sort by: conf DESC, restriction DESC, activation ASC
        return (-s.confidence_score, -restriction_rank, activation_ts)

    return min(signals, key=_sort_key)


# ---------------------------------------------------------------------------
# Background scan loop — launched by main.py lifespan
# ---------------------------------------------------------------------------

class PredictiveSyncScheduler:
    """
    Asyncio background task that periodically scans all tenants for signals.
    Launched as a named task in main.py alongside the reconciliation scheduler.
    """

    async def run(self) -> None:
        # Stagger 60s to let the reconciliation engine start first
        await asyncio.sleep(60)
        logger.info("predictive_sync_scheduler: started (interval=%ds)", _SCAN_INTERVAL_SEC)
        while True:
            try:
                summary = await run_all_tenants()
                logger.info(
                    "predictive_sync_scheduler: scan complete — %d tenants, %d staged, %d skipped",
                    summary["total"], summary["staged"], summary["skipped"],
                )
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.error("predictive_sync_scheduler: scan error: %s", exc)
            await asyncio.sleep(_SCAN_INTERVAL_SEC)
