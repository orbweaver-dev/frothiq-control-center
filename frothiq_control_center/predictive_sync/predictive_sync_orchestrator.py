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
    """
    results: list[dict[str, Any]] = []

    # Don't generate a new staged contract if one already exists and is active
    existing = await get_staged_contract(tenant_id)
    if existing and _contract_still_valid(existing):
        logger.debug("run_for_tenant: active staged contract exists for %s — skipping", tenant_id)
        return results

    signals = await detect_signals_for_tenant(tenant_id)
    if not signals:
        return results

    # Use the highest-confidence actionable signal
    best_signal = max(signals, key=lambda s: s.confidence_score)
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
    """Run the predictive pipeline for all known tenants."""
    signals  = await detect_signals_all_tenants()
    if not signals:
        return {"total": 0, "staged": 0, "skipped": 0}

    # Deduplicate: one run per tenant (highest-confidence signal wins)
    by_tenant: dict[str, Any] = {}
    for s in signals:
        if s.tenant_id not in by_tenant or s.confidence_score > by_tenant[s.tenant_id].confidence_score:
            by_tenant[s.tenant_id] = s

    staged  = 0
    skipped = 0
    for tenant_id in by_tenant:
        results = await run_for_tenant(tenant_id)
        if results:
            staged += 1
        else:
            skipped += 1

    return {"total": len(by_tenant), "staged": staged, "skipped": skipped}


def _contract_still_valid(contract: dict[str, Any]) -> bool:
    """Return True if a staged contract has not yet expired."""
    valid_until = float(contract.get("max_valid_until") or contract.get("valid_until") or 0)
    return valid_until > time.time()


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
