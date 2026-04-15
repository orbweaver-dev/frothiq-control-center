"""
Reconciliation Scheduler — asyncio-native background task runner.

Schedules:
  Every  5 minutes: high-risk tenants (recent billing changes, CRITICAL drift)
  Every 15 minutes: 10% random sample of all tenants
  Hourly:           full reconciliation sweep of all known tenants
  Daily (03:00 UTC): audit log pruning (30-day retention)
  On-demand:        triggered via reconciliation_api.py

Implementation uses asyncio.sleep loops launched as named tasks in main.py
lifespan — no external scheduler dependency needed.

Usage (from main.py lifespan):
    from frothiq_control_center.reconciliation.reconciliation_scheduler import (
        ReconciliationScheduler
    )
    scheduler = ReconciliationScheduler()
    task = asyncio.create_task(scheduler.run(), name="reconciliation_scheduler")
    yield
    task.cancel()
"""

from __future__ import annotations

import asyncio
import logging
import random
import time
from datetime import datetime, timezone

from frothiq_control_center.billing.license_state_cache import get_all_billing_states
from frothiq_control_center.reconciliation.reconciliation_engine import (
    reconcile_all,
    reconcile_tenant,
)
from frothiq_control_center.reconciliation.reconciliation_audit_log import (
    prune_old_entries,
)

logger = logging.getLogger(__name__)

# Schedule intervals (seconds)
_HIGH_RISK_INTERVAL_SEC     = 5   * 60   #  5 minutes
_SAMPLE_INTERVAL_SEC        = 15  * 60   # 15 minutes
_FULL_SWEEP_INTERVAL_SEC    = 60  * 60   #  1 hour
_PRUNE_INTERVAL_SEC         = 24  * 60 * 60  # 24 hours

# Fraction of tenants to sample per 15-minute window
_SAMPLE_FRACTION = 0.10

# High-risk = state changed within last N seconds
_HIGH_RISK_WINDOW_SEC = 10 * 60  # 10 minutes


class ReconciliationScheduler:
    """
    Runs three independent asyncio loops for the three schedules.
    All loops share the same asyncio event loop (single process).
    """

    def __init__(self) -> None:
        self._running = False

    async def run(self) -> None:
        """Entry point — launches all sub-loops and supervises them."""
        self._running = True
        logger.info("reconciliation_scheduler: started")

        tasks = [
            asyncio.create_task(self._high_risk_loop(),  name="recon_high_risk"),
            asyncio.create_task(self._sample_loop(),     name="recon_sample"),
            asyncio.create_task(self._full_sweep_loop(), name="recon_full"),
            asyncio.create_task(self._prune_loop(),      name="recon_prune"),
        ]

        try:
            await asyncio.gather(*tasks)
        except asyncio.CancelledError:
            logger.info("reconciliation_scheduler: stopping")
            for t in tasks:
                t.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            self._running = False
            raise

    # -------------------------------------------------------------------------
    # Sub-loops
    # -------------------------------------------------------------------------

    async def _high_risk_loop(self) -> None:
        """Every 5 minutes: reconcile tenants that changed state recently."""
        while True:
            try:
                await asyncio.sleep(_HIGH_RISK_INTERVAL_SEC)
                tenant_ids = await _get_high_risk_tenant_ids()
                if tenant_ids:
                    logger.info(
                        "reconciliation_scheduler: high_risk sweep — %d tenants",
                        len(tenant_ids),
                    )
                    summary = await reconcile_all(tenant_ids, concurrency=3)
                    _log_summary("high_risk", summary)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.error("reconciliation_scheduler: high_risk_loop error: %s", exc)

    async def _sample_loop(self) -> None:
        """Every 15 minutes: reconcile 10% of all tenants (random)."""
        while True:
            try:
                await asyncio.sleep(_SAMPLE_INTERVAL_SEC)
                all_ids = await _get_all_tenant_ids()
                if not all_ids:
                    continue
                sample_size = max(1, int(len(all_ids) * _SAMPLE_FRACTION))
                sample = random.sample(all_ids, min(sample_size, len(all_ids)))
                logger.info(
                    "reconciliation_scheduler: sample sweep — %d/%d tenants",
                    len(sample), len(all_ids),
                )
                summary = await reconcile_all(sample, concurrency=3)
                _log_summary("sample", summary)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.error("reconciliation_scheduler: sample_loop error: %s", exc)

    async def _full_sweep_loop(self) -> None:
        """Hourly: full reconciliation of all known tenants."""
        # Stagger 90s after startup to let other initialization finish
        await asyncio.sleep(90)
        while True:
            try:
                all_ids = await _get_all_tenant_ids()
                if all_ids:
                    logger.info(
                        "reconciliation_scheduler: full sweep — %d tenants",
                        len(all_ids),
                    )
                    summary = await reconcile_all(all_ids, concurrency=5)
                    _log_summary("full_sweep", summary)
                await asyncio.sleep(_FULL_SWEEP_INTERVAL_SEC)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.error("reconciliation_scheduler: full_sweep_loop error: %s", exc)
                await asyncio.sleep(_FULL_SWEEP_INTERVAL_SEC)

    async def _prune_loop(self) -> None:
        """
        Daily: prune audit log entries older than 30 days.
        First fires at next 03:00 UTC; subsequent fires every 24 hours.
        """
        await _sleep_until_utc_hour(3)
        while True:
            try:
                deleted = await prune_old_entries()
                logger.info("reconciliation_scheduler: audit log pruned %d rows", deleted)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.error("reconciliation_scheduler: prune_loop error: %s", exc)
            await asyncio.sleep(_PRUNE_INTERVAL_SEC)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

async def _get_all_tenant_ids() -> list[str]:
    try:
        states = await get_all_billing_states()
        return [s["tenant_id"] for s in states if s.get("tenant_id")]
    except Exception as exc:
        logger.warning("_get_all_tenant_ids failed: %s", exc)
        return []


async def _get_high_risk_tenant_ids() -> list[str]:
    """
    Return tenants whose billing state was updated within the last HIGH_RISK_WINDOW_SEC.
    These are most likely to be in mid-transition and worth proactive checking.
    """
    try:
        cutoff = time.time() - _HIGH_RISK_WINDOW_SEC
        states = await get_all_billing_states()
        return [
            s["tenant_id"]
            for s in states
            if float(s.get("last_updated") or 0) >= cutoff
        ]
    except Exception as exc:
        logger.warning("_get_high_risk_tenant_ids failed: %s", exc)
        return []


def _log_summary(label: str, summary: dict) -> None:
    logger.info(
        "reconciliation_scheduler: %s complete — total=%d corrected=%d "
        "deferred=%d no_drift=%d errors=%d (%.0fms)",
        label,
        summary.get("total",     0),
        summary.get("corrected", 0),
        summary.get("deferred",  0),
        summary.get("no_drift",  0),
        summary.get("errors",    0),
        summary.get("duration_ms", 0),
    )


async def _sleep_until_utc_hour(target_hour: int) -> None:
    """Sleep until the next occurrence of *target_hour* UTC."""
    now = datetime.now(timezone.utc)
    next_run = now.replace(hour=target_hour, minute=0, second=0, microsecond=0)
    if next_run <= now:
        # Already past today's 03:00 — aim for tomorrow
        from datetime import timedelta
        next_run += timedelta(days=1)
    delay = (next_run - now).total_seconds()
    logger.info(
        "reconciliation_scheduler: prune_loop sleeping %.0fs until %s UTC",
        delay, next_run.strftime("%Y-%m-%d %H:%M"),
    )
    await asyncio.sleep(delay)
