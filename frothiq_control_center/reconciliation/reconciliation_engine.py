"""
Reconciliation Engine — deterministic, idempotent drift correction.

Decision tree
─────────────
                    Drift detected
                         │
          ┌──────────────┴──────────────┐
    ERPNext reachable?            ERPNext unreachable?
          │                              │
    Pull authoritative state       DEFERRED_RECONCILIATION
    Apply state machine             (log + return)
    Overwrite MC3 cache
    Increment version
    Publish billing event
          │
    Edge drift also present?
    ─ YES: push FederationContract to edge
           wait for ACK (async, tracked by edge_ack_tracker)
           retry up to MAX_RETRIES on failure

Safety rules enforced here:
  - NEVER downgrade state without ERPNext confirmation
  - NEVER infer billing state
  - NEVER allow edge to override MC3
  - ALWAYS increment version on correction
  - ALWAYS write audit log entry
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

from frothiq_control_center.billing.billing_event_publisher import publish_billing_update
from frothiq_control_center.billing.billing_sync_client import pull_tenant_state
from frothiq_control_center.billing.billing_sync_client import _apply_and_persist
from frothiq_control_center.billing.license_state_cache import (
    get_billing_state,
    invalidate_cache,
)
from frothiq_control_center.reconciliation.drift_detector import (
    DriftReport,
    DriftType,
    DriftSeverity,
    detect_drift,
)
from frothiq_control_center.reconciliation.reconciliation_audit_log import (
    log_deferred,
    log_drift_detected,
    log_error,
    log_reconciled,
)
from frothiq_control_center.reconciliation.edge_ack_tracker import (
    record_push,
    record_push_failure,
)

logger = logging.getLogger(__name__)

# How many seconds to try reaching ERPNext before declaring it unreachable
ERP_REACHABILITY_TIMEOUT = 8.0

# Max retries for edge contract push within one reconciliation run
EDGE_PUSH_MAX_RETRIES = 3
EDGE_PUSH_BACKOFF_BASE = 2.0  # seconds


# ---------------------------------------------------------------------------
# Public: reconcile one tenant
# ---------------------------------------------------------------------------

class ReconciliationResult:
    __slots__ = (
        "tenant_id", "action", "drifts_found", "drifts_resolved",
        "deferred", "error", "duration_ms",
    )

    def __init__(self, tenant_id: str):
        self.tenant_id      = tenant_id
        self.action         = "no_drift"
        self.drifts_found   : list[str] = []
        self.drifts_resolved: list[str] = []
        self.deferred       : list[str] = []
        self.error          : str | None = None
        self.duration_ms    : float = 0.0

    def as_dict(self) -> dict[str, Any]:
        return {
            "tenant_id":       self.tenant_id,
            "action":          self.action,
            "drifts_found":    self.drifts_found,
            "drifts_resolved": self.drifts_resolved,
            "deferred":        self.deferred,
            "error":           self.error,
            "duration_ms":     self.duration_ms,
        }


async def reconcile_tenant(
    tenant_id: str,
    force: bool = False,
    edge_state: dict[str, Any] | None = None,
) -> ReconciliationResult:
    """
    Run a full reconciliation cycle for *tenant_id*.

    Steps:
      1. Read MC3 cached state.
      2. Pull ERPNext authoritative state (with timeout).
      3. Run drift detector.
      4. If drift found: apply corrections per decision tree.
      5. If edge_state provided: check edge drift and push contract if needed.

    Args:
        tenant_id:   Tenant to reconcile.
        force:       If True, always pull from ERPNext even if no drift detected.
        edge_state:  Optional edge heartbeat payload for edge drift detection.

    Returns:
        ReconciliationResult describing what happened.
    """
    result = ReconciliationResult(tenant_id)
    t0 = time.monotonic()

    try:
        # ── Step 1: read cached state ──────────────────────────────────
        mc3_state = await get_billing_state(tenant_id)

        # ── Step 2: pull from ERPNext ──────────────────────────────────
        erp_state = await _try_pull_erp(tenant_id)
        erp_reachable = erp_state is not None and erp_state.get("source") != "fallback"

        # ── Step 3: detect drift ───────────────────────────────────────
        reports = detect_drift(tenant_id, mc3_state, erp_state, edge_state)

        if not reports and not force:
            result.action = "no_drift"
            result.duration_ms = (time.monotonic() - t0) * 1000
            return result

        result.drifts_found = [r.drift_type.value for r in reports]

        # ── Step 4: log all detected drift ────────────────────────────
        for report in reports:
            await log_drift_detected(
                tenant_id=tenant_id,
                drift_type=report.drift_type.value,
                severity=report.severity.value,
                mc3_state=report.mc3_state,
                erp_state=report.erp_state,
                edge_state=report.edge_state,
                detail=report.detail,
            )

        # ── Step 5: classify by resolution path ───────────────────────
        mc3_drifts  = [r for r in reports if r.drift_type in (
            DriftType.STATE_MISMATCH, DriftType.PLAN_MISMATCH,
            DriftType.VERSION_MISMATCH, DriftType.MISSING_STATE,
            DriftType.SPLIT_BRAIN,
        )]
        edge_drifts = [r for r in reports if r.drift_type in (
            DriftType.EDGE_STALE, DriftType.EDGE_CONFLICT,
        )]

        # ── Step 6: resolve MC3 drift ──────────────────────────────────
        if mc3_drifts or force:
            if not erp_reachable:
                # CASE 1: ERPNext down — defer
                for r in mc3_drifts:
                    await log_deferred(
                        tenant_id=tenant_id,
                        drift_type=r.drift_type.value,
                        reason="ERPNext unreachable — reconciliation deferred",
                        mc3_state=mc3_state,
                    )
                    result.deferred.append(r.drift_type.value)
                result.action = "deferred"
            else:
                # ERPNext reachable — force authoritative overwrite
                before_version = int((mc3_state or {}).get("state_version") or 0)
                fresh = await _apply_and_persist(tenant_id, erp_state, "reconciliation")
                after_version = int(fresh.get("state_version") or 0)

                for r in mc3_drifts:
                    await log_reconciled(
                        tenant_id=tenant_id,
                        drift_type=r.drift_type.value,
                        before_version=before_version,
                        after_version=after_version,
                        action_taken=(
                            f"overwrote MC3 from ERPNext: "
                            f"status={fresh.get('subscription_status')!r} "
                            f"plan={fresh.get('effective_plan')!r}"
                        ),
                        mc3_state=mc3_state,
                        erp_state=erp_state,
                        duration_ms=(time.monotonic() - t0) * 1000,
                    )
                    result.drifts_resolved.append(r.drift_type.value)

                # Publish updated state to edge + WS
                try:
                    await publish_billing_update(
                        tenant_id, fresh, "billing.reconciliation_correction"
                    )
                except Exception as exc:
                    logger.warning("reconcile_tenant: publish failed for %s: %s", tenant_id, exc)

                result.action = "corrected"
                mc3_state = fresh   # update for edge drift check below

        # ── Step 7: resolve edge drift ─────────────────────────────────
        if edge_drifts and mc3_state:
            pushed = await _push_contract_to_edges(tenant_id, mc3_state, edge_drifts)
            for r in edge_drifts:
                if pushed:
                    result.drifts_resolved.append(r.drift_type.value)
                else:
                    result.deferred.append(r.drift_type.value)

            if pushed and result.action == "no_drift":
                result.action = "edge_corrected"

    except Exception as exc:
        logger.error("reconcile_tenant failed: tenant=%s: %s", tenant_id, exc, exc_info=True)
        await log_error(tenant_id, "reconciliation_error", str(exc))
        result.action = "error"
        result.error = str(exc)

    result.duration_ms = (time.monotonic() - t0) * 1000
    return result


# ---------------------------------------------------------------------------
# Batch reconcile
# ---------------------------------------------------------------------------

async def reconcile_all(
    tenant_ids: list[str],
    concurrency: int = 5,
) -> dict[str, Any]:
    """
    Reconcile a batch of tenants with bounded concurrency.
    Returns a summary dict.
    """
    semaphore = asyncio.Semaphore(concurrency)

    async def _bounded(tid: str) -> ReconciliationResult:
        async with semaphore:
            return await reconcile_tenant(tid)

    t0 = time.monotonic()
    results = await asyncio.gather(*[_bounded(tid) for tid in tenant_ids], return_exceptions=True)

    total      = len(tenant_ids)
    corrected  = 0
    deferred   = 0
    no_drift   = 0
    errors     = 0

    for r in results:
        if isinstance(r, ReconciliationResult):
            if r.action in ("corrected", "edge_corrected"):
                corrected += 1
            elif r.action == "deferred":
                deferred += 1
            elif r.action == "no_drift":
                no_drift += 1
            elif r.action == "error":
                errors += 1
        else:
            errors += 1

    return {
        "total":      total,
        "corrected":  corrected,
        "deferred":   deferred,
        "no_drift":   no_drift,
        "errors":     errors,
        "duration_ms": (time.monotonic() - t0) * 1000,
    }


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

async def _try_pull_erp(tenant_id: str) -> dict[str, Any] | None:
    """
    Attempt to pull ERPNext state with a timeout.
    Returns None if the pull times out or returns only a fallback state.
    """
    try:
        state = await asyncio.wait_for(
            pull_tenant_state(tenant_id),
            timeout=ERP_REACHABILITY_TIMEOUT,
        )
        # Distinguish genuine ERP data from the free-fallback
        if state.get("source") == "fallback":
            logger.warning(
                "_try_pull_erp: got fallback state for %s (ERPNext unreachable?)", tenant_id
            )
            return None
        return state
    except asyncio.TimeoutError:
        logger.warning("_try_pull_erp: timeout for tenant=%s", tenant_id)
        return None
    except Exception as exc:
        logger.warning("_try_pull_erp: error for tenant=%s: %s", tenant_id, exc)
        return None


async def _push_contract_to_edges(
    tenant_id: str,
    mc3_state: dict[str, Any],
    edge_drifts: list[DriftReport],
) -> bool:
    """
    Push a FederationContract to all edge nodes for *tenant_id*.
    Uses the billing event publisher (which handles HTTP PATCH to each node).
    Returns True if at least one edge was reached.
    """
    import httpx
    from frothiq_control_center.reconciliation.edge_ack_tracker import record_push, record_push_failure
    from frothiq_control_center.billing.billing_event_publisher import _get_edge_nodes, _build_edge_billing_url

    nodes = await _get_edge_nodes(tenant_id)
    if not nodes:
        logger.debug("_push_contract_to_edges: no registered edge nodes for %s", tenant_id)
        return False

    contract_version = int(mc3_state.get("state_version") or 0)
    contract_payload = {
        "subscription_status": mc3_state.get("subscription_status"),
        "effective_plan":      mc3_state.get("effective_plan"),
        "enforcement_mode":    mc3_state.get("enforcement_mode"),
        "features":            mc3_state.get("features") or {},
        "limits":              mc3_state.get("limits") or {},
        "state_version":       contract_version,
        "expiry":              mc3_state.get("expiry"),
        "grace_until":         mc3_state.get("grace_until"),
        "contract_type":       "reconciliation",
    }

    pushed_any = False
    async with httpx.AsyncClient(timeout=8.0) as client:
        for node in nodes:
            edge_id = node.get("id") or node.get("edge_id") or "unknown"
            url = _build_edge_billing_url(node)
            if not url:
                continue

            await record_push(tenant_id, edge_id, contract_version)

            for attempt in range(1, EDGE_PUSH_MAX_RETRIES + 1):
                try:
                    resp = await client.patch(url, json=contract_payload)
                    if resp.status_code < 400:
                        pushed_any = True
                        logger.info(
                            "contract push OK: tenant=%s edge=%s v=%d attempt=%d",
                            tenant_id, edge_id, contract_version, attempt,
                        )
                        break
                    else:
                        logger.warning(
                            "contract push HTTP %d: tenant=%s edge=%s attempt=%d",
                            resp.status_code, tenant_id, edge_id, attempt,
                        )
                except Exception as exc:
                    logger.warning(
                        "contract push error: tenant=%s edge=%s attempt=%d: %s",
                        tenant_id, edge_id, attempt, exc,
                    )

                if attempt < EDGE_PUSH_MAX_RETRIES:
                    await asyncio.sleep(EDGE_PUSH_BACKOFF_BASE ** attempt)
                else:
                    await record_push_failure(tenant_id, edge_id)

    return pushed_any
