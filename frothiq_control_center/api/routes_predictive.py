"""
Predictive Sync API.

Endpoints:
  GET  /api/v1/cc/predictive/signals             — current signals across all tenants
  GET  /api/v1/cc/predictive/signals/{tenant_id} — signals for one tenant
  GET  /api/v1/cc/predictive/staged              — all active staged contracts
  GET  /api/v1/cc/predictive/staged/{tenant_id}  — staged contract for one tenant
  GET  /api/v1/cc/predictive/accuracy            — prediction accuracy metrics
  GET  /api/v1/cc/predictive/accuracy/history    — raw prediction history
  POST /api/v1/cc/predictive/scan/{tenant_id}    — on-demand scan (billing_admin)
  POST /api/v1/cc/predictive/scan-all            — full scan (super_admin)
  DELETE /api/v1/cc/predictive/staged/{tenant_id} — discard staged contract
"""

from __future__ import annotations

import time
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query

from frothiq_control_center.auth import (
    require_billing_admin,
    require_read_only,
    require_super_admin,
)
from frothiq_control_center.predictive_sync.predictive_signal_detector import (
    detect_signals_all_tenants,
    detect_signals_for_tenant,
)
from frothiq_control_center.predictive_sync.staged_contract_dispatcher import (
    get_all_staged_contracts,
    get_staged_contract,
    invalidate_staged_contract,
)
from frothiq_control_center.predictive_sync.prediction_accuracy_tracker import (
    get_accuracy_metrics,
    get_accuracy_history,
)
from frothiq_control_center.predictive_sync.predictive_sync_orchestrator import (
    run_all_tenants,
    run_for_tenant,
)

router = APIRouter(prefix="/predictive", tags=["Predictive Sync"])


# ---------------------------------------------------------------------------
# Signals
# ---------------------------------------------------------------------------

@router.get("/signals")
async def get_all_signals(
    _user: Any = Depends(require_read_only),
) -> dict[str, Any]:
    """
    Run signal detection across all tenants and return current signals.
    Only actionable signals (confidence ≥ threshold) are returned.
    """
    signals = await detect_signals_all_tenants()
    by_type: dict[str, int] = {}
    for s in signals:
        by_type[s.signal_type.value] = by_type.get(s.signal_type.value, 0) + 1

    return {
        "total":          len(signals),
        "by_signal_type": by_type,
        "signals":        [s.as_dict() for s in signals],
        "scanned_at":     time.time(),
    }


@router.get("/signals/{tenant_id}")
async def get_tenant_signals(
    tenant_id: str,
    _user: Any = Depends(require_read_only),
) -> dict[str, Any]:
    """Return predictive signals for a single tenant."""
    signals = await detect_signals_for_tenant(tenant_id)
    return {
        "tenant_id": tenant_id,
        "count":     len(signals),
        "signals":   [s.as_dict() for s in signals],
    }


# ---------------------------------------------------------------------------
# Staged contracts
# ---------------------------------------------------------------------------

@router.get("/staged")
async def get_all_staged(
    _user: Any = Depends(require_read_only),
) -> dict[str, Any]:
    """Return all currently active staged contracts."""
    contracts = await get_all_staged_contracts()
    now = time.time()
    valid = [c for c in contracts if float(c.get("valid_until") or 0) > now]
    expired = [c for c in contracts if float(c.get("valid_until") or 0) <= now]

    return {
        "total":       len(contracts),
        "valid":       len(valid),
        "expired":     len(expired),
        "contracts":   contracts,
        "fetched_at":  time.time(),
    }


@router.get("/staged/{tenant_id}")
async def get_tenant_staged(
    tenant_id: str,
    _user: Any = Depends(require_read_only),
) -> dict[str, Any]:
    """Return the active staged contract for one tenant (if any)."""
    contract = await get_staged_contract(tenant_id)
    if not contract:
        raise HTTPException(
            status_code=404,
            detail=f"No active staged contract for tenant {tenant_id!r}",
        )
    return contract


@router.delete("/staged/{tenant_id}", status_code=200)
async def discard_staged_contract(
    tenant_id: str,
    _user: Any = Depends(require_billing_admin),
) -> dict[str, Any]:
    """Manually discard a staged contract (admin override)."""
    found = await invalidate_staged_contract(tenant_id, reason="admin_discard")
    if not found:
        raise HTTPException(
            status_code=404,
            detail=f"No staged contract found for tenant {tenant_id!r}",
        )
    return {"status": "discarded", "tenant_id": tenant_id}


# ---------------------------------------------------------------------------
# Accuracy
# ---------------------------------------------------------------------------

@router.get("/accuracy")
async def get_prediction_accuracy(
    window_hours: Annotated[int, Query(ge=1, le=720)] = 24,
    _user: Any = Depends(require_read_only),
) -> dict[str, Any]:
    """
    Return prediction accuracy metrics for the given time window.
    Includes per-signal-type breakdown and latency savings.
    """
    return await get_accuracy_metrics(window_hours=window_hours)


@router.get("/accuracy/history")
async def get_prediction_history(
    tenant_id: Annotated[str | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    _user: Any = Depends(require_billing_admin),
) -> dict[str, Any]:
    """Return raw prediction history records."""
    history = await get_accuracy_history(tenant_id=tenant_id, limit=limit)
    return {"count": len(history), "records": history}


# ---------------------------------------------------------------------------
# On-demand scan
# ---------------------------------------------------------------------------

@router.post("/scan/{tenant_id}")
async def scan_tenant(
    tenant_id: str,
    _user: Any = Depends(require_billing_admin),
) -> dict[str, Any]:
    """
    Trigger an immediate predictive scan for one tenant.
    Generates a staged contract if a high-confidence signal is found.
    """
    results = await run_for_tenant(tenant_id)
    if results:
        return {"status": "staged", "tenant_id": tenant_id, "contracts": results}
    return {"status": "no_action", "tenant_id": tenant_id, "reason": "no actionable signals"}


@router.post("/scan-all")
async def scan_all_tenants(
    _user: Any = Depends(require_super_admin),
) -> dict[str, Any]:
    """Trigger a full predictive scan across all tenants (super_admin only)."""
    summary = await run_all_tenants()
    return {"status": "ok", **summary}
