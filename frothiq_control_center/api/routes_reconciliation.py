"""
Reconciliation API — inspect drift, trigger reconciliation, query audit trail.

Endpoints:
  GET  /api/v1/cc/reconciliation/drift               — current drift across all tenants
  GET  /api/v1/cc/reconciliation/drift/{tenant_id}   — drift for one tenant
  POST /api/v1/cc/reconciliation/run/{tenant_id}     — on-demand reconcile one tenant
  POST /api/v1/cc/reconciliation/run-all             — on-demand full sweep (super_admin)
  GET  /api/v1/cc/reconciliation/audit               — audit log query
  GET  /api/v1/cc/reconciliation/health              — subsystem health + scheduler stats
  POST /api/v1/cc/reconciliation/edge/ack            — edge plugin ACK receiver
  GET  /api/v1/cc/reconciliation/edge/ack/{tenant_id} — ACK status for a tenant
"""

from __future__ import annotations

import time
from typing import Annotated, Any

from fastapi import APIRouter, Body, Depends, HTTPException, Query
from pydantic import BaseModel

from frothiq_control_center.auth import (
    require_billing_admin,
    require_read_only,
    require_super_admin,
)
from frothiq_control_center.billing.license_state_cache import (
    get_all_billing_states,
    get_billing_state,
)
from frothiq_control_center.reconciliation.drift_detector import (
    DriftReport,
    detect_drift,
    detect_all_drift,
)
from frothiq_control_center.reconciliation.edge_ack_tracker import (
    get_tenant_ack_status,
    record_ack,
)
from frothiq_control_center.reconciliation.reconciliation_audit_log import (
    get_log_stats,
    get_recent_log,
)
from frothiq_control_center.reconciliation.reconciliation_engine import (
    reconcile_all,
    reconcile_tenant,
)

router = APIRouter(prefix="/reconciliation", tags=["Reconciliation"])


# ---------------------------------------------------------------------------
# Drift inspection
# ---------------------------------------------------------------------------

@router.get("/drift")
async def get_all_drift(
    _user: Any = Depends(require_billing_admin),
) -> dict[str, Any]:
    """
    Return current drift status for all known tenants.
    Compares MC3 cache against a fresh ERPNext pull for each tenant.
    """
    from frothiq_control_center.billing.billing_sync_client import pull_tenant_state

    all_states = await get_all_billing_states()
    tenant_ids = [s["tenant_id"] for s in all_states]

    reports: list[DriftReport] = await detect_all_drift(
        tenant_ids=tenant_ids,
        erp_pull_fn=pull_tenant_state,
        mc3_read_fn=get_billing_state,
    )

    clean     = [tid for tid in tenant_ids if not any(r.tenant_id == tid for r in reports)]
    drifted   = list({r.tenant_id for r in reports})
    critical  = [r.as_dict() for r in reports if r.severity.value == "CRITICAL"]
    high      = [r.as_dict() for r in reports if r.severity.value == "HIGH"]
    other     = [r.as_dict() for r in reports if r.severity.value not in ("CRITICAL", "HIGH")]

    return {
        "total_tenants": len(tenant_ids),
        "clean":         len(clean),
        "drifted":       len(drifted),
        "critical_count": len(critical),
        "high_count":    len(high),
        "reports":       [r.as_dict() for r in reports],
        "checked_at":    time.time(),
    }


@router.get("/drift/{tenant_id}")
async def get_tenant_drift(
    tenant_id: str,
    _user: Any = Depends(require_read_only),
) -> dict[str, Any]:
    """Return drift status for a single tenant."""
    from frothiq_control_center.billing.billing_sync_client import pull_tenant_state

    mc3_state  = await get_billing_state(tenant_id)
    erp_state  = await pull_tenant_state(tenant_id)
    erp_usable = erp_state and erp_state.get("source") != "fallback"

    reports = detect_drift(
        tenant_id, mc3_state, erp_state if erp_usable else None
    )

    return {
        "tenant_id":      tenant_id,
        "drift_detected": len(reports) > 0,
        "erp_reachable":  erp_usable,
        "reports":        [r.as_dict() for r in reports],
        "mc3_state":      mc3_state,
        "erp_state":      erp_state if erp_usable else None,
        "checked_at":     time.time(),
    }


# ---------------------------------------------------------------------------
# On-demand reconciliation
# ---------------------------------------------------------------------------

class ReconcileRequest(BaseModel):
    edge_state: dict[str, Any] | None = None


@router.post("/run/{tenant_id}")
async def run_reconciliation(
    tenant_id: str,
    body: ReconcileRequest = Body(default=ReconcileRequest()),
    _user: Any = Depends(require_billing_admin),
) -> dict[str, Any]:
    """
    Trigger an immediate reconciliation for one tenant.
    Optionally accepts an edge heartbeat payload to check edge drift.
    """
    result = await reconcile_tenant(
        tenant_id=tenant_id,
        force=True,
        edge_state=body.edge_state,
    )
    return result.as_dict()


@router.post("/run-all")
async def run_reconciliation_all(
    _user: Any = Depends(require_super_admin),
) -> dict[str, Any]:
    """
    Trigger a full reconciliation sweep for all known tenants (super_admin only).
    This is a heavy operation — it will call ERPNext once per tenant.
    """
    all_states = await get_all_billing_states()
    tenant_ids = [s["tenant_id"] for s in all_states]

    if not tenant_ids:
        return {"total": 0, "message": "No tenants found"}

    summary = await reconcile_all(tenant_ids, concurrency=5)
    return {"status": "ok", **summary}


# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------

@router.get("/audit")
async def get_audit_log(
    tenant_id: Annotated[str | None, Query()] = None,
    event_type: Annotated[str | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
    _user: Any = Depends(require_read_only),
) -> dict[str, Any]:
    """
    Query the reconciliation audit log.
    Filterable by tenant_id and event_type.
    """
    entries = await get_recent_log(
        tenant_id=tenant_id,
        event_type=event_type,
        limit=limit,
        offset=offset,
    )
    stats = await get_log_stats()
    return {
        "entries":  entries,
        "count":    len(entries),
        "offset":   offset,
        "limit":    limit,
        "stats_24h": stats,
    }


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

@router.get("/health")
async def reconciliation_health(
    _user: Any = Depends(require_read_only),
) -> dict[str, Any]:
    """
    Return health of the reconciliation subsystem.
    Checks DB connectivity and reports recent audit stats.
    """
    db_ok = False
    tenant_count = 0
    try:
        all_states = await get_all_billing_states()
        db_ok = True
        tenant_count = len(all_states)
    except Exception:
        pass

    audit_stats = await get_log_stats()

    # Compute drift rate from audit stats (drifts per total events in 24h)
    by_type = audit_stats.get("by_event_type", {})
    total_events   = audit_stats.get("total", 0)
    drifts_24h     = by_type.get("drift_detected", 0)
    resolved_24h   = by_type.get("reconciled", 0)
    deferred_24h   = by_type.get("deferred", 0)
    edge_acks_24h  = by_type.get("edge_ack", 0)

    reconciliation_rate = (
        resolved_24h / drifts_24h if drifts_24h > 0 else 1.0
    )

    return {
        "status":               "healthy" if db_ok else "degraded",
        "db_ok":                db_ok,
        "tracked_tenants":      tenant_count,
        "metrics_24h": {
            "drifts_detected":    drifts_24h,
            "reconciled":         resolved_24h,
            "deferred":           deferred_24h,
            "edge_acks":          edge_acks_24h,
            "reconciliation_rate": round(reconciliation_rate, 3),
            "total_events":       total_events,
        },
        "checked_at": time.time(),
    }


# ---------------------------------------------------------------------------
# Edge ACK endpoints (called by edge plugins)
# ---------------------------------------------------------------------------

class EdgeAckPayload(BaseModel):
    tenant_id:        str
    edge_id:          str
    contract_version: int
    received_at:      float
    signature:        str | None = None


@router.post("/edge/ack")
async def receive_edge_ack(
    payload: EdgeAckPayload,
) -> dict[str, Any]:
    """
    Receive an acknowledgement from an edge plugin confirming it has applied
    the latest FederationContract.

    This endpoint is intentionally public (no JWT) because edge plugins
    authenticate via HMAC signature on the payload, not session tokens.
    """
    from frothiq_control_center.config import get_settings
    settings = get_settings()
    signing_secret = getattr(settings, "gateway_signing_key", "")

    result = await record_ack(
        tenant_id=payload.tenant_id,
        edge_id=payload.edge_id,
        contract_version=payload.contract_version,
        received_at=payload.received_at,
        signature=payload.signature,
        signing_secret=signing_secret if payload.signature else None,
    )
    return {"status": "ok", "ack": result}


@router.get("/edge/ack/{tenant_id}")
async def get_edge_ack_status(
    tenant_id: str,
    _user: Any = Depends(require_read_only),
) -> dict[str, Any]:
    """Return ACK status for all edge nodes of a tenant."""
    records = await get_tenant_ack_status(tenant_id)
    all_synced = all(r.get("in_sync") for r in records) if records else True
    return {
        "tenant_id":  tenant_id,
        "all_synced": all_synced,
        "nodes":      records,
    }
