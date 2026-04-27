"""
Rollback & Recovery Engine API routes.

  GET  /api/v1/cc/recovery/events           — recovery event log (filterable)
  GET  /api/v1/cc/recovery/stats            — 7-day summary counts
  POST /api/v1/cc/recovery/scan             — trigger manual recovery scan (super_admin)
  POST /api/v1/cc/recovery/node/{edge_id}   — manually recover a single node (super_admin)
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request

from frothiq_control_center.auth.jwt_handler import TokenPayload, get_current_user, require_role
from frothiq_control_center.services.rollback_recovery_engine import (
    get_recovery_stats,
    list_recovery_events,
    recover_node,
    run_recovery,
)

router = APIRouter(prefix="/recovery", tags=["recovery"])


@router.get("/events")
async def recovery_event_log(
    request: Request,
    recovery_type: str | None = None,
    status: str | None = None,
    limit: int = 100,
    offset: int = 0,
    current_user: TokenPayload = Depends(get_current_user),
):
    """Return paginated recovery event log."""
    return await list_recovery_events(
        recovery_type=recovery_type,
        status=status,
        limit=min(limit, 500),
        offset=offset,
    )


@router.get("/stats")
async def recovery_stats(
    request: Request,
    current_user: TokenPayload = Depends(get_current_user),
):
    """Return 7-day recovery action counts by type and status."""
    return await get_recovery_stats()


@router.post("/scan")
async def trigger_recovery_scan(
    request: Request,
    current_user: TokenPayload = Depends(require_role("super_admin")),
):
    """Manually trigger a full recovery scan cycle (super_admin only)."""
    result = await run_recovery()
    return {"status": "ok", **result}


@router.post("/node/{edge_id}")
async def manual_node_recovery(
    edge_id: str,
    request: Request,
    current_user: TokenPayload = Depends(require_role("super_admin")),
):
    """Manually reset a single edge node to ACTIVE state (super_admin only)."""
    try:
        result = await recover_node(edge_id, initiated_by=current_user.sub)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    return {"status": "recovered", **result}
