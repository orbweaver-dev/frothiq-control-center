"""
Anomaly Detection API routes.

All endpoints require a valid JWT (super_admin or security_analyst).

  GET  /api/v1/cc/anomalies          — list events (filterable)
  POST /api/v1/cc/anomalies/{id}/acknowledge — mark event acknowledged
  POST /api/v1/cc/anomalies/scan     — trigger manual scan (super_admin only)
  GET  /api/v1/cc/anomalies/stats    — summary counts by type and severity
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from frothiq_control_center.auth.jwt_handler import TokenPayload, get_current_user, require_role
from frothiq_control_center.services.anomaly_detection import (
    acknowledge_event,
    get_stats,
    list_events,
    run_scan,
)

router = APIRouter(prefix="/anomalies", tags=["anomaly-detection"])


class AcknowledgeRequest(BaseModel):
    acknowledged_by: str = ""


# ─────────────────────────────────────────────────────────────────────────────
# Endpoints
# ─────────────────────────────────────────────────────────────────────────────

@router.get("")
async def list_anomaly_events(
    request: Request,
    unacknowledged_only: bool = False,
    severity: str | None = None,
    anomaly_type: str | None = None,
    tenant_id: str | None = None,
    limit: int = 100,
    offset: int = 0,
    current_user: TokenPayload = Depends(get_current_user),
):
    """Return paginated anomaly events with optional filters."""
    return await list_events(
        unacknowledged_only=unacknowledged_only,
        severity=severity,
        anomaly_type=anomaly_type,
        tenant_id=tenant_id,
        limit=min(limit, 500),
        offset=offset,
    )


@router.get("/stats")
async def anomaly_stats(
    request: Request,
    current_user: TokenPayload = Depends(get_current_user),
):
    """Return open event counts grouped by type and severity (for dashboard widgets)."""
    return await get_stats()


@router.post("/scan")
async def trigger_scan(
    request: Request,
    current_user: TokenPayload = Depends(require_role("super_admin")),
):
    """Manually trigger an anomaly scan cycle (super_admin only)."""
    result = await run_scan()
    return {"status": "ok", **result}


@router.post("/{event_id}/acknowledge")
async def acknowledge_anomaly_event(
    event_id: str,
    body: AcknowledgeRequest,
    request: Request,
    current_user: TokenPayload = Depends(get_current_user),
):
    """Mark an anomaly event as acknowledged."""
    acknowledged_by = body.acknowledged_by or current_user.sub
    success = await acknowledge_event(event_id, acknowledged_by)
    if not success:
        raise HTTPException(status_code=404, detail="Event not found")
    return {"status": "acknowledged", "event_id": event_id, "acknowledged_by": acknowledged_by}
