"""
Edge Node Integrity Score API routes.

All endpoints require a valid JWT (any authenticated role).

  GET /api/v1/cc/integrity            — fleet-level scores (paginated, filterable)
  GET /api/v1/cc/integrity/stats      — lightweight fleet summary for dashboard
  GET /api/v1/cc/integrity/{edge_id}  — single node score with component breakdown
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request

from frothiq_control_center.auth.jwt_handler import TokenPayload, get_current_user
from frothiq_control_center.services.integrity_service import (
    get_fleet_stats,
    score_fleet,
    score_node,
)

router = APIRouter(prefix="/integrity", tags=["integrity"])


@router.get("")
async def fleet_integrity(
    request: Request,
    state: str | None = None,
    grade: str | None = None,
    limit: int = 100,
    offset: int = 0,
    current_user: TokenPayload = Depends(get_current_user),
):
    """Return integrity scores for all active edge nodes."""
    return await score_fleet(
        state_filter=state,
        grade_filter=grade,
        limit=min(limit, 500),
        offset=offset,
    )


@router.get("/stats")
async def fleet_integrity_stats(
    request: Request,
    current_user: TokenPayload = Depends(get_current_user),
):
    """Lightweight fleet integrity summary for dashboard widgets."""
    return await get_fleet_stats()


@router.get("/{edge_id}")
async def node_integrity(
    edge_id: str,
    request: Request,
    current_user: TokenPayload = Depends(get_current_user),
):
    """Return the full integrity score breakdown for a single edge node."""
    result = await score_node(edge_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Edge node not found")
    return result
