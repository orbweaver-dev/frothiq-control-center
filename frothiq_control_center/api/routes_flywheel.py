"""
Flywheel Intelligence routes — correlation heatmap, reinforcement vectors, optimization.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends

from frothiq_control_center.auth import TokenPayload, require_read_only, require_security_analyst
from frothiq_control_center.services import (
    get_correlation_heatmap,
    get_flywheel_dashboard,
    get_flywheel_state,
    get_optimization_suggestions,
    get_reinforcement_vectors,
)

router = APIRouter(prefix="/flywheel", tags=["flywheel"])


@router.get("/dashboard")
async def flywheel_dashboard(_: TokenPayload = Depends(require_read_only)):
    """Full Flywheel Intelligence dashboard aggregate."""
    return await get_flywheel_dashboard()


@router.get("/state")
async def flywheel_state(_: TokenPayload = Depends(require_read_only)):
    """Current Flywheel state from the orchestration engine."""
    return await get_flywheel_state()


@router.get("/correlations")
async def correlation_heatmap(_: TokenPayload = Depends(require_read_only)):
    """
    Signal correlation heatmap between Flywheel dimensions.
    Suitable for rendering as a 2D heatmap in the UI.
    """
    return await get_correlation_heatmap()


@router.get("/vectors")
async def reinforcement_vectors(_: TokenPayload = Depends(require_security_analyst)):
    """Active reinforcement vectors driving autonomous improvements."""
    return {"vectors": await get_reinforcement_vectors()}


@router.get("/suggestions")
async def optimization_suggestions(_: TokenPayload = Depends(require_security_analyst)):
    """Operator-level optimization suggestions from Flywheel analysis."""
    return {"suggestions": await get_optimization_suggestions()}
