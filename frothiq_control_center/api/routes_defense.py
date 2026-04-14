"""
Defense Mesh routes — global cluster view, propagation graph, suggested actions.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from frothiq_control_center.auth import TokenPayload, require_read_only, require_security_analyst
from frothiq_control_center.services import (
    get_all_clusters,
    get_cluster_detail,
    get_engine_status,
    get_propagation_graph,
    get_suggested_actions,
)
from frothiq_control_center.services.core_client import CoreClientError
from frothiq_control_center.services.audit_service import log_action

router = APIRouter(prefix="/defense", tags=["defense-mesh"])


@router.get("/clusters")
async def list_clusters(
    bypass_cache: bool = Query(False, description="Force fresh fetch from frothiq-core"),
    _: TokenPayload = Depends(require_read_only),
):
    """List all global defense clusters (super-admin, no tenant filtering)."""
    return await get_all_clusters(bypass_cache=bypass_cache)


@router.get("/clusters/{cluster_id}")
async def cluster_detail(
    cluster_id: str,
    _: TokenPayload = Depends(require_read_only),
):
    """Get full detail for a specific defense cluster."""
    try:
        return await get_cluster_detail(cluster_id)
    except CoreClientError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail)


@router.get("/status")
async def engine_status(_: TokenPayload = Depends(require_read_only)):
    """Defense engine health and freshness metrics."""
    return await get_engine_status()


@router.get("/propagation")
async def propagation_graph(_: TokenPayload = Depends(require_read_only)):
    """
    Attack propagation graph — nodes (clusters) and edges (campaign membership).
    Use this to render the propagation visualization in the UI.
    """
    return await get_propagation_graph()


@router.get("/suggested-actions")
async def suggested_actions(_: TokenPayload = Depends(require_security_analyst)):
    """
    Prioritized list of suggested defensive actions derived from active clusters.
    Requires security_analyst role or above.
    """
    return await get_suggested_actions()
