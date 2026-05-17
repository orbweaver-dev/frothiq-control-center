"""
Defense Mesh service — global cluster views, propagation tracking, suggested actions.

BOUNDARY CONTRACT: All severity prioritization, action eligibility evaluation,
and cluster scoring must come from frothiq-core. This service is a structured
proxy — it shapes responses for the operator UI but never derives defense logic.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

from .core_client import CoreClientError, core_client

logger = logging.getLogger(__name__)


async def get_all_clusters(bypass_cache: bool = False) -> dict[str, Any]:
    """
    Fetch all defense clusters from frothiq-core (global, super-admin view).
    Falls back to partial data if core is degraded.
    """
    try:
        data = await core_client.get(
            "/api/v2/defense/clusters/all",
            bypass_cache=bypass_cache,
        )
        return {
            "success": True,
            "source": "frothiq-core",
            "clusters": data.get("clusters", []),
            "total": data.get("total", len(data.get("clusters", []))),
            "engine_healthy": True,
            "last_refresh": datetime.now(UTC).isoformat(),
        }
    except CoreClientError as exc:
        logger.error("Defense cluster fetch failed: %s", exc.detail)
        return {
            "success": False,
            "source": "frothiq-core",
            "clusters": [],
            "total": 0,
            "engine_healthy": False,
            "error": exc.detail,
            "last_refresh": datetime.now(UTC).isoformat(),
        }


async def get_cluster_detail(cluster_id: str) -> dict[str, Any]:
    """Fetch a single defense cluster by ID from frothiq-core."""
    try:
        return await core_client.get(f"/api/v2/defense/cluster/{cluster_id}")
    except CoreClientError as exc:
        logger.error("Cluster detail fetch failed for %s: %s", cluster_id, exc.detail)
        raise


async def get_engine_status() -> dict[str, Any]:
    """Fetch defense engine status from frothiq-core."""
    try:
        return await core_client.get("/api/v2/defense/status")
    except CoreClientError as exc:
        logger.warning("Defense engine status unavailable: %s", exc.detail)
        return {"healthy": False, "error": exc.detail, "source": "frothiq-core"}


async def get_propagation_graph() -> dict[str, Any]:
    """
    Fetch propagation graph from frothiq-core.

    Prefers the core's native propagation-graph endpoint.
    Falls back to building node/edge topology from the cluster list only
    if core does not expose a dedicated graph endpoint — topology mapping
    (cluster → campaign membership) is pure structural data, not scoring.
    """
    # Prefer core's dedicated endpoint
    try:
        data = await core_client.get("/api/v2/defense/propagation-graph")
        return {"source": "frothiq-core", **data}
    except CoreClientError:
        pass

    # Fallback: build structural graph from cluster list (no scoring/logic)
    try:
        clusters_data = await core_client.get("/api/v2/defense/clusters/all")
        clusters = clusters_data.get("clusters", [])

        nodes = []
        edges = []

        for cluster in clusters:
            cluster_id = cluster.get("cluster_id", "")
            campaign_ids = cluster.get("campaign_ids", [])

            nodes.append({
                "id": cluster_id,
                "type": "cluster",
                "label": f"Cluster {cluster_id[:8]}",
                "campaign_count": len(campaign_ids),
                # Pass severity through from core; never re-derive it here
                "severity": cluster.get("severity", "unknown"),
            })

            for cid in campaign_ids:
                edges.append({
                    "source": cid,
                    "target": cluster_id,
                    "type": "member_of",
                })

        return {
            "source": "frothiq-core",
            "nodes": nodes,
            "edges": edges,
            "cluster_count": len(clusters),
        }

    except CoreClientError as exc:
        logger.error("Propagation graph failed: %s", exc.detail)
        return {"source": "frothiq-core", "nodes": [], "edges": [], "error": exc.detail}


async def get_suggested_actions() -> list[dict[str, Any]]:
    """
    Fetch suggested defense actions from frothiq-core.

    Prefers the core's /api/v2/defense/suggested-actions endpoint.
    Falls back to filtering core cluster data by auto_apply_eligible — no
    priority scoring is computed here; priority comes from core's fields.
    """
    # Prefer core's dedicated endpoint
    try:
        data = await core_client.get("/api/v2/defense/suggested-actions")
        actions = data if isinstance(data, list) else data.get("actions", [])
        return actions
    except CoreClientError:
        pass

    # Fallback: filter clusters by core's auto_apply_eligible flag
    try:
        clusters_data = await core_client.get("/api/v2/defense/clusters/all")
        clusters = clusters_data.get("clusters", [])

        actions = [
            {
                "cluster_id": c.get("cluster_id"),
                "action": c.get("action"),
                "severity": c.get("severity", "medium"),
                "affected_campaigns": len(c.get("campaign_ids", [])),
                # Use core's priority field; never compute locally
                "priority": c.get("priority", 0),
            }
            for c in clusters
            if c.get("auto_apply_eligible") and c.get("action")
        ]

        # Sort by core-provided priority only
        actions.sort(key=lambda a: a["priority"], reverse=True)
        return actions

    except CoreClientError as exc:
        logger.error("Suggested actions fetch failed: %s", exc.detail)
        return []
