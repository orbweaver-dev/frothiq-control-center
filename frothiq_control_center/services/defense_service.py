"""
Defense Mesh service — global cluster views, propagation tracking, suggested actions.

The Control Center has super-admin scope; it can see all clusters across all
tenants (no tenant-scoped filtering applied here).
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

from .core_client import CoreClientError, core_client

logger = logging.getLogger(__name__)


async def get_all_clusters(bypass_cache: bool = False) -> dict[str, Any]:
    """
    Fetch all defense clusters (global, super-admin view).
    Falls back to partial data if core is degraded.
    """
    try:
        data = await core_client.get(
            "/api/v2/defense/clusters/all",
            bypass_cache=bypass_cache,
        )
        return {
            "success": True,
            "clusters": data.get("clusters", []),
            "total": data.get("total", len(data.get("clusters", []))),
            "engine_healthy": True,
            "last_refresh": datetime.now(UTC).isoformat(),
        }
    except CoreClientError as exc:
        logger.error("Defense cluster fetch failed: %s", exc.detail)
        return {
            "success": False,
            "clusters": [],
            "total": 0,
            "engine_healthy": False,
            "error": exc.detail,
            "last_refresh": datetime.now(UTC).isoformat(),
        }


async def get_cluster_detail(cluster_id: str) -> dict[str, Any]:
    """Fetch a single defense cluster by ID."""
    try:
        return await core_client.get(f"/api/v2/defense/cluster/{cluster_id}")
    except CoreClientError as exc:
        logger.error("Cluster detail fetch failed for %s: %s", cluster_id, exc.detail)
        raise


async def get_engine_status() -> dict[str, Any]:
    """Fetch defense engine status + freshness metrics."""
    try:
        return await core_client.get("/api/v2/defense/status")
    except CoreClientError as exc:
        logger.warning("Defense engine status unavailable: %s", exc.detail)
        return {"healthy": False, "error": exc.detail}


async def get_propagation_graph() -> dict[str, Any]:
    """
    Build a propagation graph showing how attack campaigns spread across tenants.
    Returns nodes (campaigns) and edges (propagation paths).
    """
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
                "severity": cluster.get("severity", "unknown"),
            })

            for cid in campaign_ids:
                edges.append({
                    "source": cid,
                    "target": cluster_id,
                    "type": "member_of",
                })

        return {
            "nodes": nodes,
            "edges": edges,
            "cluster_count": len(clusters),
        }

    except CoreClientError as exc:
        logger.error("Propagation graph failed: %s", exc.detail)
        return {"nodes": [], "edges": [], "error": exc.detail}


async def get_suggested_actions() -> list[dict[str, Any]]:
    """
    Derive suggested actions from active defense clusters.
    Returns a prioritized list of recommended defenses.
    """
    try:
        clusters_data = await core_client.get("/api/v2/defense/clusters/all")
        clusters = clusters_data.get("clusters", [])

        actions = []
        for cluster in clusters:
            if cluster.get("auto_apply_eligible") and cluster.get("action"):
                actions.append({
                    "cluster_id": cluster.get("cluster_id"),
                    "action": cluster.get("action"),
                    "severity": cluster.get("severity", "medium"),
                    "affected_campaigns": len(cluster.get("campaign_ids", [])),
                    "priority": _severity_to_priority(cluster.get("severity", "medium")),
                })

        # Sort by priority descending
        actions.sort(key=lambda a: a["priority"], reverse=True)
        return actions

    except CoreClientError as exc:
        logger.error("Suggested actions fetch failed: %s", exc.detail)
        return []


def _severity_to_priority(severity: str) -> int:
    return {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(severity, 0)
