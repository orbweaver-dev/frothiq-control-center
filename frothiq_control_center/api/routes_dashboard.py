"""
Dashboard routes — system health ring, global threat level, key metrics.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Request

from frothiq_control_center.auth import TokenPayload, require_read_only
from frothiq_control_center.services import (
    core_client,
    get_all_clusters,
    get_all_license_states,
    get_active_policies,
    get_monetization_overview,
    get_simulation_status,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("/health")
async def system_health(
    request: Request,
    _: TokenPayload = Depends(require_read_only),
):
    """
    Full system health snapshot — core status, cluster counts,
    license health, threat level, and key indices.
    """
    (
        core_health,
        clusters_data,
        licenses_data,
        policies_data,
        monetization_data,
        sim_status,
    ) = await asyncio.gather(
        core_client.health_check(),
        get_all_clusters(),
        get_all_license_states(),
        get_active_policies(),
        get_monetization_overview(),
        get_simulation_status(),
        return_exceptions=True,
    )

    # Safely extract values (may be exceptions)
    def safe(val, default):
        return default if isinstance(val, Exception) else val

    core_health = safe(core_health, {"status": "offline"})
    clusters_data = safe(clusters_data, {"clusters": [], "total": 0, "engine_healthy": False})
    licenses_data = safe(licenses_data, {"total": 0, "active": 0, "suspended": 0})
    policies_data = safe(policies_data, {"total": 0, "active": 0})
    monetization_data = safe(monetization_data, {"revenue_pressure_index": 0.0})
    sim_status = safe(sim_status, {"healthy": False})

    clusters = clusters_data.get("clusters", [])
    threat_level = _compute_threat_level(clusters)
    instability = _compute_instability_index(clusters, licenses_data)

    tenants = licenses_data.get("tenants", [])
    active_tenants = sum(1 for t in tenants if t.get("status") == "active")

    return {
        "core_status": core_health.get("status", "offline"),
        "core_version": core_health.get("version"),
        "total_tenants": licenses_data.get("total", 0),
        "active_tenants": active_tenants,
        "defense_clusters": clusters_data.get("total", 0),
        "active_policies": policies_data.get("active", 0),
        "licenses_active": licenses_data.get("active", 0),
        "licenses_suspended": licenses_data.get("suspended", 0),
        "events_last_hour": core_health.get("events_last_hour", 0),
        "threat_level": threat_level,
        "instability_index": instability,
        "revenue_pressure_index": monetization_data.get("revenue_pressure_index", 0.0),
        "simulation_engine_healthy": sim_status.get("healthy", False) if isinstance(sim_status, dict) else False,
        "checked_at": datetime.now(UTC).isoformat(),
    }


@router.get("/metrics/summary")
async def metrics_summary(
    _: TokenPayload = Depends(require_read_only),
):
    """
    Quick summary metrics for the top-of-dashboard ring charts.
    Returns percentages and trend directions for key indicators.
    """
    licenses_data, clusters_data = await asyncio.gather(
        get_all_license_states(),
        get_all_clusters(),
        return_exceptions=True,
    )

    def safe(val, default):
        return default if isinstance(val, Exception) else val

    licenses_data = safe(licenses_data, {"total": 0, "active": 0, "suspended": 0})
    clusters_data = safe(clusters_data, {"total": 0, "clusters": []})

    total_licenses = max(licenses_data.get("total", 1), 1)
    active_licenses = licenses_data.get("active", 0)
    suspended_licenses = licenses_data.get("suspended", 0)

    total_clusters = clusters_data.get("total", 0)
    critical_clusters = sum(
        1 for c in clusters_data.get("clusters", [])
        if c.get("severity") in ("critical", "high")
    )

    return {
        "license_health_pct": round((active_licenses / total_licenses) * 100, 1),
        "cluster_critical_pct": round(
            (critical_clusters / max(total_clusters, 1)) * 100, 1
        ),
        "suspended_tenant_count": suspended_licenses,
        "total_clusters": total_clusters,
        "critical_clusters": critical_clusters,
    }


def _compute_threat_level(clusters: list) -> str:
    if not clusters:
        return "low"
    critical = sum(1 for c in clusters if c.get("severity") == "critical")
    high = sum(1 for c in clusters if c.get("severity") == "high")
    if critical > 0:
        return "critical"
    if high >= 3:
        return "high"
    if high >= 1:
        return "medium"
    return "low"


def _compute_instability_index(clusters: list, licenses_data: dict) -> float:
    """
    Composite instability index (0.0 = stable, 1.0 = highly unstable).
    Considers:
      - Ratio of critical/high clusters
      - Ratio of suspended licenses
    """
    cluster_score = 0.0
    if clusters:
        critical_high = sum(1 for c in clusters if c.get("severity") in ("critical", "high"))
        cluster_score = min(critical_high / len(clusters), 1.0)

    license_score = 0.0
    total = licenses_data.get("total", 0)
    if total:
        suspended = licenses_data.get("suspended", 0)
        license_score = min(suspended / total, 1.0)

    return round((cluster_score * 0.7 + license_score * 0.3), 3)
