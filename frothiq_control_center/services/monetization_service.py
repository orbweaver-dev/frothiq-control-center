"""
Monetization service — revenue signals, upgrade funnel, paywall metrics, billing visibility.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

from .core_client import CoreClientError, core_client

logger = logging.getLogger(__name__)


async def get_monetization_overview() -> dict[str, Any]:
    """
    Build a complete monetization overview for the Control Center dashboard.
    Aggregates plan distribution, upgrade signals, and paywall data.
    """
    try:
        tenants_data = await core_client.get("/api/v2/internal/tenants")
        tenants = tenants_data.get("tenants", [])
    except CoreClientError as exc:
        logger.error("Monetization data unavailable: %s", exc.detail)
        tenants = []

    plan_breakdown: dict[str, int] = {}
    upgrade_candidates = []

    for t in tenants:
        plan = t.get("plan", "free")
        plan_breakdown[plan] = plan_breakdown.get(plan, 0) + 1

        # Identify tenants close to plan limits (upgrade candidates)
        max_sites = t.get("max_sites", 1)
        active_sites = t.get("active_sites", 0)
        utilization = active_sites / max(max_sites, 1)

        if utilization >= 0.8 and plan != "enterprise":
            upgrade_candidates.append({
                "tenant_id": t.get("tenant_id"),
                "plan": plan,
                "utilization": round(utilization, 2),
                "active_sites": active_sites,
                "max_sites": max_sites,
                "next_plan": _next_plan(plan),
            })

    # Sort by utilization descending
    upgrade_candidates.sort(key=lambda x: x["utilization"], reverse=True)

    return {
        "total_tenants": len(tenants),
        "plan_breakdown": plan_breakdown,
        "upgrade_signals_last_7d": _estimate_upgrade_signals(tenants),
        "paywall_hits_last_7d": _estimate_paywall_hits(tenants),
        "revenue_pressure_index": _compute_rpi(plan_breakdown),
        "top_upgrade_candidates": upgrade_candidates[:20],
        "fetched_at": datetime.now(UTC).isoformat(),
    }


async def get_upgrade_funnel() -> dict[str, Any]:
    """
    Return upgrade funnel analytics — how many tenants are in each upgrade stage.
    """
    try:
        tenants_data = await core_client.get("/api/v2/internal/tenants")
        tenants = tenants_data.get("tenants", [])
    except CoreClientError:
        tenants = []

    funnel = {
        "free_to_pro_candidates": 0,
        "pro_to_enterprise_candidates": 0,
        "at_limit": 0,
        "comfortable": 0,
    }

    for t in tenants:
        max_sites = t.get("max_sites", 1)
        active_sites = t.get("active_sites", 0)
        plan = t.get("plan", "free")
        utilization = active_sites / max(max_sites, 1)

        if utilization >= 1.0:
            funnel["at_limit"] += 1
        elif utilization >= 0.8:
            if plan == "free":
                funnel["free_to_pro_candidates"] += 1
            elif plan == "pro":
                funnel["pro_to_enterprise_candidates"] += 1
        else:
            funnel["comfortable"] += 1

    return funnel


async def get_paywall_analytics() -> dict[str, Any]:
    """
    Aggregate paywall hit analytics across all tenants.
    Uses the frothiq-core intelligence endpoint if available.
    """
    try:
        data = await core_client.get("/api/v2/intelligence/paywall-stats")
        return {
            "success": True,
            **data,
            "fetched_at": datetime.now(UTC).isoformat(),
        }
    except CoreClientError as exc:
        logger.warning("Paywall analytics unavailable: %s", exc.detail)
        return {
            "success": False,
            "total_hits": 0,
            "unique_tenants": 0,
            "error": exc.detail,
            "fetched_at": datetime.now(UTC).isoformat(),
        }


async def get_revenue_heatmap(period_days: int = 30) -> dict[str, Any]:
    """
    Generate revenue pressure heatmap data by tenant.
    Each cell represents a tenant's revenue pressure level.
    """
    try:
        data = await get_monetization_overview()
        tenants = data.get("top_upgrade_candidates", [])

        heatmap = []
        for t in tenants:
            heatmap.append({
                "tenant_id": t["tenant_id"],
                "plan": t["plan"],
                "pressure": t["utilization"],  # 0.0 – 1.0
                "action": "upgrade" if t["utilization"] >= 0.9 else "monitor",
            })

        return {
            "period_days": period_days,
            "cells": heatmap,
            "rpi": data.get("revenue_pressure_index", 0.0),
        }
    except Exception as exc:
        logger.error("Revenue heatmap failed: %s", exc)
        return {"period_days": period_days, "cells": [], "rpi": 0.0}


def _next_plan(plan: str) -> str:
    return {"free": "pro", "pro": "enterprise"}.get(plan, "enterprise")


def _estimate_upgrade_signals(tenants: list[dict]) -> int:
    """Count tenants showing upgrade signals (>80% utilization, not enterprise)."""
    return sum(
        1 for t in tenants
        if t.get("plan") != "enterprise"
        and (t.get("active_sites", 0) / max(t.get("max_sites", 1), 1)) >= 0.8
    )


def _estimate_paywall_hits(tenants: list[dict]) -> int:
    """Count tenants at or over limit (paywall-triggering state)."""
    return sum(
        1 for t in tenants
        if t.get("active_sites", 0) >= t.get("max_sites", 1)
    )


def _compute_rpi(plan_breakdown: dict[str, int]) -> float:
    """
    Revenue Pressure Index — ratio of free-plan tenants to total.
    0.0 = all enterprise, 1.0 = all free.
    A high RPI means strong upgrade pressure exists.
    """
    total = sum(plan_breakdown.values())
    if not total:
        return 0.0
    free = plan_breakdown.get("free", 0)
    return round(free / total, 3)
