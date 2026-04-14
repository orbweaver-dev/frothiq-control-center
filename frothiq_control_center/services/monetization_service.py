"""
Monetization service — revenue signals, upgrade funnel, paywall metrics.

BOUNDARY CONTRACT: Revenue Pressure Index computation, upgrade candidate
identification, conversion probability estimation, and funnel classification
are all business logic owned by frothiq-core. This service proxies core's
monetization endpoints and shapes them for operator UI consumption.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

from .core_client import CoreClientError, core_client

logger = logging.getLogger(__name__)


async def get_monetization_overview() -> dict[str, Any]:
    """
    Fetch monetization overview from frothiq-core.

    Prefers core's /api/v2/intelligence/monetization/overview.
    Falls back to assembling from core's tenant list — plan counts
    and upgrade candidates come from core fields only; no local RPI
    or conversion probability is computed.
    """
    # Prefer core's dedicated overview endpoint
    try:
        data = await core_client.get("/api/v2/intelligence/monetization/overview")
        return {
            "source": "frothiq-core",
            "fetched_at": datetime.now(UTC).isoformat(),
            **data,
        }
    except CoreClientError:
        pass

    # Fallback: assemble from core tenant list — core provides all fields
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

        # Use core's upgrade_candidate flag or utilization; never compute locally
        if t.get("upgrade_candidate") or t.get("upgrade_recommended"):
            upgrade_candidates.append({
                "tenant_id": t.get("tenant_id"),
                "plan": plan,
                # Use core-provided utilization; never compute active_sites/max_sites ratio here
                "utilization": t.get("utilization", t.get("site_utilization", 0.0)),
                "active_sites": t.get("active_sites", 0),
                "max_sites": t.get("max_sites", 1),
                "next_plan": t.get("next_plan", ""),
            })

    return {
        "source": "frothiq-core",
        "total_tenants": len(tenants),
        "plan_breakdown": plan_breakdown,
        # Core provides these counts; no local estimation
        "upgrade_signals_last_7d": tenants_data.get("upgrade_signals_last_7d", len(upgrade_candidates)),
        "paywall_hits_last_7d": tenants_data.get("paywall_hits_last_7d", 0),
        # Core provides RPI; never compute locally
        "revenue_pressure_index": tenants_data.get("revenue_pressure_index", 0.0),
        "top_upgrade_candidates": upgrade_candidates[:20],
        "fetched_at": datetime.now(UTC).isoformat(),
    }


async def get_upgrade_funnel() -> dict[str, Any]:
    """Fetch upgrade funnel analytics from frothiq-core."""
    try:
        return await core_client.get("/api/v2/intelligence/monetization/upgrade-funnel")
    except CoreClientError as exc:
        logger.warning("Upgrade funnel unavailable: %s", exc.detail)
        return {
            "error": exc.detail,
            "source": "frothiq-core",
        }


async def get_paywall_analytics() -> dict[str, Any]:
    """Fetch paywall hit analytics from frothiq-core."""
    try:
        data = await core_client.get("/api/v2/intelligence/paywall-stats")
        return {
            "success": True,
            "source": "frothiq-core",
            **data,
            "fetched_at": datetime.now(UTC).isoformat(),
        }
    except CoreClientError as exc:
        logger.warning("Paywall analytics unavailable: %s", exc.detail)
        return {
            "success": False,
            "source": "frothiq-core",
            "total_hits": 0,
            "unique_tenants": 0,
            "error": exc.detail,
            "fetched_at": datetime.now(UTC).isoformat(),
        }


async def get_revenue_heatmap(period_days: int = 30) -> dict[str, Any]:
    """Fetch revenue pressure heatmap from frothiq-core."""
    try:
        data = await core_client.get(
            "/api/v2/intelligence/monetization/revenue-heatmap",
            params={"period_days": period_days},
        )
        return {"source": "frothiq-core", "period_days": period_days, **data}
    except CoreClientError as exc:
        logger.error("Revenue heatmap failed: %s", exc.detail)
        return {
            "source": "frothiq-core",
            "period_days": period_days,
            "cells": [],
            "rpi": 0.0,
            "error": exc.detail,
        }
