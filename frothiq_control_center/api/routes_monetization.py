"""
Monetization routes — revenue signals, upgrade funnel, paywall analytics.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from frothiq_control_center.auth import TokenPayload, require_billing_admin, require_read_only
from frothiq_control_center.services import (
    get_monetization_overview,
    get_paywall_analytics,
    get_revenue_heatmap,
    get_upgrade_funnel,
)

router = APIRouter(prefix="/monetization", tags=["monetization"])


@router.get("/overview")
async def monetization_overview(_: TokenPayload = Depends(require_billing_admin)):
    """Full monetization overview — plan breakdown, RPI, upgrade signals."""
    return await get_monetization_overview()


@router.get("/upgrade-funnel")
async def upgrade_funnel(_: TokenPayload = Depends(require_billing_admin)):
    """
    Upgrade funnel analytics — tenants at each upgrade stage.
    Requires billing_admin role.
    """
    return await get_upgrade_funnel()


@router.get("/paywall")
async def paywall_analytics(_: TokenPayload = Depends(require_billing_admin)):
    """Paywall hit analytics — aggregate across all tenants."""
    return await get_paywall_analytics()


@router.get("/heatmap")
async def revenue_heatmap(
    period_days: int = Query(30, ge=1, le=365),
    _: TokenPayload = Depends(require_billing_admin),
):
    """Revenue pressure heatmap data by tenant."""
    return await get_revenue_heatmap(period_days=period_days)
