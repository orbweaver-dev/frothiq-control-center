"""
Simulation Center routes — scenario runner, DAS/DEI/PPS metrics, alerts.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from frothiq_control_center.auth import TokenPayload, require_read_only, require_security_analyst
from frothiq_control_center.services import (
    get_alerts,
    get_metrics,
    get_recent_runs,
    get_run_detail,
    get_scenarios,
    get_simulation_center_overview,
    get_simulation_status,
    run_scenario,
)
from frothiq_control_center.services.core_client import CoreClientError
from frothiq_control_center.services.audit_service import log_action
from frothiq_control_center.models.schemas import SimulationRunRequest

router = APIRouter(prefix="/simulation", tags=["simulation"])


@router.get("/overview")
async def simulation_overview(_: TokenPayload = Depends(require_read_only)):
    """Full Simulation Center dashboard aggregate."""
    return await get_simulation_center_overview()


@router.get("/status")
async def simulation_status(_: TokenPayload = Depends(require_read_only)):
    """Simulation engine status and last run summary."""
    return await get_simulation_status()


@router.get("/scenarios")
async def list_scenarios(_: TokenPayload = Depends(require_read_only)):
    """List all available simulation scenarios."""
    return {"scenarios": await get_scenarios()}


@router.post("/run")
async def trigger_run(
    payload: SimulationRunRequest,
    request: Request,
    current_user: TokenPayload = Depends(require_security_analyst),
):
    """
    Trigger a simulation scenario run.
    Requires security_analyst role. Audited.
    """
    result = await run_scenario(
        scenario_id=payload.scenario_id,
        tenant_id=payload.tenant_id,
        parameters=payload.parameters,
        admin_user=current_user.sub,
    )

    await log_action(
        action="simulation.run",
        user_id=current_user.sub,
        user_email=current_user.sub,
        resource=payload.scenario_id,
        detail=f"Ran scenario {payload.scenario_id} for tenant {payload.tenant_id or 'global'}",
        ip_address=request.client.host if request.client else None,
        status="success" if result.get("success") else "failure",
        redis=request.state.redis,
    )

    if not result.get("success"):
        raise HTTPException(status_code=502, detail=result.get("error", "Simulation failed"))

    return result


@router.get("/runs")
async def recent_runs(
    limit: int = Query(20, ge=1, le=100),
    _: TokenPayload = Depends(require_read_only),
):
    """List recent simulation run results."""
    return {"runs": await get_recent_runs(limit=limit)}


@router.get("/runs/{sim_id}")
async def run_detail(
    sim_id: str,
    _: TokenPayload = Depends(require_read_only),
):
    """Get full result for a specific simulation run."""
    try:
        return await get_run_detail(sim_id)
    except CoreClientError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail)


@router.get("/metrics")
async def simulation_metrics(
    period_days: int = Query(7, ge=1, le=90),
    _: TokenPayload = Depends(require_read_only),
):
    """Rolling aggregate DAS / DEI / PPS metrics and trend arrays."""
    return await get_metrics(period_days=period_days)


@router.get("/alerts")
async def simulation_alerts(
    limit: int = Query(50, ge=1, le=200),
    _: TokenPayload = Depends(require_read_only),
):
    """Recent simulation threshold-breach alerts."""
    return {"alerts": await get_alerts(limit=limit)}
