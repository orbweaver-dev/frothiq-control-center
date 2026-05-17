"""
Simulation service — DAS / DEI / PPS metrics, scenario runner, trend analysis.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

from .core_client import CoreClientError, core_client

logger = logging.getLogger(__name__)


async def get_simulation_status() -> dict[str, Any]:
    """Fetch simulation engine status and last run summary."""
    try:
        return await core_client.get("/api/v2/simulation/status")
    except CoreClientError as exc:
        logger.warning("Simulation status unavailable: %s", exc.detail)
        return {"healthy": False, "error": exc.detail}


async def get_scenarios() -> list[dict[str, Any]]:
    """List all available simulation scenarios."""
    try:
        data = await core_client.get("/api/v2/simulation/scenarios")
        return data.get("scenarios", [])
    except CoreClientError as exc:
        logger.warning("Scenarios unavailable: %s", exc.detail)
        return []


async def run_scenario(
    scenario_id: str,
    tenant_id: str | None,
    parameters: dict[str, Any],
    admin_user: str,
) -> dict[str, Any]:
    """
    Trigger a simulation scenario run.
    Requires security_analyst role at minimum (enforced at route level).
    """
    body: dict[str, Any] = {
        "scenario_id": scenario_id,
        "initiated_by": admin_user,
        "parameters": parameters,
    }
    if tenant_id:
        body["tenant_id"] = tenant_id

    try:
        result = await core_client.post("/api/v2/simulation/run", body=body)
        logger.info("Simulation run triggered: scenario=%s by %s", scenario_id, admin_user)
        return {"success": True, **result}
    except CoreClientError as exc:
        logger.error("Simulation run failed: %s", exc.detail)
        return {"success": False, "error": exc.detail}


async def get_recent_runs(limit: int = 20) -> list[dict[str, Any]]:
    """Fetch recent simulation run results."""
    try:
        data = await core_client.get("/api/v2/simulation/runs", params={"limit": limit})
        return data.get("runs", [])
    except CoreClientError as exc:
        logger.warning("Recent runs unavailable: %s", exc.detail)
        return []


async def get_run_detail(sim_id: str) -> dict[str, Any]:
    """Fetch full result for a specific simulation run."""
    try:
        return await core_client.get(f"/api/v2/simulation/runs/{sim_id}")
    except CoreClientError as exc:
        logger.error("Run detail fetch failed for %s: %s", sim_id, exc.detail)
        raise


async def get_metrics(period_days: int = 7) -> dict[str, Any]:
    """
    Fetch rolling aggregate simulation metrics (DAS, DEI, PPS).
    Returns trend arrays suitable for charting.
    """
    try:
        data = await core_client.get(
            "/api/v2/simulation/metrics",
            params={"period_days": period_days},
        )
        return {
            "success": True,
            "das_avg": data.get("das_avg", 0.0),
            "dei_avg": data.get("dei_avg", 0.0),
            "pps_avg": data.get("pps_avg", 0.0),
            "das_trend": data.get("das_trend", []),
            "dei_trend": data.get("dei_trend", []),
            "pps_trend": data.get("pps_trend", []),
            "period_days": period_days,
        }
    except CoreClientError as exc:
        logger.warning("Simulation metrics unavailable: %s", exc.detail)
        return {
            "success": False,
            "das_avg": 0.0,
            "dei_avg": 0.0,
            "pps_avg": 0.0,
            "das_trend": [],
            "dei_trend": [],
            "pps_trend": [],
            "period_days": period_days,
            "error": exc.detail,
        }


async def get_alerts(limit: int = 50) -> list[dict[str, Any]]:
    """Fetch recent simulation threshold-breach alerts."""
    try:
        data = await core_client.get("/api/v2/simulation/alerts", params={"limit": limit})
        return data.get("alerts", [])
    except CoreClientError as exc:
        logger.warning("Simulation alerts unavailable: %s", exc.detail)
        return []


async def get_simulation_center_overview() -> dict[str, Any]:
    """Aggregate view for the Simulation Center dashboard panel."""
    status, scenarios, metrics, alerts = await _gather(
        get_simulation_status(),
        get_scenarios(),
        get_metrics(period_days=7),
        get_alerts(limit=10),
    )
    return {
        "engine_status": status,
        "scenario_count": len(scenarios),
        "scenarios": scenarios,
        "metrics": metrics,
        "recent_alerts": alerts,
        "fetched_at": datetime.now(UTC).isoformat(),
    }


async def _gather(*coros) -> list[Any]:
    """Run coroutines concurrently, returning results in order."""
    import asyncio
    return list(await asyncio.gather(*coros, return_exceptions=True))
