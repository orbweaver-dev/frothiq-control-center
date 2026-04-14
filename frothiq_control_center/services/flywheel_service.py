"""
Flywheel Intelligence service — correlation heatmap, reinforcement vectors, optimization.

The Flywheel is the self-reinforcing feedback loop that connects:
  Defense signals → Policy updates → License enforcement → Revenue signals
  → Simulation results → back to Defense signals

The Control Center surfaces Flywheel state for operator visibility.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

from .core_client import CoreClientError, core_client

logger = logging.getLogger(__name__)


async def get_flywheel_state() -> dict[str, Any]:
    """
    Fetch current Flywheel state from the orchestration engine.
    """
    try:
        data = await core_client.get("/api/v2/agents/flywheel/state")
        return {"success": True, **data, "fetched_at": datetime.now(UTC).isoformat()}
    except CoreClientError as exc:
        logger.warning("Flywheel state unavailable: %s", exc.detail)
        return {
            "success": False,
            "error": exc.detail,
            "fetched_at": datetime.now(UTC).isoformat(),
        }


async def get_correlation_heatmap() -> dict[str, Any]:
    """
    Build a correlation heatmap between Flywheel signal dimensions.
    Dimensions: defense_signal, policy_update, license_event, revenue_signal, simulation_score
    """
    try:
        data = await core_client.get("/api/v2/agents/flywheel/correlations")
        return {
            "success": True,
            "dimensions": data.get("dimensions", _default_dimensions()),
            "matrix": data.get("matrix", []),
            "fetched_at": datetime.now(UTC).isoformat(),
        }
    except CoreClientError as exc:
        logger.warning("Correlation data unavailable: %s", exc.detail)
        # Return synthetic zero-correlation matrix so the UI doesn't break
        dims = _default_dimensions()
        return {
            "success": False,
            "dimensions": dims,
            "matrix": [[0.0] * len(dims) for _ in dims],
            "error": exc.detail,
            "fetched_at": datetime.now(UTC).isoformat(),
        }


async def get_reinforcement_vectors() -> list[dict[str, Any]]:
    """
    Fetch active reinforcement vectors — signals that are positively feeding
    back into the system and driving autonomous improvements.
    """
    try:
        data = await core_client.get("/api/v2/agents/flywheel/vectors")
        return data.get("vectors", [])
    except CoreClientError as exc:
        logger.warning("Reinforcement vectors unavailable: %s", exc.detail)
        return []


async def get_optimization_suggestions() -> list[dict[str, Any]]:
    """
    Fetch operator-level optimization suggestions derived from Flywheel analysis.
    These are high-level recommendations (not automated actions) for operators.
    """
    try:
        data = await core_client.get("/api/v2/agents/flywheel/suggestions")
        return data.get("suggestions", [])
    except CoreClientError as exc:
        logger.warning("Optimization suggestions unavailable: %s", exc.detail)
        return []


async def get_flywheel_dashboard() -> dict[str, Any]:
    """Full Flywheel Intelligence dashboard aggregate."""
    import asyncio

    state, heatmap, vectors, suggestions = await asyncio.gather(
        get_flywheel_state(),
        get_correlation_heatmap(),
        get_reinforcement_vectors(),
        get_optimization_suggestions(),
        return_exceptions=True,
    )

    return {
        "state": state if not isinstance(state, Exception) else {"success": False},
        "correlation_heatmap": heatmap if not isinstance(heatmap, Exception) else {},
        "reinforcement_vectors": vectors if not isinstance(vectors, Exception) else [],
        "optimization_suggestions": suggestions if not isinstance(suggestions, Exception) else [],
        "fetched_at": datetime.now(UTC).isoformat(),
    }


def _default_dimensions() -> list[str]:
    return [
        "defense_signal",
        "policy_update",
        "license_event",
        "revenue_signal",
        "simulation_score",
    ]
