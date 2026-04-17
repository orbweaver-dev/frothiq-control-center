"""
Policy Mesh service — policy lifecycle, distribution, version history, rollback.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

from .core_client import CoreClientError, core_client

logger = logging.getLogger(__name__)


async def get_active_policies(bypass_cache: bool = False) -> dict[str, Any]:
    """Fetch all active policies across all tenants (super-admin view)."""
    try:
        data = await core_client.get("/api/v2/policy/rules", bypass_cache=bypass_cache)
        policies = data.get("policies", [])
        return {
            "success": True,
            "total": len(policies),
            "active": sum(1 for p in policies if p.get("status") == "active"),
            "policies": policies,
        }
    except CoreClientError as exc:
        logger.error("Policy fetch failed: %s", exc.detail)
        return {"success": False, "total": 0, "active": 0, "policies": [], "error": exc.detail}


async def get_policy_detail(policy_id: str) -> dict[str, Any]:
    """Fetch a single policy with full lifecycle detail."""
    try:
        return await core_client.get(f"/api/v2/policy/{policy_id}")
    except CoreClientError as exc:
        logger.error("Policy detail fetch failed for %s: %s", policy_id, exc.detail)
        raise


async def get_policy_version_history(policy_id: str) -> list[dict[str, Any]]:
    """Fetch version history for a specific policy."""
    try:
        data = await core_client.get(f"/api/v2/policy/{policy_id}/versions")
        return data.get("versions", [])
    except CoreClientError as exc:
        logger.warning("Policy version history unavailable for %s: %s", policy_id, exc.detail)
        return []


async def rollback_policy(policy_id: str, version: int, admin_user: str) -> dict[str, Any]:
    """
    Roll back a policy to a specific version.
    Admin action — fully audited.
    """
    try:
        result = await core_client.post(
            f"/api/v2/policy/{policy_id}/rollback",
            body={"version": version, "initiated_by": admin_user},
        )
        logger.info("Policy %s rolled back to version %d by %s", policy_id, version, admin_user)
        return {"success": True, **result}
    except CoreClientError as exc:
        logger.error("Policy rollback failed: %s", exc.detail)
        return {"success": False, "error": exc.detail}


async def get_distribution_status(policy_id: str) -> dict[str, Any]:
    """Fetch distribution status — which tenants have received this policy version."""
    try:
        return await core_client.get(f"/api/v2/policy/{policy_id}/distribution")
    except CoreClientError as exc:
        logger.warning("Distribution status unavailable: %s", exc.detail)
        return {"distributed": 0, "pending": 0, "failed": 0, "error": exc.detail}


async def get_policy_mesh_overview() -> dict[str, Any]:
    """
    Build a comprehensive policy mesh overview for the Control Center dashboard.
    """
    active = await get_active_policies()
    return {
        "total_policies": active["total"],
        "active_policies": active["active"],
        "policies": active["policies"],
        "fetched_at": datetime.now(UTC).isoformat(),
    }
