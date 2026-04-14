"""
License Authority service — tenant license state, revocation, sync health.

The Control Center is the operator authority for license management.
It communicates with frothiq-core to sync license state and can initiate
revocations that propagate to all edge plugins.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

from .core_client import CoreClientError, core_client

logger = logging.getLogger(__name__)


async def get_all_license_states() -> dict[str, Any]:
    """
    Fetch license states for all tenants.
    Returns structured overview for the Control Center license panel.
    """
    try:
        data = await core_client.get("/api/v2/internal/tenants")
        tenants = data.get("tenants", [])

        summary = {
            "total": len(tenants),
            "active": 0,
            "suspended": 0,
            "expired": 0,
            "trial": 0,
            "tenants": [],
        }

        for t in tenants:
            status = _derive_license_status(t)
            summary[status] = summary.get(status, 0) + 1
            summary["tenants"].append({
                "tenant_id": t.get("tenant_id"),
                "plan": t.get("plan", "free"),
                "status": status,
                "max_sites": t.get("max_sites", 1),
                "active_sites": t.get("active_sites", 0),
                "last_sync": t.get("last_sync"),
                "sync_healthy": _is_sync_healthy(t),
            })

        return {"success": True, **summary}

    except CoreClientError as exc:
        logger.error("License state fetch failed: %s", exc.detail)
        return {"success": False, "total": 0, "tenants": [], "error": exc.detail}


async def get_tenant_license(tenant_id: str) -> dict[str, Any]:
    """Fetch license state for a specific tenant."""
    try:
        return await core_client.get(f"/api/v2/internal/tenant/{tenant_id}")
    except CoreClientError as exc:
        logger.error("Tenant license fetch failed for %s: %s", tenant_id, exc.detail)
        raise


async def revoke_license(tenant_id: str, reason: str, admin_user: str) -> dict[str, Any]:
    """
    Revoke a tenant's license. This immediately suspends all their edge access.
    Critical action — requires super_admin role (enforced at the route level).
    """
    try:
        result = await core_client.post(
            f"/api/v2/internal/tenant/{tenant_id}/revoke",
            body={
                "reason": reason,
                "revoked_by": admin_user,
                "revoked_at": datetime.now(UTC).isoformat(),
            },
        )
        logger.warning(
            "License REVOKED for tenant %s by admin %s — reason: %s",
            tenant_id, admin_user, reason,
        )
        return {"success": True, "tenant_id": tenant_id, **result}
    except CoreClientError as exc:
        logger.error("License revocation failed for %s: %s", tenant_id, exc.detail)
        return {"success": False, "tenant_id": tenant_id, "error": exc.detail}


async def restore_license(tenant_id: str, admin_user: str) -> dict[str, Any]:
    """Restore a previously revoked license."""
    try:
        result = await core_client.post(
            f"/api/v2/internal/tenant/{tenant_id}/restore",
            body={"restored_by": admin_user, "restored_at": datetime.now(UTC).isoformat()},
        )
        logger.info("License restored for tenant %s by admin %s", tenant_id, admin_user)
        return {"success": True, "tenant_id": tenant_id, **result}
    except CoreClientError as exc:
        logger.error("License restore failed for %s: %s", tenant_id, exc.detail)
        return {"success": False, "tenant_id": tenant_id, "error": exc.detail}


async def force_sync(tenant_id: str) -> dict[str, Any]:
    """Force an immediate license sync for a tenant."""
    try:
        return await core_client.post(f"/api/v2/internal/tenant/{tenant_id}/sync")
    except CoreClientError as exc:
        return {"success": False, "error": exc.detail}


async def get_sync_health() -> dict[str, Any]:
    """
    Check sync health across all tenants.
    Returns counts of healthy, degraded, and failed sync states.
    """
    data = await get_all_license_states()
    tenants = data.get("tenants", [])
    healthy = sum(1 for t in tenants if t.get("sync_healthy"))
    degraded = len(tenants) - healthy
    return {
        "total": len(tenants),
        "sync_healthy": healthy,
        "sync_degraded": degraded,
        "health_pct": round((healthy / max(len(tenants), 1)) * 100, 1),
    }


def _derive_license_status(tenant: dict[str, Any]) -> str:
    """Derive a license status from tenant config fields."""
    if tenant.get("suspended"):
        return "suspended"
    if tenant.get("expired"):
        return "expired"
    if tenant.get("plan") == "trial":
        return "trial"
    return "active"


def _is_sync_healthy(tenant: dict[str, Any]) -> bool:
    """Check if a tenant's edge sync is within acceptable bounds."""
    last_sync = tenant.get("last_sync")
    if not last_sync:
        return False
    # Consider unhealthy if last sync > 24 hours ago
    try:
        from datetime import timezone
        if isinstance(last_sync, str):
            from datetime import datetime
            last = datetime.fromisoformat(last_sync.replace("Z", "+00:00"))
            delta = (datetime.now(timezone.utc) - last).total_seconds()
            return delta < 86400
    except Exception:
        pass
    return True
