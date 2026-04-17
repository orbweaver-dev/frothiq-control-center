"""
License Authority service — tenant license state, revocation, sync health.

The Control Center is the operator authority for license management.
It communicates with frothiq-core to sync license state and can initiate
revocations that propagate to all edge plugins.

BOUNDARY CONTRACT: All status derivation and sync health evaluation
is delegated to frothiq-core. This service is a pass-through proxy only.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

from .core_client import CoreClientError, core_client

logger = logging.getLogger(__name__)


async def get_all_license_states() -> dict[str, Any]:
    """
    Fetch license states for all tenants from frothiq-core.

    frothiq-core is the source of truth; we pass its response through
    without any local status derivation or validation logic.
    """
    try:
        data = await core_client.get("/api/v2/internal/registry")
        tenants = data.get("tenants", [])

        # Aggregate counts from core-provided status fields — no local derivation
        summary: dict[str, Any] = {
            "total": len(tenants),
            "active": 0,
            "suspended": 0,
            "expired": 0,
            "trial": 0,
            "tenants": [],
        }

        for t in tenants:
            # Trust the `status` field from core; never derive it here
            status = t.get("license_status") or t.get("status", "active")
            if status in summary:
                summary[status] += 1

            summary["tenants"].append({
                "tenant_id": t.get("tenant_id"),
                "plan": t.get("plan", "free"),
                "status": status,
                "max_sites": t.get("max_sites", 1),
                "active_sites": t.get("active_sites", 0),
                "last_sync": t.get("last_sync"),
                # core provides sync_healthy; never compute it here
                "sync_healthy": t.get("sync_healthy", False),
            })

        return {
            "success": True,
            "source": "frothiq-core",
            **summary,
        }

    except CoreClientError as exc:
        logger.error("License state fetch failed: %s", exc.detail)
        return {"success": False, "total": 0, "tenants": [], "error": exc.detail}


async def get_tenant_license(tenant_id: str) -> dict[str, Any]:
    """Fetch license state for a specific tenant from frothiq-core."""
    try:
        return await core_client.get(f"/api/v2/internal/tenant/{tenant_id}")
    except CoreClientError as exc:
        logger.error("Tenant license fetch failed for %s: %s", tenant_id, exc.detail)
        raise


async def revoke_license(tenant_id: str, reason: str, admin_user: str) -> dict[str, Any]:
    """
    Revoke a tenant's license via frothiq-core.
    Critical action — requires super_admin role (enforced at route level).
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
    """Restore a previously revoked license via frothiq-core."""
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
    """Force an immediate license sync for a tenant via frothiq-core."""
    try:
        return await core_client.post(f"/api/v2/internal/tenant/{tenant_id}/sync")
    except CoreClientError as exc:
        return {"success": False, "error": exc.detail}


async def get_sync_health() -> dict[str, Any]:
    """
    Fetch sync health summary from frothiq-core.

    Prefers core's /api/v2/internal/sync-health endpoint.
    Falls back to aggregating tenant sync_healthy fields (still from core).
    """
    try:
        return await core_client.get("/api/v2/internal/sync-health")
    except CoreClientError:
        # Fallback: derive from tenant list (core-provided sync_healthy field)
        data = await get_all_license_states()
        tenants = data.get("tenants", [])
        healthy = sum(1 for t in tenants if t.get("sync_healthy"))
        degraded = len(tenants) - healthy
        return {
            "total": len(tenants),
            "sync_healthy": healthy,
            "sync_degraded": degraded,
            "health_pct": round((healthy / max(len(tenants), 1)) * 100, 1),
            "source": "frothiq-core",
        }
