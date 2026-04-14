"""
Tenant management routes — super-admin view of all tenants.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query

from frothiq_control_center.auth import TokenPayload, require_read_only, require_super_admin
from frothiq_control_center.services import core_client
from frothiq_control_center.services.core_client import CoreClientError

router = APIRouter(prefix="/tenants", tags=["tenants"])


@router.get("/")
async def list_tenants(
    plan: str | None = Query(None, description="Filter by plan (free/pro/enterprise)"),
    _: TokenPayload = Depends(require_read_only),
):
    """List all tenants with their configuration (super-admin view)."""
    try:
        data = await core_client.get("/api/v2/internal/tenants")
        tenants = data.get("tenants", [])
        if plan:
            tenants = [t for t in tenants if t.get("plan") == plan]
        return {"total": len(tenants), "tenants": tenants}
    except CoreClientError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail)


@router.get("/{tenant_id}")
async def get_tenant(
    tenant_id: str,
    _: TokenPayload = Depends(require_read_only),
):
    """Fetch full configuration for a specific tenant."""
    try:
        return await core_client.get(f"/api/v2/internal/tenant/{tenant_id}")
    except CoreClientError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail)


@router.post("/{tenant_id}/reload")
async def reload_tenant_config(
    tenant_id: str,
    _: TokenPayload = Depends(require_super_admin),
):
    """
    Force a hot-reload of tenant config in frothiq-core.
    Used after billing plan changes in Frappe propagate to core.
    Requires super_admin.
    """
    try:
        return await core_client.post(f"/api/v2/internal/tenant/{tenant_id}/reload")
    except CoreClientError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail)
