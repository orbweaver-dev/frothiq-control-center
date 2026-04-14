"""
License Authority routes — tenant license states, revocation, sync health.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status

from frothiq_control_center.auth import TokenPayload, require_read_only, require_super_admin
from frothiq_control_center.services import (
    force_sync,
    get_all_license_states,
    get_sync_health,
    get_tenant_license,
    restore_license,
    revoke_license,
)
from frothiq_control_center.services.core_client import CoreClientError
from frothiq_control_center.services.audit_service import log_action

from pydantic import BaseModel


class RevokeRequest(BaseModel):
    reason: str


router = APIRouter(prefix="/license", tags=["license"])


@router.get("/overview")
async def license_overview(_: TokenPayload = Depends(require_read_only)):
    """Full license overview — all tenants, statuses, sync health."""
    return await get_all_license_states()


@router.get("/sync-health")
async def sync_health(_: TokenPayload = Depends(require_read_only)):
    """Aggregate sync health across all tenants."""
    return await get_sync_health()


@router.get("/{tenant_id}")
async def tenant_license(
    tenant_id: str,
    _: TokenPayload = Depends(require_read_only),
):
    """Fetch license state for a specific tenant."""
    try:
        return await get_tenant_license(tenant_id)
    except CoreClientError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail)


@router.post("/{tenant_id}/revoke")
async def revoke_tenant_license(
    tenant_id: str,
    payload: RevokeRequest,
    request: Request,
    current_user: TokenPayload = Depends(require_super_admin),
):
    """
    Revoke a tenant's license immediately.
    CRITICAL: requires super_admin. Fully audited.
    This suspends all edge access for the tenant.
    """
    db = request.state.db
    redis = request.state.redis
    client_ip = request.client.host if request.client else None

    result = await revoke_license(tenant_id, payload.reason, current_user.sub)

    await log_action(
        action="license.revoke",
        user_id=current_user.sub,
        user_email=current_user.sub,
        resource=tenant_id,
        detail=f"Revoked license: {payload.reason}",
        ip_address=client_ip,
        status="success" if result.get("success") else "failure",
        db=db,
        redis=redis,
    )

    if not result.get("success"):
        raise HTTPException(status_code=502, detail=result.get("error", "Revocation failed"))

    return result


@router.post("/{tenant_id}/restore")
async def restore_tenant_license(
    tenant_id: str,
    request: Request,
    current_user: TokenPayload = Depends(require_super_admin),
):
    """Restore a previously revoked tenant license. Requires super_admin."""
    db = request.state.db
    redis = request.state.redis
    client_ip = request.client.host if request.client else None

    result = await restore_license(tenant_id, current_user.sub)

    await log_action(
        action="license.restore",
        user_id=current_user.sub,
        user_email=current_user.sub,
        resource=tenant_id,
        detail="License restored",
        ip_address=client_ip,
        status="success" if result.get("success") else "failure",
        db=db,
        redis=redis,
    )

    if not result.get("success"):
        raise HTTPException(status_code=502, detail=result.get("error", "Restore failed"))

    return result


@router.post("/{tenant_id}/sync")
async def force_tenant_sync(
    tenant_id: str,
    request: Request,
    current_user: TokenPayload = Depends(require_super_admin),
):
    """Force an immediate license sync for a tenant."""
    db = request.state.db
    redis = request.state.redis

    result = await force_sync(tenant_id)

    await log_action(
        action="license.force_sync",
        user_id=current_user.sub,
        user_email=current_user.sub,
        resource=tenant_id,
        db=db,
        redis=redis,
    )

    return result
