"""
Policy Mesh routes — policy lifecycle, version history, rollback, distribution.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request

from frothiq_control_center.auth import TokenPayload, require_read_only, require_security_analyst
from frothiq_control_center.services import (
    get_active_policies,
    get_distribution_status,
    get_policy_detail,
    get_policy_mesh_overview,
    get_policy_version_history,
    rollback_policy,
)
from frothiq_control_center.services.core_client import CoreClientError
from frothiq_control_center.services.audit_service import log_action

from pydantic import BaseModel


class RollbackRequest(BaseModel):
    version: int


router = APIRouter(prefix="/policy", tags=["policy-mesh"])


@router.get("/overview")
async def policy_overview(_: TokenPayload = Depends(require_read_only)):
    """Full policy mesh overview for the dashboard."""
    return await get_policy_mesh_overview()


@router.get("/active")
async def active_policies(
    bypass_cache: bool = False,
    _: TokenPayload = Depends(require_read_only),
):
    """List all active policies across all tenants."""
    return await get_active_policies(bypass_cache=bypass_cache)


@router.get("/{policy_id}")
async def policy_detail(
    policy_id: str,
    _: TokenPayload = Depends(require_read_only),
):
    """Fetch full detail for a specific policy."""
    try:
        return await get_policy_detail(policy_id)
    except CoreClientError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail)


@router.get("/{policy_id}/versions")
async def policy_versions(
    policy_id: str,
    _: TokenPayload = Depends(require_read_only),
):
    """Fetch version history for a specific policy."""
    return await get_policy_version_history(policy_id)


@router.get("/{policy_id}/distribution")
async def policy_distribution(
    policy_id: str,
    _: TokenPayload = Depends(require_read_only),
):
    """Check which tenants have received the current policy version."""
    return await get_distribution_status(policy_id)


@router.post("/{policy_id}/rollback")
async def rollback_policy_endpoint(
    policy_id: str,
    payload: RollbackRequest,
    request: Request,
    current_user: TokenPayload = Depends(require_security_analyst),
):
    """
    Roll back a policy to a specific version.
    Requires security_analyst role. Fully audited.
    """
    redis = request.state.redis
    result = await rollback_policy(policy_id, payload.version, current_user.sub)

    await log_action(
        action="policy.rollback",
        user_id=current_user.sub,
        user_email=current_user.sub,
        resource=policy_id,
        detail=f"Rolled back to version {payload.version}",
        ip_address=request.client.host if request.client else None,
        status="success" if result.get("success") else "failure",
        redis=redis,
    )

    if not result.get("success"):
        raise HTTPException(status_code=502, detail=result.get("error", "Rollback failed"))

    return result
