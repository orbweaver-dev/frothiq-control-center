"""
Unified Envelope routes — full envelope view, diff, history, batch verification.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from frothiq_control_center.auth import TokenPayload, require_read_only, require_security_analyst
from frothiq_control_center.services import (
    get_envelope_diff,
    get_envelope_history,
    get_tenant_envelope,
    verify_all_envelopes,
)
from frothiq_control_center.services.core_client import CoreClientError
from fastapi import HTTPException

from pydantic import BaseModel


class BatchVerifyRequest(BaseModel):
    tenant_ids: list[str]


router = APIRouter(prefix="/envelope", tags=["envelope"])


@router.get("/{tenant_id}")
async def get_envelope(
    tenant_id: str,
    bypass_cache: bool = Query(False),
    _: TokenPayload = Depends(require_read_only),
):
    """Fetch the full Unified Envelope for a tenant."""
    return await get_tenant_envelope(tenant_id, bypass_cache=bypass_cache)


@router.get("/{tenant_id}/history")
async def envelope_history(
    tenant_id: str,
    _: TokenPayload = Depends(require_read_only),
):
    """Fetch envelope version history for a tenant."""
    return await get_envelope_history(tenant_id)


@router.get("/{tenant_id}/diff")
async def envelope_diff(
    tenant_id: str,
    from_version: str = Query(..., description="Source version"),
    to_version: str = Query(..., description="Target version"),
    _: TokenPayload = Depends(require_security_analyst),
):
    """Compute a structural diff between two envelope versions."""
    try:
        return await get_envelope_diff(tenant_id, from_version, to_version)
    except CoreClientError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail)


@router.post("/verify-batch")
async def batch_verify(
    payload: BatchVerifyRequest,
    _: TokenPayload = Depends(require_security_analyst),
):
    """Verify envelope signatures for a batch of tenants."""
    return await verify_all_envelopes(payload.tenant_ids)
