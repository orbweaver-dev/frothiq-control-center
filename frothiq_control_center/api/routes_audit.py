"""
Audit log routes — paginated access to the admin action audit trail.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Request

from frothiq_control_center.auth import TokenPayload, require_security_analyst
from frothiq_control_center.services.audit_service import get_recent_audit_log

router = APIRouter(prefix="/audit", tags=["audit"])


@router.get("/log")
async def audit_log(
    request: Request,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    action: str | None = Query(None, description="Filter by action name substring"),
    user: str | None = Query(None, description="Filter by user email substring"),
    _: TokenPayload = Depends(require_security_analyst),
):
    """
    Paginated audit log of all admin actions.
    Requires security_analyst role or above.
    """
    db = request.state.db
    return await get_recent_audit_log(
        db=db,
        page=page,
        page_size=page_size,
        action_filter=action,
        user_filter=user,
    )
