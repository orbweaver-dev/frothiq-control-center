"""
Edge Node API routes.

Public (no auth):
  POST /api/v1/edge/register        — plugin self-registration

Protected (JWT required, served under /api/v1/cc/):
  GET  /api/v1/cc/edge/nodes        — list all registered edge nodes
  GET  /api/v1/cc/edge/tenants      — list all edge tenants
  GET  /api/v1/cc/edge/stats        — registration statistics
  GET  /api/v1/cc/system/flags      — get all feature flags
  POST /api/v1/cc/system/flags/{key} — set a feature flag (super_admin only)
"""

from __future__ import annotations

import hashlib
import hmac
import time
import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, field_validator

from frothiq_control_center.auth.jwt_handler import TokenPayload, get_current_user, require_role
from frothiq_control_center.services.edge_service import (
    get_feature_flags,
    get_registration_stats,
    list_edge_nodes,
    list_edge_tenants,
    register_edge_node,
    set_feature_flag,
)

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Public registration router (no /api/v1/cc prefix — served at /api/v1/edge/)
# ─────────────────────────────────────────────────────────────────────────────

public_router = APIRouter(prefix="/api/v1/edge", tags=["edge-public"])


class EdgeRegisterRequest(BaseModel):
    domain: str = Field(..., min_length=3, max_length=253, description="Customer site domain")
    edge_id: str = Field(..., min_length=8, max_length=128, description="Unique edge node identifier")
    plugin_version: str = Field(..., max_length=32)
    platform: str = Field(..., max_length=64, description="wordpress|frappe|joomla|custom")

    @field_validator("platform")
    @classmethod
    def platform_allowed(cls, v: str) -> str:
        allowed = {"wordpress", "frappe", "joomla", "custom", "shopify", "magento", "drupal"}
        if v.lower() not in allowed:
            raise ValueError(f"platform must be one of: {', '.join(sorted(allowed))}")
        return v.lower()

    @field_validator("domain")
    @classmethod
    def clean_domain(cls, v: str) -> str:
        # Strip protocol and trailing slashes
        return v.lower().replace("https://", "").replace("http://", "").strip("/")


@public_router.post("/register")
async def register_edge(body: EdgeRegisterRequest, request: Request) -> dict[str, Any]:
    """
    Self-registration endpoint for FrothIQ edge plugins.

    Idempotent — safe to call on every plugin boot.
    Auto-creates a tenant on first call for the domain.
    Assigns free plan by default. No payment or manual approval required.
    """
    client_ip = (
        request.headers.get("x-forwarded-for", "").split(",")[0].strip()
        or (request.client.host if request.client else "unknown")
    )
    logger.info(
        "edge.register: domain=%s edge_id=%s platform=%s version=%s ip=%s",
        body.domain, body.edge_id[:16], body.platform, body.plugin_version, client_ip,
    )

    result = await register_edge_node(
        domain=body.domain,
        edge_id=body.edge_id,
        plugin_version=body.plugin_version,
        platform=body.platform,
    )
    return {
        "ok": True,
        "tenant_id": result["tenant_id"],
        "license_token": result["license_token"],
        "plan": result["plan"],
        "edge_id": result["edge_id"],
        "node_state": result["node_state"],
        "feature_flags": result["feature_flags"],
        "enforcement_enabled": result["enforcement_enabled"],
        "registered_at": int(time.time()),
    }


# ─────────────────────────────────────────────────────────────────────────────
# Protected management router (included under /api/v1/cc/ prefix)
# ─────────────────────────────────────────────────────────────────────────────

protected_router = APIRouter(tags=["edge-management"])


@protected_router.get("/edge/nodes")
async def get_edge_nodes(
    limit: int = 100,
    offset: int = 0,
    platform: str | None = None,
    current_user: TokenPayload = Depends(require_role("read_only")),
) -> dict[str, Any]:
    """List all registered edge nodes. read_only+ required."""
    return await list_edge_nodes(limit=min(limit, 500), offset=offset, platform=platform)


@protected_router.get("/edge/tenants")
async def get_edge_tenants(
    limit: int = 100,
    offset: int = 0,
    current_user: TokenPayload = Depends(require_role("read_only")),
) -> dict[str, Any]:
    """List all edge tenants. read_only+ required."""
    return await list_edge_tenants(limit=min(limit, 500), offset=offset)


@protected_router.get("/edge/stats")
async def edge_stats(
    current_user: TokenPayload = Depends(require_role("read_only")),
) -> dict[str, Any]:
    """Edge node registration statistics for MC3 dashboard."""
    return await get_registration_stats()


@protected_router.get("/system/flags")
async def list_flags(
    current_user: TokenPayload = Depends(require_role("read_only")),
) -> dict[str, Any]:
    """Get all feature flags. read_only+ required."""
    flags = await get_feature_flags()
    return {"flags": flags}


class FlagUpdateRequest(BaseModel):
    value: bool


@protected_router.post("/system/flags/{flag_key}")
async def update_flag(
    flag_key: str,
    body: FlagUpdateRequest,
    current_user: TokenPayload = Depends(require_role("super_admin")),
) -> dict[str, Any]:
    """
    Set a feature flag. super_admin only.

    Allowed keys:
    - PLAN_ENFORCEMENT_ENABLED: activate/deactivate plan limits and paywalls
    - UPGRADE_SYSTEM_ENABLED: show/hide upgrade prompts and orchestration
    - REGISTRATION_ENABLED: accept/reject new edge registrations
    """
    allowed_keys = {
        "PLAN_ENFORCEMENT_ENABLED",
        "UPGRADE_SYSTEM_ENABLED",
        "REGISTRATION_ENABLED",
    }
    if flag_key not in allowed_keys:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown flag '{flag_key}'. Allowed: {sorted(allowed_keys)}",
        )
    user_email = current_user.sub  # sub = user_id
    return await set_feature_flag(flag_key, body.value, user_email)
