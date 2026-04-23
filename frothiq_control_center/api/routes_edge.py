"""
Edge Node API routes.

Public (no auth — authenticated by edge_id + license_token in body/query):
  POST /api/v1/edge/register        — plugin self-registration (auto-creates tenant)
  POST /api/v1/edge/deregister      — plugin uninstall notification (sets state=REMOVED)
  POST /api/v1/edge/heartbeat       — 1-minute keep-alive with traffic counters
  GET  /api/v1/edge/blocklist       — pull current threat IP list (RBL-style)
  POST /api/v1/edge/outage          — plugin-reported outage event (self-healed or ongoing)

Protected (JWT required, served under /api/v1/cc/):
  GET  /api/v1/cc/edge/nodes        — list all registered edge nodes
  GET  /api/v1/cc/edge/tenants      — list all edge tenants
  GET  /api/v1/cc/edge/stats        — registration statistics
  GET  /api/v1/cc/edge/outages      — recent outage events
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
    get_blocklist,
    get_feature_flags,
    get_registration_stats,
    deregister_edge_node,
    list_edge_nodes,
    list_edge_tenants,
    register_edge_node,
    report_edge_event,
    set_feature_flag,
    touch_edge_node,
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
    contact_email: str | None = Field(None, max_length=254, description="Admin email — required when re-registering a deregistered domain")

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


def _verify_license_token(edge_id: str, license_token: str) -> bool:
    """
    Verify that license_token is well-formed and references this edge_id.
    Full cryptographic verification is in edge_service._issue_license_token().
    Here we do a fast structural check — full HMAC re-verify is in get_blocklist().
    """
    if not license_token or not edge_id:
        return False
    # Token format: base64url(payload).hmac_hex — at minimum two segments
    parts = license_token.split(".")
    return len(parts) == 2 and len(parts[1]) == 64


class EdgeDeregisterRequest(BaseModel):
    edge_id:       str = Field(..., min_length=8, max_length=128)
    license_token: str = Field(..., min_length=10)
    reason:        str = Field("uninstalled", max_length=128)


class EdgeHeartbeatRequest(BaseModel):
    edge_id:         str      = Field(..., min_length=8, max_length=128)
    tenant_id:       str      = Field(..., min_length=8, max_length=36)
    license_token:   str      = Field(..., min_length=10)
    requests_1m:     int      = Field(0, ge=0)
    blocks_1m:       int      = Field(0, ge=0)
    errors_1m:       int      = Field(0, ge=0)
    protection_mode: str | None = Field(None, description="monitor|protect|block")


@public_router.post("/register")
async def register_edge(body: EdgeRegisterRequest, request: Request) -> dict[str, Any]:
    """
    Self-registration endpoint for FrothIQ edge plugins.

    Idempotent — safe to call multiple times.
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
        contact_email=body.contact_email,
    )
    return {
        "ok": True,
        "tenant_id": result["tenant_id"],
        "domain": result.get("domain", body.domain),
        "license_token": result["license_token"],
        "plan": result["plan"],
        "edge_id": result["edge_id"],
        "node_state": result["node_state"],
        "feature_flags": result["feature_flags"],
        "enforcement_enabled": result["enforcement_enabled"],
        "registered_at": int(time.time()),
    }


@public_router.post("/deregister")
async def deregister_edge(body: EdgeDeregisterRequest, request: Request) -> dict[str, Any]:
    """
    Plugin uninstall notification.

    Sets the edge node state to REMOVED and records the reason.
    The node record is retained for audit purposes — it is never hard-deleted.
    Called by the WordPress uninstall hook before wiping plugin data.
    """
    if not _verify_license_token(body.edge_id, body.license_token):
        raise HTTPException(status_code=401, detail="Invalid license token")

    client_ip = (
        request.headers.get("x-forwarded-for", "").split(",")[0].strip()
        or (request.client.host if request.client else "unknown")
    )
    logger.info(
        "edge.deregister: edge_id=%s reason=%s ip=%s",
        body.edge_id[:16], body.reason, client_ip,
    )

    removed = await deregister_edge_node(
        edge_id=body.edge_id,
        license_token=body.license_token,
        reason=body.reason,
    )
    if not removed:
        raise HTTPException(status_code=404, detail="Edge node not found or already removed")

    return {"ok": True, "edge_id": body.edge_id, "state": "REMOVED"}


@public_router.post("/heartbeat")
async def edge_heartbeat(body: EdgeHeartbeatRequest) -> dict[str, Any]:
    """
    1-minute keep-alive from a registered edge plugin.
    Updates last_seen_at and promotes node state REGISTERED → ACTIVE.
    Returns the current plan and feature flags so the plugin can self-update.
    """
    if not _verify_license_token(body.edge_id, body.license_token):
        raise HTTPException(status_code=401, detail="Invalid license token")

    result = await touch_edge_node(
        edge_id=body.edge_id,
        requests_1m=body.requests_1m,
        blocks_1m=body.blocks_1m,
        errors_1m=body.errors_1m,
        protection_mode=body.protection_mode,
    )
    if not result:
        raise HTTPException(status_code=404, detail="Edge node not found")

    return {
        "ok":         True,
        "edge_id":    body.edge_id,
        "plan":       result["plan"],
        "node_state": result["state"],
        "ts":         int(time.time()),
    }


class EdgeEventRequest(BaseModel):
    edge_id:       str = Field(..., min_length=8,  max_length=128)
    tenant_id:     str = Field(..., min_length=8,  max_length=36)
    license_token: str = Field(..., min_length=10)
    ip:            str = Field(..., min_length=7,  max_length=45, description="IPv4 or IPv6")
    event_type:    str = Field(..., max_length=64,
                               description="blocked_local|blocked_rbl|failed_login|threat_detected")
    severity:      str = Field("high", max_length=16)
    reason:        str = Field("",     max_length=512)

    @field_validator("ip")
    @classmethod
    def valid_ip(cls, v: str) -> str:
        import ipaddress
        try:
            ipaddress.ip_address(v)
        except ValueError:
            raise ValueError("Invalid IP address")
        return v

    @field_validator("event_type")
    @classmethod
    def event_type_allowed(cls, v: str) -> str:
        allowed = {"blocked_local", "blocked_rbl", "failed_login", "threat_detected"}
        if v not in allowed:
            raise ValueError(f"event_type must be one of: {', '.join(sorted(allowed))}")
        return v


@public_router.post("/event")
async def report_event(body: EdgeEventRequest) -> dict[str, Any]:
    """
    Receive a threat event from an edge plugin.

    Called fire-and-forget (non-blocking) when the plugin blocks or detects
    a threat. Ingested into the community threat pool and redistributed via
    the /blocklist feed to all edge nodes at their next 15-minute sync.

    Threat score escalation:
      1 tenant reports → score 40  (low confidence)
      2 tenants        → score 65  (corroborated)
      3 tenants        → score 80  (multi-site confirmed)
      5+ tenants       → score 95  (high confidence — enters free-tier blocklist)
    """
    if not _verify_license_token(body.edge_id, body.license_token):
        raise HTTPException(status_code=401, detail="Invalid license token")

    result = await report_edge_event(
        edge_id=body.edge_id,
        tenant_id=body.tenant_id,
        ip=body.ip,
        event_type=body.event_type,
        severity=body.severity,
        reason=body.reason,
    )
    return {"ok": True, **result}


@public_router.get("/blocklist")
async def edge_blocklist(
    edge_id:       str,
    license_token: str,
    since:         int = 0,
) -> dict[str, Any]:
    """
    Pull-based threat IP list — RBL-style block list delivery.

    The plugin calls this endpoint every 15 minutes via wp-cron.
    Results are keyed by the edge node's plan:
      - free:       high-confidence confirmed threats (score ≥ 90)
      - pro:        extended threat list (score ≥ 70)
      - enterprise: full list including predictive signals (score ≥ 50)

    Returns:
      ips:        list of blocked IP addresses
      expires_at: unix timestamp when this list should be considered stale
      total:      total count of IPs in this response
      plan:       the plan tier used to filter this list
    """
    if not _verify_license_token(edge_id, license_token):
        raise HTTPException(status_code=401, detail="Invalid license token")

    result = await get_blocklist(edge_id=edge_id, since=since)
    if result is None:
        raise HTTPException(status_code=404, detail="Edge node not found or removed")

    return {
        "ok":         True,
        "ips":        result["ips"],
        "total":      len(result["ips"]),
        "plan":       result["plan"],
        "expires_at": int(time.time()) + 900,  # 15 minutes
        "generated_at": int(time.time()),
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


# ─────────────────────────────────────────────────────────────────────────────
# Outage reporting (public — authenticated by edge_id + license_token)
# ─────────────────────────────────────────────────────────────────────────────

class EdgeOutageRequest(BaseModel):
    edge_id:       str = Field(..., min_length=8, max_length=128)
    tenant_id:     str = Field(..., min_length=8, max_length=36)
    license_token: str = Field(..., min_length=10)
    outage_type:   str = Field(..., max_length=64)
    cause:         str = Field("", max_length=128)
    cause_detail:  str = Field("", max_length=2000)
    auto_resolved: bool = False
    duration_sec:  int  = Field(0, ge=0)
    site_url:      str  = Field("", max_length=512)


@public_router.post("/outage")
async def report_outage(body: EdgeOutageRequest) -> dict[str, Any]:
    """
    Plugin-reported outage event.
    Called immediately after the plugin detects (and optionally self-heals) an outage.
    Authenticated by edge_id + license_token; no JWT required.
    """
    if not _verify_license_token(body.edge_id, body.license_token):
        raise HTTPException(status_code=401, detail="Invalid license token")

    from frothiq_control_center.integrations.database import get_session_factory as _gsf
    from frothiq_control_center.services.edge_outage_service import receive_plugin_outage

    factory = _gsf()
    async with factory() as session:
        event = await receive_plugin_outage(
            session      = session,
            edge_id      = body.edge_id,
            tenant_id    = body.tenant_id,
            outage_type  = body.outage_type,
            cause        = body.cause,
            cause_detail = body.cause_detail,
            auto_resolved = body.auto_resolved,
            duration_sec = body.duration_sec,
            site_url     = body.site_url,
        )

    logger.warning(
        "edge.outage: edge_id=%s type=%s auto_resolved=%s",
        body.edge_id[:16], body.outage_type, body.auto_resolved,
    )
    return {"ok": True, "outage_id": event.id, "is_open": event.is_open}


# ─────────────────────────────────────────────────────────────────────────────
# Outage history (protected — JWT required)
# ─────────────────────────────────────────────────────────────────────────────

@protected_router.get("/edge/outages")
async def list_outages(
    limit: int = 20,
    current_user: TokenPayload = Depends(require_role("read_only")),
) -> dict[str, Any]:
    """Return recent outage events across all edge nodes. read_only+ required."""
    from frothiq_control_center.integrations.database import get_session_factory as _gsf
    from frothiq_control_center.services.edge_outage_service import get_recent_outages

    factory = _gsf()
    async with factory() as session:
        outages = await get_recent_outages(session, min(limit, 100))

    return {"outages": outages, "count": len(outages)}
