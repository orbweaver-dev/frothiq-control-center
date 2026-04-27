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
    auto_compile_attack_report,
    get_blocklist,
    get_eula_version,
    get_feature_flags,
    get_registration_stats,
    deregister_edge_node,
    list_attack_reports,
    list_edge_nodes,
    list_edge_tenants,
    register_edge_node,
    report_edge_event,
    set_feature_flag,
    store_attack_report,
    touch_edge_node,
    record_eula_acceptance,
)

logger = logging.getLogger(__name__)

# Bump this whenever a new plugin version is released; edge nodes compare against
# their installed version and surface an "update available" notice in WP admin.
LATEST_PLUGIN_VERSION = "0.25.3"

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
    plugin_version:  str | None = Field(None, max_length=32)


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
        plugin_version=body.plugin_version,
    )
    if not result:
        raise HTTPException(status_code=404, detail="Edge node not found")

    return {
        "ok":                    True,
        "edge_id":               body.edge_id,
        "plan":                  result["plan"],
        "node_state":            result["state"],
        "latest_plugin_version": LATEST_PLUGIN_VERSION,
        "ts":                    int(time.time()),
    }


@public_router.get("/eula/{version}")
async def edge_eula_fetch(version: str) -> dict[str, Any]:
    """
    Return the canonical EULA text and its SHA-256 for a given version.

    Public — no authentication required. The plugin calls this before
    showing the EULA modal so it can display the server-authoritative text
    and send back its hash on acceptance (proving the admin saw exactly
    this text, not a modified local copy).
    """
    data = await get_eula_version(version)
    if data is None:
        raise HTTPException(status_code=404, detail=f"EULA version '{version}' not found")
    return data


class EulaAcceptRequest(BaseModel):
    edge_id:           str = Field(..., min_length=8, max_length=128)
    license_token:     str = Field(..., min_length=10)
    eula_version:      str = Field(..., max_length=16)
    plugin_version:    str = Field("", max_length=32)
    eula_hash:         str = Field("", max_length=64)
    site_url:          str = Field("", max_length=255)
    accepted_by_email: str = Field("", max_length=254)
    accepted_from_ip:  str = Field("", max_length=45)


@public_router.post("/eula/accept")
async def edge_eula_accept(body: EulaAcceptRequest, request: Request) -> dict[str, Any]:
    """
    Record that a site administrator has accepted the FrothIQ EULA.

    Called immediately after the admin clicks "I Accept" in the plugin.
    Idempotent — re-posting the same (edge_id, eula_version) is a no-op.
    The accepted_from_ip falls back to the HTTP client IP when the plugin
    does not supply one.
    """
    if not _verify_license_token(body.edge_id, body.license_token):
        raise HTTPException(status_code=401, detail="Invalid license token")

    client_ip = body.accepted_from_ip or (request.client.host if request.client else "") or ""
    result = await record_eula_acceptance(
        edge_id=body.edge_id,
        eula_version=body.eula_version,
        plugin_version=body.plugin_version,
        eula_hash=body.eula_hash,
        site_url=body.site_url,
        accepted_by_email=body.accepted_by_email,
        accepted_from_ip=client_ip,
    )
    return {"ok": True, **result}


class AttackReportRequest(BaseModel):
    edge_id:            str       = Field(..., min_length=8, max_length=128)
    license_token:      str       = Field(..., min_length=10)
    tenant_id:          str       = Field(..., min_length=8, max_length=36)
    domain:             str       = Field("", max_length=255)
    attacking_ip:       str       = Field(..., min_length=7, max_length=45)
    cidr:               str       = Field("", max_length=50)
    asn:                str       = Field("", max_length=32)
    org:                str       = Field("", max_length=255)
    attack_type:        str       = Field("credential_stuffing", max_length=64)
    attempt_count:      int       = Field(0, ge=0)
    usernames_targeted: list[str] = Field(default_factory=list)
    user_agents:        list[str] = Field(default_factory=list)
    attack_started_at:  int | None = None
    attack_ended_at:    int | None = None
    ip_blocked:         bool      = False
    cidr_blocked:       bool      = False
    enum_lockdown:      bool      = False
    notes:              str       = Field("", max_length=2000)
    traceroute_hops:    list[dict] = Field(default_factory=list)


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


class TracerouteRequest(BaseModel):
    edge_id:       str = Field(..., min_length=8, max_length=128)
    license_token: str = Field(..., min_length=10)
    ip:            str = Field(..., min_length=7, max_length=45)

    @field_validator("ip")
    @classmethod
    def valid_ip(cls, v: str) -> str:
        import ipaddress
        try:
            ipaddress.ip_address(v)
        except ValueError:
            raise ValueError("Invalid IP address")
        return v


@public_router.post("/traceroute")
async def edge_traceroute(body: TracerouteRequest) -> dict[str, Any]:
    """
    Run a traceroute from the MC3 server to the requested IP and return hop data.

    Called by edge nodes when building an attack report — the traceroute runs
    here so the WordPress plugin never needs exec().

    Returns: { hops: [{hop, ip, rtt_ms}, ...] }
    """
    import asyncio
    import re

    if not _verify_license_token(body.edge_id, body.license_token):
        raise HTTPException(status_code=401, detail="Invalid license token")

    hops: list[dict] = []
    try:
        cmd = ["traceroute", "-n", "-q", "1", "-w", "2", "-m", "20", body.ip]
        proc = await asyncio.wait_for(
            asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            ),
            timeout=60,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=60)
        for line in (stdout or b"").decode("utf-8", errors="replace").splitlines():
            m = re.match(
                r"^\s*(\d+)\s+(\*|\d{1,3}(?:\.\d{1,3}){3}|[0-9a-f:]+)\s+(?:([\d.]+)\s+ms)?",
                line,
            )
            if m:
                hops.append({
                    "hop":    int(m.group(1)),
                    "ip":     None if m.group(2) == "*" else m.group(2),
                    "rtt_ms": float(m.group(3)) if m.group(3) else None,
                })
    except Exception as exc:
        logger.warning("edge_traceroute: failed for %s — %s", body.ip, exc)

    return {"hops": hops}


@public_router.post("/report/attack")
async def report_attack(body: AttackReportRequest) -> dict[str, Any]:
    """
    Receive a structured attack incident report from an edge node.

    Stores the full incident context (attacking IP/CIDR/ASN, attack type,
    targeted usernames, rotating user agents, attempt count, and every
    mitigation the edge applied). Also feeds the attacking IP into the
    community threat pool for blocklist distribution to other nodes.
    """
    if not _verify_license_token(body.edge_id, body.license_token):
        raise HTTPException(status_code=401, detail="Invalid license token")

    result = await store_attack_report(body.model_dump())
    return {"ok": True, **result}


class AutoAttackTrigger(BaseModel):
    edge_id:       str  = Field(..., min_length=8, max_length=128)
    license_token: str  = Field(..., min_length=10)
    ip:            str  = Field(..., min_length=7, max_length=45, description="Attacking IP")
    score:         int  = Field(..., ge=0, le=100, description="Threat score assigned by the edge")
    reason:        str  = Field("", max_length=512, description="Short reason string from the block phase")
    path:          str  = Field("", max_length=1024, description="Request path that triggered the block")
    ip_blocked:    bool = Field(False, description="True if the edge actually blocked this IP")

    @field_validator("ip")
    @classmethod
    def valid_ip(cls, v: str) -> str:
        import ipaddress
        try:
            ipaddress.ip_address(v)
        except ValueError:
            raise ValueError("Invalid IP address")
        return v


@public_router.post("/report/attack/auto")
async def auto_report_attack(body: AutoAttackTrigger) -> dict[str, Any]:
    """
    Thin trigger — plugin sends minimal context; MC3 compiles the full report.

    Called fire-and-forget (non-blocking=false on the plugin side is OK — the
    plugin uses wp_remote_post with blocking=false so this runs independently).

    MC3 handles:
      - EdgeNode lookup (tenant_id, domain)
      - 24-hour per-IP deduplication
      - Attempt count from ThreatReport history
      - Attack type inference from reason string
      - Async traceroute
      - Storing the AttackReport record

    Returns:
      { ok: true, report_id: "..." }           — report created
      { ok: false, skipped: true, ... }         — rate-limited (already reported within 24h)
    """
    if not _verify_license_token(body.edge_id, body.license_token):
        raise HTTPException(status_code=401, detail="Invalid license token")

    result = await auto_compile_attack_report(
        edge_id=body.edge_id,
        ip=body.ip,
        score=body.score,
        reason=body.reason,
        path=body.path,
        ip_blocked=body.ip_blocked,
    )
    return result


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


# ─────────────────────────────────────────────────────────────────────────────
# Support ticket proxy (public — authenticated by edge_id + license_token)
# Allows the plugin to submit/query Frappe Issues without holding credentials.
# ─────────────────────────────────────────────────────────────────────────────

class EdgeTicketRequest(BaseModel):
    edge_id:       str = Field(..., min_length=8, max_length=128)
    tenant_id:     str = Field(..., min_length=8, max_length=36)
    license_token: str = Field(..., min_length=10)
    subject:       str = Field(..., min_length=5, max_length=120)
    description:   str = Field(..., min_length=10, max_length=5000)
    priority:      str = Field("Medium", pattern="^(Low|Medium|High|Urgent)$")


@public_router.post("/ticket")
async def submit_ticket(body: EdgeTicketRequest) -> dict[str, Any]:
    """
    Plugin submits a support ticket through MC3.
    MC3 proxies the request to the Frappe ERPNext Issue DocType.
    Deduplication: checks for an existing open Issue for this edge_id first.
    """
    if not _verify_license_token(body.edge_id, body.license_token):
        raise HTTPException(status_code=401, detail="Invalid license token")

    from frothiq_control_center.services import frappe_ticket_client as _ftc

    ref_tag = f"edge:{body.edge_id[:24]}"
    existing = await _ftc.find_open_issue(ref_tag)

    if existing:
        # Amend the existing ticket with the new submission details
        note = (
            f"**Additional report from site admin**\n"
            f"Subject: {body.subject}\n"
            f"Priority: {body.priority}\n"
            f"Details: {body.description[:800]}"
        )
        amended = await _ftc.append_to_issue(existing, note)
        logger.warning(
            "ticket_proxy.amended edge=%s ticket=%s amended=%s subject=%s",
            body.edge_id[:16], existing, amended, body.subject[:60],
        )
        return {
            "ok": True,
            "ticket_name": existing,
            "duplicate": True,
            "amended": amended,
            "message": "An open ticket already exists for this site — your report has been added to it.",
        }

    ticket_name = await _ftc.create_issue(
        subject=f"{body.subject} ({ref_tag})",
        description=(
            f"{body.description}\n\n"
            f"---\n*Submitted by site admin via FrothIQ plugin*\n"
            f"*Edge: {body.edge_id[:24]}*"
        ),
        priority=body.priority,
    )
    if not ticket_name:
        logger.error(
            "ticket_proxy.create_failed edge=%s subject=%s",
            body.edge_id[:16], body.subject[:60],
        )
        raise HTTPException(status_code=502, detail="Could not create support ticket — try again later.")

    logger.info("ticket_proxy.created edge=%s ticket=%s subject=%s", body.edge_id[:16], ticket_name, body.subject[:60])
    return {"ok": True, "ticket_name": ticket_name, "duplicate": False, "amended": False}


@public_router.get("/tickets")
async def list_tickets(
    edge_id:       str,
    license_token: str,
) -> dict[str, Any]:
    """Return recent Frappe Issues for this edge node."""
    if not _verify_license_token(edge_id, license_token):
        raise HTTPException(status_code=401, detail="Invalid license token")

    from frothiq_control_center.services import frappe_ticket_client as _ftc

    tickets = await _ftc.get_issues_for_edge(edge_id, limit=20)
    return {"ok": True, "tickets": tickets, "count": len(tickets)}


@public_router.get("/attack-reports")
async def list_edge_attack_reports(
    edge_id:       str,
    license_token: str,
    limit:         int = 50,
    offset:        int = 0,
) -> dict[str, Any]:
    """Return attack reports for this edge node (plugin-facing, no CC auth required)."""
    if not _verify_license_token(edge_id, license_token):
        raise HTTPException(status_code=401, detail="Invalid license token")

    from frothiq_control_center.services.edge_service import list_attack_reports
    result = await list_attack_reports(limit=min(limit, 100), offset=offset, edge_id=edge_id)
    return {"ok": True, **result}


@protected_router.get("/edge/attack-reports")
async def get_attack_reports(
    limit:     int       = 50,
    offset:    int       = 0,
    tenant_id: str | None = None,
    _user: Any = Depends(require_role("read_only")),
) -> dict[str, Any]:
    """
    Return paginated attack reports for the Control Center Attack Reports page.
    Accessible to all authenticated CC users (read_only and above).
    """
    result = await list_attack_reports(limit=limit, offset=offset, tenant_id=tenant_id)
    return {"ok": True, **result}
