"""
Edge Node service — self-registering edge node provisioning.

Flow:
  1. Plugin calls POST /api/v1/edge/register with domain + edge_id + platform
  2. get_or_create_tenant() finds or creates an EdgeTenant for the domain
  3. register_node() creates/upserts the EdgeNode record
  4. issue_license_token() signs a license envelope with the tenant binding
  5. Returns tenant_id, license_token, plan, feature_flags to the plugin

All new tenants receive plan="free" and PLAN_ENFORCEMENT_ENABLED is respected.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import time
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from fastapi import HTTPException

from frothiq_control_center.config import get_settings
from frothiq_control_center.integrations.database import get_session_factory
from frothiq_control_center.models.edge import AttackReport, EdgeNode, EdgeTenant, FeatureFlag, ThreatReport
from frothiq_control_center.services import frappe_billing_client

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

async def register_edge_node(
    domain: str,
    edge_id: str,
    plugin_version: str,
    platform: str,
    contact_email: str | None = None,
) -> dict[str, Any]:
    """
    Idempotent: safe to call multiple times (e.g. on every plugin boot).
    Returns a complete registration response with license token.
    """
    factory = get_session_factory()
    async with factory() as session:
        tenant = await _get_or_create_tenant(
            session, domain, contact_email=contact_email
        )
        node = await _upsert_node(session, tenant, edge_id, plugin_version, platform)
        await session.commit()

        # Refresh after commit to get DB-generated values
        await session.refresh(tenant)
        await session.refresh(node)

        enforcement_enabled = await _flag_value(session, "PLAN_ENFORCEMENT_ENABLED")
        feature_flags = _build_feature_flags(tenant.plan, enforcement_enabled)
        license_token = _issue_license_token(
            tenant_id=tenant.tenant_id,
            edge_id=edge_id,
            domain=domain,
            plan=tenant.plan,
        )

    is_new_tenant = node.registration_count == 1
    logger.info(
        "edge_service: %s node=%s tenant=%s plan=%s state=%s",
        "new" if is_new_tenant else "re-register",
        edge_id[:16], tenant.tenant_id[:8], tenant.plan, node.state,
    )

    # Fire-and-forget: sync new tenants to ERPNext for GAAP accounting.
    # Never blocks the registration response; failures are logged, not raised.
    if is_new_tenant:
        asyncio.create_task(frappe_billing_client.sync_new_tenant(
            tenant_id=tenant.tenant_id,
            domain=tenant.domain,
            contact_email=tenant.contact_email,
            plan=tenant.plan,
        ))

    return {
        "tenant_id": tenant.tenant_id,
        "domain": tenant.domain,
        "license_token": license_token,
        "plan": tenant.plan,
        "edge_id": edge_id,
        "node_state": node.state,
        "feature_flags": feature_flags,
        "enforcement_enabled": enforcement_enabled,
    }


async def deregister_edge_node(
    edge_id: str,
    license_token: str,
    reason: str = "uninstalled",
) -> bool:
    """
    Set node state to REMOVED. Returns True if the node was found and updated.
    The node record is kept for audit — never hard-deleted.
    """
    factory = get_session_factory()
    async with factory() as session:
        result = await session.execute(
            select(EdgeNode).where(EdgeNode.edge_id == edge_id)
        )
        node = result.scalar_one_or_none()
        if node is None or node.state == "REMOVED":
            return False

        node.state = "REMOVED"
        node.last_seen_at = datetime.now(timezone.utc).replace(tzinfo=None)
        await session.commit()

    logger.info("edge_service: deregistered edge_id=%s reason=%s", edge_id[:16], reason)
    return True


async def touch_edge_node(
    edge_id: str,
    requests_1m: int = 0,
    blocks_1m: int = 0,
    errors_1m: int = 0,
    protection_mode: str | None = None,
) -> dict[str, Any] | None:
    """
    Update last_seen_at and promote node state on heartbeat.
    Returns current plan and state, or None if node not found.
    """
    factory = get_session_factory()
    async with factory() as session:
        result = await session.execute(
            select(EdgeNode).where(EdgeNode.edge_id == edge_id)
        )
        node = result.scalar_one_or_none()
        if node is None:
            return None

        now = datetime.now(timezone.utc).replace(tzinfo=None)
        node.last_seen_at = now
        if protection_mode in ("monitor", "protect", "block"):
            node.protection_mode = protection_mode
        # State promotions
        if node.state == "REGISTERED":
            node.state = "ACTIVE"
        elif node.state in ("ACTIVE", "DEGRADED"):
            node.state = "SYNCED"
        # Don't promote REMOVED nodes
        if node.state == "REMOVED":
            return None

        # Close any open heartbeat-miss outage windows — node is alive again.
        from frothiq_control_center.services.edge_outage_service import close_open_windows_for_node
        await close_open_windows_for_node(session, edge_id)

        await session.commit()

    logger.debug(
        "edge_service: heartbeat edge_id=%s req=%d blk=%d err=%d",
        edge_id[:16], requests_1m, blocks_1m, errors_1m,
    )
    return {"plan": node.plan, "state": node.state}


async def get_blocklist(
    edge_id: str,
    since: int = 0,
) -> dict[str, Any] | None:
    """
    Return the threat IP block list for this edge node's plan.

    Block list tiers:
      free:       full feed — same as enterprise while plan enforcement is off
      pro:        extended feed (score ≥ 70)
      enterprise: full feed (score ≥ 50)

    Falls back to an empty list if core is unreachable (fail-open for availability).
    """
    from frothiq_control_center.services.core_client import core_client

    factory = get_session_factory()
    async with factory() as session:
        result = await session.execute(
            select(EdgeNode).where(EdgeNode.edge_id == edge_id)
        )
        node = result.scalar_one_or_none()

    if node is None or node.state == "REMOVED":
        return None

    plan = node.plan

    # Score threshold by plan — free matches enterprise while plan enforcement is off
    score_threshold = {"pro": 70, "enterprise": 50}.get(plan, 50)

    # Source 1 — frothiq-core threat feed (fail-open)
    core_ips: list[str] = []
    try:
        params: dict[str, Any] = {"min_score": score_threshold, "limit": 500}
        if since:
            params["since"] = since
        data = await core_client.get("/api/v1/threats/feed", params=params)
        if isinstance(data, list):
            core_ips = [str(e["ip"]) for e in data if e.get("ip")]
        elif isinstance(data, dict):
            raw = data.get("ips") or data.get("threats") or []
            core_ips = [str(e["ip"] if isinstance(e, dict) else e) for e in raw if e]
    except Exception as exc:
        logger.warning("edge_service: get_blocklist core feed failed: %s", exc)

    # Source 2 — community threat pool (IPs reported as blocked by edge nodes)
    community_ips: list[str] = []
    try:
        async with get_session_factory()() as session:
            stmt = (
                select(ThreatReport.ip)
                .where(ThreatReport.threat_score >= score_threshold)
                .distinct()
            )
            if since:
                since_dt = datetime.fromtimestamp(since, tz=timezone.utc).replace(tzinfo=None)
                stmt = stmt.where(ThreatReport.last_seen >= since_dt)
            result = await session.execute(stmt)
            community_ips = [row[0] for row in result.fetchall()]
    except Exception as exc:
        logger.warning("edge_service: get_blocklist community query failed: %s", exc)

    # Merge and deduplicate both sources
    ips = list(dict.fromkeys(core_ips + community_ips))

    logger.debug(
        "edge_service: blocklist plan=%s threshold=%d core=%d community=%d total=%d",
        plan, score_threshold, len(core_ips), len(community_ips), len(ips),
    )
    return {"ips": ips, "plan": plan}


async def report_edge_event(
    edge_id: str,
    tenant_id: str,
    ip: str,
    event_type: str,
    severity: str = "high",
    reason: str = "",
) -> dict[str, Any]:
    """
    Ingest a threat event reported by an edge node.

    Upserts into ThreatReport (one row per ip+tenant). Recalculates
    threat_score based on cross-tenant confirmation count:
      1 tenant  → score 40   (single-source, low confidence)
      2 tenants → score 65   (corroborated)
      3 tenants → score 80   (multi-site confirmed)
      5+ tenants → score 95  (high confidence, enters free-tier blocklist)

    The updated IP becomes eligible for the global blocklist on the next pull.
    """
    factory = get_session_factory()
    now = datetime.now(timezone.utc).replace(tzinfo=None)

    async with factory() as session:
        # Load or create the per-(ip, tenant) row
        result = await session.execute(
            select(ThreatReport).where(
                ThreatReport.ip == ip,
                ThreatReport.tenant_id == tenant_id,
            )
        )
        row = result.scalar_one_or_none()

        if row is None:
            row = ThreatReport(
                id=str(uuid.uuid4()),
                ip=ip,
                tenant_id=tenant_id,
                edge_id=edge_id,
                event_type=event_type,
                severity=severity,
                reason=reason[:512],
                report_count=1,
                tenant_count=1,
                threat_score=0,
                first_seen=now,
                last_seen=now,
            )
            session.add(row)
        else:
            row.report_count += 1
            row.last_seen = now
            if severity in ("high", "critical") and row.severity not in ("high", "critical"):
                row.severity = severity

        await session.flush()

        # Count distinct tenants that have reported this IP
        from sqlalchemy import func
        count_result = await session.execute(
            select(func.count(ThreatReport.id)).where(ThreatReport.ip == ip)
        )
        distinct_tenants = count_result.scalar_one() or 1

        # Update tenant_count and recalculate threat_score on the current row
        row.tenant_count = distinct_tenants
        score_map = {1: 40, 2: 65, 3: 80, 4: 88}
        row.threat_score = score_map.get(distinct_tenants, 95 if distinct_tenants >= 5 else 40)

        await session.commit()

    logger.info(
        "threat_report: ip=%s tenants=%d score=%d event=%s edge=%s",
        ip, distinct_tenants, row.threat_score, event_type, edge_id[:16],
    )

    # Forward to frothiq-core intelligence pipeline (fire-and-forget).
    # This seeds the campaign correlator so Defense Mesh shows real data.
    asyncio.create_task(_forward_threat_to_core(ip, event_type, severity))

    return {
        "ip": ip,
        "threat_score": row.threat_score,
        "tenant_count": distinct_tenants,
        "ingested": True,
    }


async def list_edge_nodes(
    limit: int = 100, offset: int = 0, platform: str | None = None
) -> dict[str, Any]:
    factory = get_session_factory()
    async with factory() as session:
        stmt = select(EdgeNode).order_by(EdgeNode.registered_at.desc()).offset(offset).limit(limit)
        if platform:
            stmt = stmt.where(EdgeNode.platform == platform)
        result = await session.execute(stmt)
        nodes = result.scalars().all()

        count_result = await session.execute(select(EdgeNode))
        total = len(count_result.scalars().all())

    return {
        "total": total,
        "nodes": [_node_to_dict(n) for n in nodes],
    }


async def list_edge_tenants(limit: int = 100, offset: int = 0) -> dict[str, Any]:
    factory = get_session_factory()
    async with factory() as session:
        result = await session.execute(
            select(EdgeTenant).order_by(EdgeTenant.created_at.desc()).offset(offset).limit(limit)
        )
        tenants = result.scalars().all()
    return {
        "total": len(tenants),
        "tenants": [_tenant_to_dict(t) for t in tenants],
    }


async def get_feature_flags() -> dict[str, bool]:
    factory = get_session_factory()
    async with factory() as session:
        result = await session.execute(select(FeatureFlag))
        flags = result.scalars().all()
    return {f.flag_key: f.flag_value for f in flags}


async def set_feature_flag(flag_key: str, value: bool, changed_by: str) -> dict[str, Any]:
    factory = get_session_factory()
    async with factory() as session:
        result = await session.execute(
            select(FeatureFlag).where(FeatureFlag.flag_key == flag_key)
        )
        flag = result.scalar_one_or_none()
        if flag is None:
            flag = FeatureFlag(
                id=str(uuid.uuid4()),
                flag_key=flag_key,
                flag_value=value,
                description=_flag_description(flag_key),
                last_changed_by=changed_by,
            )
            session.add(flag)
        else:
            flag.flag_value = value
            flag.last_changed_at = datetime.now(timezone.utc).replace(tzinfo=None)
            flag.last_changed_by = changed_by
        await session.commit()

    logger.info("feature_flag: %s set to %s by %s", flag_key, value, changed_by)
    return {"flag_key": flag_key, "flag_value": value, "changed_by": changed_by}


async def get_edge_endpoint(tenant_id: str) -> str | None:
    """
    Return the HTTP base URL of the most-recently-seen active edge node for *tenant_id*.
    Returns None if no active node is registered.
    The URL is derived from the node's domain field: https://<domain>
    """
    factory = get_session_factory()
    async with factory() as session:
        result = await session.execute(
            select(EdgeNode)
            .where(EdgeNode.tenant_id == tenant_id)
            .where(EdgeNode.state.in_(["ACTIVE", "SYNCED"]))
            .order_by(EdgeNode.last_seen_at.desc())
        )
        node = result.scalars().first()

    if node is None:
        return None

    domain = node.domain.rstrip("/")
    if not domain.startswith("http"):
        domain = f"https://{domain}"
    return domain


async def get_registration_stats() -> dict[str, Any]:
    """Summary statistics for the MC3 dashboard."""
    factory = get_session_factory()
    async with factory() as session:
        nodes_result = await session.execute(select(EdgeNode))
        nodes = nodes_result.scalars().all()

        tenants_result = await session.execute(select(EdgeTenant))
        tenants = tenants_result.scalars().all()

    plan_dist: dict[str, int] = {}
    platform_dist: dict[str, int] = {}
    state_dist: dict[str, int] = {}

    for n in nodes:
        plan_dist[n.plan] = plan_dist.get(n.plan, 0) + 1
        platform_dist[n.platform] = platform_dist.get(n.platform, 0) + 1
        state_dist[n.state] = state_dist.get(n.state, 0) + 1

    return {
        "total_nodes": len(nodes),
        "total_tenants": len(tenants),
        "plan_distribution": plan_dist,
        "platform_distribution": platform_dist,
        "state_distribution": state_dist,
        "free_pct": round(
            plan_dist.get("free", 0) / max(len(nodes), 1) * 100, 1
        ),
    }


# ─────────────────────────────────────────────────────────────────────────────
# Internal helpers
# ─────────────────────────────────────────────────────────────────────────────

async def _get_or_create_tenant(
    session: AsyncSession,
    domain: str,
    contact_email: str | None = None,
) -> EdgeTenant:
    result = await session.execute(
        select(EdgeTenant).where(EdgeTenant.domain == domain)
    )
    tenant = result.scalar_one_or_none()

    if tenant is not None:
        # --- Gate: revoked domains may never re-register ---
        if tenant.registration_state == "revoked":
            raise HTTPException(
                status_code=403,
                detail={
                    "code": "domain_revoked",
                    "message": (
                        "This domain has been permanently revoked. "
                        "Contact support if you believe this is an error."
                    ),
                },
            )

        # --- Gate: deregistered domains require email verification ---
        if tenant.registration_state == "deregistered":
            if not contact_email:
                raise HTTPException(
                    status_code=403,
                    detail={
                        "code": "email_required",
                        "message": (
                            "This domain was previously deregistered. "
                            "Provide the original contact email to restore your data."
                        ),
                        "archived": True,
                    },
                )
            if tenant.contact_email and tenant.contact_email.lower() != contact_email.lower():
                raise HTTPException(
                    status_code=403,
                    detail={
                        "code": "email_mismatch",
                        "message": "Email does not match the archived registration record.",
                    },
                )

            # Email matched — restore archived data and reactive tenant
            archived = {}
            if tenant.archived_data:
                try:
                    archived = json.loads(tenant.archived_data)
                except Exception:
                    pass

            tenant.registration_state = "active"
            tenant.is_active = True
            tenant.deregistered_at = None
            tenant.archived_data = None
            if archived.get("plan"):
                tenant.plan = archived["plan"]
            if archived.get("notes"):
                tenant.notes = archived["notes"]

            logger.info(
                "edge_service: deregistered tenant RESTORED for domain=%s via email match", domain
            )
        else:
            # Active tenant — update contact_email if newly provided
            if contact_email and not tenant.contact_email:
                tenant.contact_email = contact_email

        return tenant

    # New tenant
    tenant = EdgeTenant(
        id=str(uuid.uuid4()),
        domain=domain,
        tenant_id=str(uuid.uuid4()),
        plan="free",
        registration_state="active",
        contact_email=contact_email,
    )
    session.add(tenant)
    logger.info("edge_service: new tenant created for domain=%s", domain)
    return tenant


async def _upsert_node(
    session: AsyncSession,
    tenant: EdgeTenant,
    edge_id: str,
    plugin_version: str,
    platform: str,
) -> EdgeNode:
    result = await session.execute(
        select(EdgeNode).where(EdgeNode.edge_id == edge_id)
    )
    node = result.scalar_one_or_none()
    now = datetime.now(timezone.utc).replace(tzinfo=None)

    if node is None:
        node = EdgeNode(
            id=str(uuid.uuid4()),
            edge_id=edge_id,
            tenant_id=tenant.tenant_id,
            domain=tenant.domain,
            platform=platform,
            plugin_version=plugin_version,
            state="REGISTERED",
            plan=tenant.plan,
            registered_at=now,
            last_seen_at=now,
            registration_count=1,
        )
        session.add(node)
    else:
        node.last_seen_at = now
        node.plugin_version = plugin_version
        node.registration_count = (node.registration_count or 0) + 1
        # Promote state on re-registration
        if node.state == "REGISTERED":
            node.state = "ACTIVE"
        elif node.state in ("ACTIVE", "DEGRADED"):
            node.state = "SYNCED"

    return node


async def _flag_value(session: AsyncSession, flag_key: str) -> bool:
    result = await session.execute(
        select(FeatureFlag).where(FeatureFlag.flag_key == flag_key)
    )
    flag = result.scalar_one_or_none()
    return flag.flag_value if flag else False


def _issue_license_token(
    tenant_id: str, edge_id: str, domain: str, plan: str
) -> str:
    """
    Issue a signed license envelope.
    Payload is HMAC-SHA256 signed with gateway_signing_key for tamper detection.
    The token is a JSON payload with a detached HMAC signature.
    """
    settings = get_settings()
    payload = {
        "tenant_id": tenant_id,
        "edge_id": edge_id,
        "domain": domain,
        "plan": plan,
        "iat": int(time.time()),
        "jti": str(uuid.uuid4()),
    }
    payload_json = json.dumps(payload, separators=(",", ":"), sort_keys=True)
    sig = hmac.new(
        settings.gateway_signing_key.encode(),
        payload_json.encode(),
        hashlib.sha256,
    ).hexdigest()
    # Return a compact token: base64url(payload) + "." + sig
    import base64
    b64 = base64.urlsafe_b64encode(payload_json.encode()).rstrip(b"=").decode()
    return f"{b64}.{sig}"


def _build_feature_flags(plan: str, enforcement_enabled: bool) -> dict[str, bool]:
    """
    Return the feature flags the edge plugin should apply.
    When PLAN_ENFORCEMENT_ENABLED=false, all features behave as accessible (soft mode).
    """
    if not enforcement_enabled:
        # Soft mode: all features open regardless of plan
        return {
            "paywall_active": False,
            "upgrade_prompt": False,
            "advanced_scanning": True,
            "real_time_events": True,
            "threat_feeds": True,
            "audit_logs": True,
        }

    # Enforcement mode: all features open for now — free plan ungated
    return {
        "paywall_active": False,
        "upgrade_prompt": False,
        "advanced_scanning": True,
        "real_time_events": True,
        "threat_feeds": True,
        "audit_logs": True,
    }


def _flag_description(flag_key: str) -> str:
    descriptions = {
        "PLAN_ENFORCEMENT_ENABLED": (
            "When true, enforce plan limits and activate paywall injection. "
            "When false (default), all features are accessible regardless of plan."
        ),
        "UPGRADE_SYSTEM_ENABLED": "When true, show upgrade prompts and enable upgrade orchestration.",
        "REGISTRATION_ENABLED": "When false, new edge node registrations are rejected.",
    }
    return descriptions.get(flag_key, f"Feature flag: {flag_key}")


def _node_to_dict(n: EdgeNode) -> dict[str, Any]:
    return {
        "id": n.id,
        "edge_id": n.edge_id,
        "tenant_id": n.tenant_id,
        "domain": n.domain,
        "platform": n.platform,
        "plugin_version": n.plugin_version,
        "state": n.state,
        "plan": n.plan,
        "protection_mode": getattr(n, "protection_mode", None),
        "registered_at": n.registered_at.isoformat() if n.registered_at else None,
        "last_seen": n.last_seen_at.isoformat() if n.last_seen_at else None,
        "last_seen_at": n.last_seen_at.isoformat() if n.last_seen_at else None,
        "registration_count": n.registration_count,
    }


def _tenant_to_dict(t: EdgeTenant) -> dict[str, Any]:
    return {
        "id": t.id,
        "tenant_id": t.tenant_id,
        "domain": t.domain,
        "plan": t.plan,
        "is_active": t.is_active,
        "registration_state": getattr(t, "registration_state", "active"),
        "contact_email": getattr(t, "contact_email", None),
        "created_at": t.created_at.isoformat() if t.created_at else None,
    }


async def _forward_threat_to_core(ip: str, event_type: str, severity: str) -> None:
    """Fire-and-forget: push edge threat event into frothiq-core's campaign correlator."""
    try:
        from frothiq_control_center.services.core_client import core_client
        await core_client.post(
            "/api/v2/internal/ingest-threat",
            body={"ip": ip, "severity": severity, "event_type": event_type, "attack_vectors": []},
        )
    except Exception as exc:
        logger.debug("_forward_threat_to_core: %s ip=%s: %s", event_type, ip, exc)


# ─────────────────────────────────────────────────────────────────────────────
# Attack Reports
# ─────────────────────────────────────────────────────────────────────────────

async def store_attack_report(data: dict[str, Any]) -> dict[str, Any]:
    """
    Persist a structured attack report submitted by an edge node.

    Also feeds the attacking IP into the community threat pool so it can
    be distributed to other edge nodes via the /blocklist feed.
    """
    factory = get_session_factory()
    now = datetime.now(timezone.utc).replace(tzinfo=None)

    def _parse_ts(val: Any) -> datetime | None:
        try:
            return datetime.fromtimestamp(int(val), tz=timezone.utc).replace(tzinfo=None)
        except (TypeError, ValueError, OSError):
            return None

    report_id = str(uuid.uuid4())
    async with factory() as session:
        report = AttackReport(
            id=report_id,
            edge_id=data.get("edge_id", ""),
            tenant_id=data.get("tenant_id", ""),
            domain=data.get("domain", "")[:255],
            attacking_ip=data.get("attacking_ip", ""),
            cidr=data.get("cidr", "")[:50],
            asn=data.get("asn", "")[:32],
            org=data.get("org", "")[:255],
            attack_type=data.get("attack_type", "credential_stuffing")[:64],
            attempt_count=int(data.get("attempt_count", 0)),
            usernames_targeted=json.dumps(data.get("usernames_targeted", [])),
            user_agents=json.dumps(data.get("user_agents", [])),
            attack_started_at=_parse_ts(data.get("attack_started_at")),
            attack_ended_at=_parse_ts(data.get("attack_ended_at")),
            ip_blocked=bool(data.get("ip_blocked", False)),
            cidr_blocked=bool(data.get("cidr_blocked", False)),
            enum_lockdown=bool(data.get("enum_lockdown", False)),
            notes=data.get("notes", "")[:2000],
            traceroute_hops=json.dumps(data.get("traceroute_hops", [])) if data.get("traceroute_hops") else None,
            reported_at=now,
        )
        session.add(report)
        await session.commit()

    logger.info(
        "attack_report: id=%s ip=%s type=%s attempts=%d domain=%s",
        report_id, data.get("attacking_ip"), data.get("attack_type"),
        data.get("attempt_count", 0), data.get("domain"),
    )

    # Feed IP into community threat pool
    await report_edge_event(
        edge_id=data.get("edge_id", ""),
        tenant_id=data.get("tenant_id", ""),
        ip=data.get("attacking_ip", ""),
        event_type=data.get("attack_type", "credential_stuffing"),
        severity="high",
        reason=(
            f"Attack report: {data.get('attack_type','credential_stuffing')} — "
            f"{data.get('attempt_count', 0)} attempts on {data.get('domain', '')}"
        ),
    )

    return {"report_id": report_id}


async def auto_compile_attack_report(
    edge_id: str,
    ip: str,
    score: int,
    reason: str,
    path: str,
    ip_blocked: bool,
) -> dict[str, Any]:
    """
    Compile a full AttackReport from a thin plugin trigger.

    The plugin supplies only the raw block context (IP, score, reason, path).
    MC3 handles everything else: tenant lookup, attempt count from stored threat
    reports, attack type inference, traceroute, deduplication, and storage.

    Rate-limited to one compiled report per (edge_id, IP) per 24 hours.
    """
    import asyncio
    import re as _re

    factory = get_session_factory()
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    cutoff_24h = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(hours=24)

    async with factory() as session:
        # Resolve edge node → tenant_id, domain
        node_result = await session.execute(
            select(EdgeNode).where(EdgeNode.edge_id == edge_id)
        )
        node = node_result.scalar_one_or_none()
        if node is None:
            return {"ok": False, "error": "unknown edge node"}

        tenant_id = node.tenant_id
        domain    = node.site_url or ""

        # Deduplication: skip if already reported this IP in the last 24 hours
        dup = await session.execute(
            select(AttackReport.id).where(
                AttackReport.edge_id      == edge_id,
                AttackReport.attacking_ip == ip,
                AttackReport.reported_at  >= cutoff_24h,
            ).limit(1)
        )
        if dup.scalar_one_or_none():
            return {"ok": False, "skipped": True, "reason": "rate_limited"}

        # Attempt count: total threat reports received from this edge for this IP
        count_result = await session.execute(
            select(ThreatReport).where(
                ThreatReport.edge_id == edge_id,
                ThreatReport.ip      == ip,
            )
        )
        tr = count_result.scalar_one_or_none()
        attempt_count = tr.report_count if tr else 1

    # Infer attack type from reason string
    reason_lc = reason.lower()
    if any(k in reason_lc for k in ("brute", "login", "credential")):
        attack_type = "brute_force"
    elif any(k in reason_lc for k in ("sql", "injection", "select", "union")):
        attack_type = "sql_injection"
    elif any(k in reason_lc for k in ("xss", "script", "javascript")):
        attack_type = "xss"
    elif any(k in reason_lc for k in ("traversal", "../", "%2e")):
        attack_type = "path_traversal"
    elif any(k in reason_lc for k in ("sensitive file", "file access")):
        attack_type = "file_access_attempt"
    elif any(k in reason_lc for k in ("scanner", "user agent", "nikto", "sqlmap")):
        attack_type = "scanner"
    else:
        attack_type = "suspicious_request"

    # Traceroute (runs on MC3 — no exec() on the WordPress server)
    hops: list[dict] = []
    try:
        proc = await asyncio.wait_for(
            asyncio.create_subprocess_exec(
                "traceroute", "-n", "-q", "1", "-w", "2", "-m", "20", ip,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            ),
            timeout=5,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=65)
        for line in stdout.decode().splitlines():
            m = _re.match(
                r"^\s*(\d+)\s+(\*|\d{1,3}(?:\.\d{1,3}){3}|[0-9a-f:]+)\s+(?:([\d.]+)\s+ms)?",
                line,
            )
            if m:
                hops.append({
                    "hop":    int(m.group(1)),
                    "ip":     None if m.group(2) == "*" else m.group(2),
                    "rtt_ms": float(m.group(3)) if m.group(3) else None,
                })
    except Exception:
        pass  # traceroute unavailable or timed out — report still stored without hops

    notes = (
        f"Auto-compiled by MC3. Block score: {score}. "
        f"Reason: {reason}. Path: {path}. "
        f"Attempt count from threat pool: {attempt_count}."
    )

    result = await store_attack_report({
        "edge_id":            edge_id,
        "tenant_id":          tenant_id,
        "domain":             domain,
        "attacking_ip":       ip,
        "cidr":               "",
        "asn":                "",
        "org":                "",
        "attack_type":        attack_type,
        "attempt_count":      attempt_count,
        "usernames_targeted": [],
        "user_agents":        [],
        "ip_blocked":         ip_blocked,
        "cidr_blocked":       False,
        "enum_lockdown":      True,
        "notes":              notes,
        "traceroute_hops":    hops,
    })
    return {"ok": True, **result}


async def list_attack_reports(
    limit: int = 50,
    offset: int = 0,
    tenant_id: str | None = None,
) -> dict[str, Any]:
    """Return paginated attack reports for the Control Center UI."""
    from sqlalchemy import func

    factory = get_session_factory()
    async with factory() as session:
        stmt = select(AttackReport).order_by(AttackReport.reported_at.desc())
        if tenant_id:
            stmt = stmt.where(AttackReport.tenant_id == tenant_id)
        stmt = stmt.limit(min(limit, 200)).offset(offset)
        result = await session.execute(stmt)
        rows = result.scalars().all()

        count_stmt = select(func.count()).select_from(AttackReport)
        if tenant_id:
            count_stmt = count_stmt.where(AttackReport.tenant_id == tenant_id)
        total = (await session.execute(count_stmt)).scalar_one()

    return {"reports": [_attack_report_to_dict(r) for r in rows], "total": total}


def _attack_report_to_dict(r: AttackReport) -> dict[str, Any]:
    return {
        "id": r.id,
        "edge_id": r.edge_id,
        "tenant_id": r.tenant_id,
        "domain": r.domain,
        "attacking_ip": r.attacking_ip,
        "cidr": r.cidr,
        "asn": r.asn,
        "org": r.org,
        "attack_type": r.attack_type,
        "attempt_count": r.attempt_count,
        "usernames_targeted": json.loads(r.usernames_targeted or "[]"),
        "user_agents": json.loads(r.user_agents or "[]"),
        "attack_started_at": r.attack_started_at.isoformat() if r.attack_started_at else None,
        "attack_ended_at": r.attack_ended_at.isoformat() if r.attack_ended_at else None,
        "ip_blocked": r.ip_blocked,
        "cidr_blocked": r.cidr_blocked,
        "enum_lockdown": r.enum_lockdown,
        "notes": r.notes,
        "traceroute_hops": json.loads(r.traceroute_hops) if r.traceroute_hops else [],
        "reported_at": r.reported_at.isoformat() if r.reported_at else None,
    }
