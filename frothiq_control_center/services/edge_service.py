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

from frothiq_control_center.config import get_settings
from frothiq_control_center.integrations.database import get_session_factory
from frothiq_control_center.models.edge import EdgeNode, EdgeTenant, FeatureFlag

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

async def register_edge_node(
    domain: str,
    edge_id: str,
    plugin_version: str,
    platform: str,
) -> dict[str, Any]:
    """
    Idempotent: safe to call multiple times (e.g. on every plugin boot).
    Returns a complete registration response with license token.
    """
    factory = get_session_factory()
    async with factory() as session:
        tenant = await _get_or_create_tenant(session, domain)
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

    logger.info(
        "edge_service: %s node=%s tenant=%s plan=%s state=%s",
        "new" if node.registration_count == 1 else "re-register",
        edge_id[:16], tenant.tenant_id[:8], tenant.plan, node.state,
    )

    return {
        "tenant_id": tenant.tenant_id,
        "license_token": license_token,
        "plan": tenant.plan,
        "edge_id": edge_id,
        "node_state": node.state,
        "feature_flags": feature_flags,
        "enforcement_enabled": enforcement_enabled,
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

async def _get_or_create_tenant(session: AsyncSession, domain: str) -> EdgeTenant:
    result = await session.execute(
        select(EdgeTenant).where(EdgeTenant.domain == domain)
    )
    tenant = result.scalar_one_or_none()
    if tenant is None:
        tenant = EdgeTenant(
            id=str(uuid.uuid4()),
            domain=domain,
            tenant_id=str(uuid.uuid4()),
            plan="free",
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

    # Enforcement mode: gate by plan
    is_free = plan == "free"
    return {
        "paywall_active": is_free,
        "upgrade_prompt": is_free,
        "advanced_scanning": not is_free,
        "real_time_events": not is_free,
        "threat_feeds": plan in ("pro", "enterprise"),
        "audit_logs": plan in ("pro", "enterprise"),
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
        "registered_at": n.registered_at.isoformat() if n.registered_at else None,
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
        "created_at": t.created_at.isoformat() if t.created_at else None,
    }
