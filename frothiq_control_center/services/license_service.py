"""
License Authority service — tenant license state, revocation, sync health.

Data source: CC's own edge_tenants + edge_nodes tables (MariaDB).
frothiq-core is NOT the source of truth for license state — that registry
only contains plan templates, not individual site registrations.
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, select, update

from frothiq_control_center.integrations.database import get_session_factory
from frothiq_control_center.models.edge import EdgeNode, EdgeTenant

logger = logging.getLogger(__name__)

_ACTIVE_STATES = {"REGISTERED", "ACTIVE", "SYNCED"}
_SYNC_HEALTHY_WINDOW = timedelta(minutes=15)
_MAX_SITES_BY_PLAN: dict[str, int] = {
    "free": 1,
    "pro": 5,
    "business": 25,
    "enterprise": 1000,
}


def _state_to_status(is_active: bool, state: str) -> str:
    if not is_active:
        return "suspended"
    if state == "REVOKED":
        return "suspended"
    if state == "REMOVED":
        return "expired"
    return "active"


async def get_all_license_states() -> dict[str, Any]:
    """
    Return license overview derived from edge_tenants + edge_nodes.
    One row per tenant; aggregates node count and sync health per tenant.
    """
    factory = get_session_factory()
    async with factory() as session:
        tenants_result = await session.execute(
            select(EdgeTenant).order_by(EdgeTenant.created_at.desc())
        )
        tenants = tenants_result.scalars().all()

        nodes_result = await session.execute(select(EdgeNode))
        all_nodes = nodes_result.scalars().all()

    # Group nodes by tenant_id
    nodes_by_tenant: dict[str, list[EdgeNode]] = {}
    for node in all_nodes:
        nodes_by_tenant.setdefault(node.tenant_id, []).append(node)

    now = datetime.now(UTC)
    summary: dict[str, Any] = {
        "total": len(tenants),
        "active": 0,
        "suspended": 0,
        "expired": 0,
        "tenants": [],
    }

    for t in tenants:
        nodes = nodes_by_tenant.get(t.tenant_id, [])
        active_nodes = [n for n in nodes if n.state in _ACTIVE_STATES]

        # Derive last sync from most recent node activity
        last_sync_candidates = [
            n.last_sync_at or n.last_seen_at for n in nodes if n.last_sync_at or n.last_seen_at
        ]
        last_sync = max(last_sync_candidates) if last_sync_candidates else None

        # Sync health: any node SYNCED and seen within the health window
        sync_healthy = any(
            n.state == "SYNCED"
            and n.last_seen_at is not None
            and (now - n.last_seen_at.replace(tzinfo=UTC)) < _SYNC_HEALTHY_WINDOW
            for n in nodes
        )

        # Derive status from tenant active flag + highest-priority node state
        dominant_state = nodes[0].state if nodes else "REGISTERED"
        status = _state_to_status(t.is_active, dominant_state)

        if status in summary:
            summary[status] += 1

        # Derive protection mode — use worst (most restrictive) mode across active nodes
        mode_rank = {"monitor": 0, "protect": 1, "block": 2}
        active_modes = [
            n.protection_mode for n in active_nodes
            if getattr(n, "protection_mode", None)
        ]
        protection_mode = max(active_modes, key=lambda m: mode_rank.get(m, 0), default=None) \
            if active_modes else (getattr(nodes[0], "protection_mode", None) if nodes else None)

        summary["tenants"].append({
            "tenant_id":          t.tenant_id,
            "domain":             t.domain,
            "plan":               t.plan,
            "status":             status,
            "registration_state": getattr(t, "registration_state", "active"),
            "max_sites":          _MAX_SITES_BY_PLAN.get(t.plan, 1),
            "active_sites":       len(active_nodes),
            "last_sync":          last_sync.isoformat() if last_sync else None,
            "sync_healthy":       sync_healthy,
            "platform":           nodes[0].platform if nodes else None,
            "plugin_version":     nodes[0].plugin_version if nodes else None,
            "protection_mode":    protection_mode,
            "deregistered_at":    t.deregistered_at.isoformat() if t.deregistered_at else None,
        })

    return {"success": True, "source": "edge_db", **summary}


async def get_sync_health() -> dict[str, Any]:
    """Aggregate sync health across all tenants from edge_nodes data."""
    data = await get_all_license_states()
    tenants = data.get("tenants", [])
    healthy = sum(1 for t in tenants if t.get("sync_healthy"))
    degraded = len(tenants) - healthy
    return {
        "total": len(tenants),
        "sync_healthy": healthy,
        "sync_degraded": degraded,
        "health_pct": round((healthy / max(len(tenants), 1)) * 100, 1),
        "source": "edge_db",
    }


async def get_tenant_license(tenant_id: str) -> dict[str, Any]:
    """Fetch license state for a specific tenant from the CC database."""
    factory = get_session_factory()
    async with factory() as session:
        tenant_result = await session.execute(
            select(EdgeTenant).where(EdgeTenant.tenant_id == tenant_id)
        )
        tenant = tenant_result.scalar_one_or_none()
        if tenant is None:
            from frothiq_control_center.services.core_client import CoreClientError
            raise CoreClientError(404, f"Tenant {tenant_id} not found")

        nodes_result = await session.execute(
            select(EdgeNode).where(EdgeNode.tenant_id == tenant_id)
        )
        nodes = nodes_result.scalars().all()

    now = datetime.now(UTC)
    active_nodes = [n for n in nodes if n.state in _ACTIVE_STATES]
    dominant_state = nodes[0].state if nodes else "REGISTERED"
    status = _state_to_status(tenant.is_active, dominant_state)

    sync_healthy = any(
        n.state == "SYNCED"
        and n.last_seen_at is not None
        and (now - n.last_seen_at.replace(tzinfo=UTC)) < _SYNC_HEALTHY_WINDOW
        for n in nodes
    )

    last_sync_candidates = [
        n.last_sync_at or n.last_seen_at for n in nodes if n.last_sync_at or n.last_seen_at
    ]
    last_sync = max(last_sync_candidates) if last_sync_candidates else None

    return {
        "tenant_id":      tenant.tenant_id,
        "domain":         tenant.domain,
        "plan":           tenant.plan,
        "status":         status,
        "is_active":      tenant.is_active,
        "max_sites":      _MAX_SITES_BY_PLAN.get(tenant.plan, 1),
        "active_sites":   len(active_nodes),
        "last_sync":      last_sync.isoformat() if last_sync else None,
        "sync_healthy":   sync_healthy,
        "nodes":          [
            {
                "edge_id":        n.edge_id,
                "domain":         n.domain,
                "platform":       n.platform,
                "plugin_version": n.plugin_version,
                "state":          n.state,
                "registered_at":  n.registered_at.isoformat() if n.registered_at else None,
                "last_seen_at":   n.last_seen_at.isoformat() if n.last_seen_at else None,
            }
            for n in nodes
        ],
        "created_at": tenant.created_at.isoformat() if tenant.created_at else None,
    }


async def revoke_license(tenant_id: str, reason: str, admin_user: str) -> dict[str, Any]:
    """
    Revoke a tenant's license — permanently blocks re-registration for this domain.
    Sets is_active=False, registration_state='revoked', nodes→REVOKED.
    """
    factory = get_session_factory()
    async with factory() as session:
        tenant_result = await session.execute(
            select(EdgeTenant).where(EdgeTenant.tenant_id == tenant_id)
        )
        tenant = tenant_result.scalar_one_or_none()
        if tenant is None:
            return {"success": False, "error": f"Tenant {tenant_id} not found"}

        tenant.is_active = False
        tenant.registration_state = "revoked"
        await session.execute(
            update(EdgeNode)
            .where(EdgeNode.tenant_id == tenant_id)
            .values(state="REVOKED")
        )
        await session.commit()

    logger.warning(
        "License REVOKED for tenant %s (domain=%s) by admin %s — reason: %s",
        tenant_id, tenant.domain, admin_user, reason,
    )
    return {"success": True, "tenant_id": tenant_id, "status": "suspended"}


async def deregister_license(tenant_id: str, admin_user: str) -> dict[str, Any]:
    """
    Deregister a tenant — archives data and allows future re-registration.

    Unlike revoke, deregistration does NOT permanently block the domain.
    The site can re-register by providing the matching contact_email.
    On email match, archived plan/notes are restored (resync).
    """
    factory = get_session_factory()
    async with factory() as session:
        tenant_result = await session.execute(
            select(EdgeTenant).where(EdgeTenant.tenant_id == tenant_id)
        )
        tenant = tenant_result.scalar_one_or_none()
        if tenant is None:
            return {"success": False, "error": f"Tenant {tenant_id} not found"}

        # Archive current state before deregistering
        archive = {
            "plan":    tenant.plan,
            "notes":   tenant.notes,
            "is_active": tenant.is_active,
            "archived_at": datetime.now(UTC).isoformat(),
        }
        tenant.registration_state = "deregistered"
        tenant.is_active = False
        tenant.deregistered_at = datetime.now(UTC).replace(tzinfo=None)
        tenant.archived_data = json.dumps(archive)

        await session.execute(
            update(EdgeNode)
            .where(EdgeNode.tenant_id == tenant_id)
            .values(state="DEREGISTERED")
        )
        await session.commit()

    logger.info(
        "Tenant DEREGISTERED: %s (domain=%s) by admin %s — data archived, re-registration allowed with email match",
        tenant_id, tenant.domain, admin_user,
    )
    return {
        "success": True,
        "tenant_id": tenant_id,
        "domain": tenant.domain,
        "status": "deregistered",
        "contact_email_required": bool(tenant.contact_email),
    }


async def restore_license(tenant_id: str, admin_user: str) -> dict[str, Any]:
    """Restore a revoked tenant — sets is_active=True and ACTIVE on all nodes."""
    factory = get_session_factory()
    async with factory() as session:
        tenant_result = await session.execute(
            select(EdgeTenant).where(EdgeTenant.tenant_id == tenant_id)
        )
        tenant = tenant_result.scalar_one_or_none()
        if tenant is None:
            return {"success": False, "error": f"Tenant {tenant_id} not found"}

        tenant.is_active = True
        tenant.registration_state = "active"
        await session.execute(
            update(EdgeNode)
            .where(EdgeNode.tenant_id == tenant_id)
            .values(state="ACTIVE")
        )
        await session.commit()

    logger.info("License restored for tenant %s (domain=%s) by admin %s", tenant_id, tenant.domain, admin_user)
    return {"success": True, "tenant_id": tenant_id, "status": "active"}


async def force_sync(tenant_id: str) -> dict[str, Any]:
    """Mark a tenant's nodes as pending re-sync by resetting to ACTIVE state."""
    factory = get_session_factory()
    async with factory() as session:
        result = await session.execute(
            update(EdgeNode)
            .where(EdgeNode.tenant_id == tenant_id, EdgeNode.state == "SYNCED")
            .values(state="ACTIVE")
        )
        await session.commit()
        affected = result.rowcount

    return {"success": True, "tenant_id": tenant_id, "nodes_reset": affected}
