"""
FrothIQ Edge Node Integrity Score System

Computes a 0–100 integrity score for each edge node from live data.
No storage — calculated on demand from EdgeNode + EdgeEulaRecord records.

Score components (max 100):
  heartbeat_freshness   25 pts — how recently the node checked in
  plugin_version        20 pts — running the latest plugin build
  protection_mode       20 pts — block > protect > monitor
  node_state            20 pts — SYNCED > ACTIVE > REGISTERED > DEGRADED
  eula_current          15 pts — current EULA version accepted

Grade labels:
  90–100  healthy
  70–89   degraded
  50–69   warning
  0–49    critical
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from frothiq_control_center.integrations.database import get_session_factory
from frothiq_control_center.models.edge import EdgeEulaRecord, EdgeNode

# Must stay in sync with routes_edge.py LATEST_PLUGIN_VERSION
CURRENT_PLUGIN_VERSION = "0.25.4"
CURRENT_EULA_VERSION   = "1.1"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


# ─────────────────────────────────────────────────────────────────────────────
# Score computation
# ─────────────────────────────────────────────────────────────────────────────

def _heartbeat_score(last_seen_at: datetime | None) -> tuple[int, str]:
    if last_seen_at is None:
        return 0, "never_seen"
    minutes = (_utcnow() - last_seen_at).total_seconds() / 60
    if minutes < 5:
        return 25, "online"
    if minutes < 15:
        return 20, "recent"
    if minutes < 30:
        return 15, "lagging"
    if minutes < 60:
        return 10, "stale"
    if minutes < 120:
        return 5, "very_stale"
    return 0, "offline"


def _version_score(plugin_version: str) -> tuple[int, str]:
    if plugin_version == CURRENT_PLUGIN_VERSION:
        return 20, "current"
    # Parse major.minor.patch for proximity
    try:
        cur = tuple(int(x) for x in CURRENT_PLUGIN_VERSION.split("."))
        run = tuple(int(x) for x in plugin_version.split("."))
        # Same major.minor, one patch behind
        if cur[:2] == run[:2] and cur[2] - run[2] == 1:
            return 10, "one_patch_behind"
    except (ValueError, IndexError):
        pass
    return 0, "outdated"


def _protection_score(protection_mode: str | None) -> tuple[int, str]:
    modes = {"block": 20, "protect": 15, "monitor": 5}
    pts = modes.get(protection_mode or "", 0)
    label = protection_mode or "unknown"
    return pts, label


def _state_score(state: str) -> tuple[int, str]:
    states = {"SYNCED": 20, "ACTIVE": 15, "REGISTERED": 5, "DEGRADED": 0}
    pts = states.get(state, 0)
    return pts, state.lower()


def _eula_score(eula_version: str | None) -> tuple[int, str]:
    if eula_version == CURRENT_EULA_VERSION:
        return 15, "current"
    if eula_version is not None:
        return 0, "outdated"
    return 0, "not_accepted"


def _grade(total: int) -> str:
    if total >= 90:
        return "healthy"
    if total >= 70:
        return "degraded"
    if total >= 50:
        return "warning"
    return "critical"


def _compute_score(node: EdgeNode, eula_version: str | None) -> dict[str, Any]:
    hb_pts,  hb_label  = _heartbeat_score(node.last_seen_at)
    ver_pts, ver_label  = _version_score(node.plugin_version)
    pm_pts,  pm_label   = _protection_score(node.protection_mode)
    st_pts,  st_label   = _state_score(node.state)
    eu_pts,  eu_label   = _eula_score(eula_version)

    total = hb_pts + ver_pts + pm_pts + st_pts + eu_pts

    return {
        "edge_id":          node.edge_id,
        "tenant_id":        node.tenant_id,
        "domain":           node.domain,
        "score":            total,
        "grade":            _grade(total),
        "plugin_version":   node.plugin_version,
        "state":            node.state,
        "protection_mode":  node.protection_mode,
        "last_seen_at":     node.last_seen_at.isoformat() if node.last_seen_at else None,
        "eula_version":     eula_version,
        "components": {
            "heartbeat_freshness": {"score": hb_pts,  "max": 25, "detail": hb_label},
            "plugin_version":      {"score": ver_pts, "max": 20, "detail": ver_label},
            "protection_mode":     {"score": pm_pts,  "max": 20, "detail": pm_label},
            "node_state":          {"score": st_pts,  "max": 20, "detail": st_label},
            "eula_current":        {"score": eu_pts,  "max": 15, "detail": eu_label},
        },
    }


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

async def score_node(edge_id: str) -> dict[str, Any] | None:
    """Return the integrity score for a single edge node, or None if not found."""
    factory = get_session_factory()
    async with factory() as session:
        node_result = await session.execute(
            select(EdgeNode).where(EdgeNode.edge_id == edge_id).limit(1)
        )
        node = node_result.scalar_one_or_none()
        if node is None:
            return None

        eula_result = await session.execute(
            select(EdgeEulaRecord.eula_version)
            .where(EdgeEulaRecord.edge_id == edge_id)
            .order_by(EdgeEulaRecord.accepted_at.desc())
            .limit(1)
        )
        eula_version = eula_result.scalar_one_or_none()

    return _compute_score(node, eula_version)


async def score_fleet(
    *,
    state_filter: str | None = None,
    grade_filter: str | None = None,
    limit: int = 200,
    offset: int = 0,
) -> dict[str, Any]:
    """
    Return integrity scores for all non-removed edge nodes.

    Optional filters:
      state_filter — SYNCED | ACTIVE | REGISTERED | DEGRADED
      grade_filter — healthy | degraded | warning | critical
    """
    factory = get_session_factory()
    async with factory() as session:
        q = select(EdgeNode).where(EdgeNode.state != "REMOVED")
        if state_filter:
            q = q.where(EdgeNode.state == state_filter.upper())

        # Total count before grade filter (grade is computed, not stored)
        count_result = await session.execute(
            select(func.count()).select_from(q.subquery())
        )
        total_db = count_result.scalar_one()

        nodes_result = await session.execute(q.order_by(EdgeNode.last_seen_at.desc()))
        nodes = nodes_result.scalars().all()

        # Batch-load most recent EULA per edge_id
        if nodes:
            edge_ids = [n.edge_id for n in nodes]
            eula_result = await session.execute(
                select(
                    EdgeEulaRecord.edge_id,
                    func.max(EdgeEulaRecord.accepted_at).label("latest_at"),
                    EdgeEulaRecord.eula_version,
                )
                .where(EdgeEulaRecord.edge_id.in_(edge_ids))
                .group_by(EdgeEulaRecord.edge_id, EdgeEulaRecord.eula_version)
            )
            # Keep only the most recent per edge_id
            eula_map: dict[str, str] = {}
            for row in eula_result.all():
                if row.edge_id not in eula_map:
                    eula_map[row.edge_id] = row.eula_version
        else:
            eula_map = {}

    scored = [_compute_score(n, eula_map.get(n.edge_id)) for n in nodes]

    # Apply grade filter post-computation
    if grade_filter:
        scored = [s for s in scored if s["grade"] == grade_filter]

    total = len(scored)
    page = scored[offset: offset + limit]

    # Fleet summary
    grade_counts: dict[str, int] = {}
    avg_score = round(sum(s["score"] for s in scored) / total, 1) if total else 0
    for s in scored:
        grade_counts[s["grade"]] = grade_counts.get(s["grade"], 0) + 1

    return {
        "total":        total,
        "average_score": avg_score,
        "by_grade":     grade_counts,
        "nodes":        page,
    }


async def get_fleet_stats() -> dict[str, Any]:
    """Lightweight fleet-level summary for dashboard widgets."""
    result = await score_fleet(limit=10000)
    return {
        "total_nodes":   result["total"],
        "average_score": result["average_score"],
        "by_grade":      result["by_grade"],
        "current_plugin_version": CURRENT_PLUGIN_VERSION,
        "current_eula_version":   CURRENT_EULA_VERSION,
    }
