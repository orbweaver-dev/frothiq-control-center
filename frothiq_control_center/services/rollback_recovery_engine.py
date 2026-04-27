"""
FrothIQ Rollback & Recovery Engine

Runs on a 10-minute loop and corrects edge nodes and community blocklist
entries that have drifted into an erroneous or stale state.

Recovery passes
───────────────
node_state_reset      — DEGRADED node silent > 30 min → reset to ACTIVE
ip_demotion           — Defense Mesh auto-promoted IP whose threat_score
                        dropped below 50 → remove from nft + frothiq_ip_list
stale_node_cleanup    — REGISTERED node with no heartbeat after 7 days → REMOVED

All actions are written to the recovery_events table for audit and dashboard.
"""
from __future__ import annotations

import asyncio
import json
import logging
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from frothiq_control_center.integrations.database import get_session_factory
from frothiq_control_center.models.defense_settings import FrothiqIPEntry
from frothiq_control_center.models.edge import EdgeNode, ThreatReport

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _ago(minutes: int) -> datetime:
    return _utcnow() - timedelta(minutes=minutes)


def _ago_days(days: int) -> datetime:
    return _utcnow() - timedelta(days=days)


async def _nft_delete_element(ip: str) -> bool:
    """Remove an IP from the live nft blacklist set. Returns True on success."""
    try:
        proc = await asyncio.create_subprocess_exec(
            "sudo", "/usr/sbin/nft", "delete", "element",
            "inet", "frothiq", "blacklist", f"{{ {ip} }}",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await asyncio.wait_for(proc.communicate(), timeout=10)
        if proc.returncode != 0:
            err = stderr.decode().strip()
            # "No such element" means it wasn't in the set — treat as success
            if "No such element" in err or "not found" in err.lower():
                return True
            logger.warning("_nft_delete_element: ip=%s err=%s", ip, err[:120])
            return False
        return True
    except Exception as exc:
        logger.warning("_nft_delete_element: ip=%s exc=%s", ip, exc)
        return False


async def _write_recovery_event(
    session: AsyncSession,
    *,
    recovery_type: str,
    target: str,
    reason: str,
    status: str = "success",
    detail: dict | None = None,
    initiated_by: str = "system",
) -> None:
    await session.execute(
        text(
            "INSERT INTO recovery_events "
            "(id, recovered_at, recovery_type, target, reason, status, detail_json, initiated_by) "
            "VALUES (:id, :ts, :rtype, :target, :reason, :status, :detail, :by)"
        ),
        {
            "id":     str(uuid.uuid4()),
            "ts":     _utcnow(),
            "rtype":  recovery_type,
            "target": target,
            "reason": reason,
            "status": status,
            "detail": json.dumps(detail or {}),
            "by":     initiated_by,
        },
    )


# ─────────────────────────────────────────────────────────────────────────────
# Recovery passes
# ─────────────────────────────────────────────────────────────────────────────

async def _recover_degraded_nodes(session: AsyncSession) -> int:
    """
    Reset DEGRADED nodes that have been silent for > 30 minutes back to ACTIVE.

    DEGRADED nodes accumulate when heartbeats miss. Resetting to ACTIVE allows
    the next successful heartbeat to promote them back to SYNCED normally.
    """
    cutoff = _ago(30)
    result = await session.execute(
        select(EdgeNode).where(
            EdgeNode.state == "DEGRADED",
            EdgeNode.last_seen_at < cutoff,
        )
    )
    nodes = result.scalars().all()

    recovered = 0
    for node in nodes:
        minutes_silent = int((_utcnow() - node.last_seen_at).total_seconds() / 60)
        node.state = "ACTIVE"
        await _write_recovery_event(
            session,
            recovery_type="node_state_reset",
            target=node.edge_id,
            reason=f"Node stuck DEGRADED for {minutes_silent} min without heartbeat; reset to ACTIVE",
            detail={
                "edge_id":        node.edge_id,
                "domain":         node.domain,
                "minutes_silent": minutes_silent,
                "last_seen_at":   node.last_seen_at.isoformat(),
            },
        )
        logger.info(
            "recovery: node_state_reset edge_id=%s domain=%s silent=%dm",
            node.edge_id[:16], node.domain, minutes_silent,
        )
        recovered += 1

    return recovered


async def _demote_stale_ips(session: AsyncSession) -> int:
    """
    Remove auto-promoted community blacklist IPs whose threat_score has dropped
    below 50 — meaning tenant reports were cleared or false-positives corrected.

    Only touches entries created by 'system' (Defense Mesh auto-promotions).
    Admin-created entries are never demoted automatically.
    """
    # Fetch all system-created blacklist entries
    bl_result = await session.execute(
        select(FrothiqIPEntry).where(
            FrothiqIPEntry.list_type == "blacklist",
            FrothiqIPEntry.created_by == "system",
        )
    )
    system_entries = bl_result.scalars().all()

    if not system_entries:
        return 0

    ips = [e.ip for e in system_entries]

    # Get current max threat_score per IP across all tenants
    score_result = await session.execute(
        select(ThreatReport.ip, ThreatReport.threat_score)
        .where(ThreatReport.ip.in_(ips))
        .order_by(ThreatReport.threat_score.desc())
    )
    # max score per IP
    max_score: dict[str, int] = {}
    for row in score_result.all():
        if row.ip not in max_score:
            max_score[row.ip] = row.threat_score

    demoted = 0
    for entry in system_entries:
        current_score = max_score.get(entry.ip, 0)
        if current_score >= 50:
            continue  # Still warranted — leave it

        # Demote: remove from nft then DB
        nft_ok = await _nft_delete_element(entry.ip)
        await session.delete(entry)
        await _write_recovery_event(
            session,
            recovery_type="ip_demotion",
            target=entry.ip,
            reason=(
                f"Auto-promoted IP no longer meets threshold "
                f"(current score={current_score}, threshold=50); removed from blacklist"
            ),
            status="success" if nft_ok else "partial",
            detail={
                "ip":            entry.ip,
                "current_score": current_score,
                "nft_removed":   nft_ok,
                "original_label": entry.label,
            },
        )
        logger.info(
            "recovery: ip_demotion ip=%s score=%d nft_ok=%s",
            entry.ip, current_score, nft_ok,
        )
        demoted += 1

    return demoted


async def _cleanup_stale_registrations(session: AsyncSession) -> int:
    """
    Mark REGISTERED nodes that never sent a heartbeat within 7 days as REMOVED.

    These are nodes that registered but the plugin was immediately deactivated
    or the site was unreachable — they will never transition to ACTIVE and
    should not clutter the active node list.
    """
    cutoff = _ago_days(7)
    result = await session.execute(
        select(EdgeNode).where(
            EdgeNode.state == "REGISTERED",
            EdgeNode.registered_at < cutoff,
            EdgeNode.last_seen_at == EdgeNode.registered_at,  # no heartbeat ever
        )
    )
    nodes = result.scalars().all()

    cleaned = 0
    for node in nodes:
        days_stale = int((_utcnow() - node.registered_at).total_seconds() / 86400)
        node.state = "REMOVED"
        await _write_recovery_event(
            session,
            recovery_type="stale_node_cleanup",
            target=node.edge_id,
            reason=f"Node registered {days_stale} days ago and never sent a heartbeat; marked REMOVED",
            detail={
                "edge_id":       node.edge_id,
                "domain":        node.domain,
                "registered_at": node.registered_at.isoformat(),
                "days_stale":    days_stale,
            },
        )
        logger.info(
            "recovery: stale_node_cleanup edge_id=%s domain=%s days=%d",
            node.edge_id[:16], node.domain, days_stale,
        )
        cleaned += 1

    return cleaned


# ─────────────────────────────────────────────────────────────────────────────
# Main entry point
# ─────────────────────────────────────────────────────────────────────────────

async def run_recovery() -> dict:
    """
    Run all three recovery passes in a single DB session and commit results.

    Returns a summary dict:
      {
        "node_state_reset":    N,
        "ip_demotion":         N,
        "stale_node_cleanup":  N,
        "total_actions":       N,
        "recovered_at":        "ISO8601",
      }
    """
    factory = get_session_factory()
    counts: dict[str, int] = {}

    async with factory() as session:
        counts["node_state_reset"]   = await _recover_degraded_nodes(session)
        counts["ip_demotion"]        = await _demote_stale_ips(session)
        counts["stale_node_cleanup"] = await _cleanup_stale_registrations(session)
        await session.commit()

    total = sum(counts.values())
    if total > 0:
        logger.info(
            "recovery_engine: %d actions — resets=%d demotions=%d cleanups=%d",
            total,
            counts["node_state_reset"],
            counts["ip_demotion"],
            counts["stale_node_cleanup"],
        )

    return {**counts, "total_actions": total, "recovered_at": _utcnow().isoformat()}


# ─────────────────────────────────────────────────────────────────────────────
# Manual node recovery (API-triggered)
# ─────────────────────────────────────────────────────────────────────────────

async def recover_node(edge_id: str, initiated_by: str) -> dict:
    """
    Manually reset a single node to ACTIVE regardless of current state.
    Returns the result dict or raises ValueError if node not found.
    """
    factory = get_session_factory()
    async with factory() as session:
        result = await session.execute(
            select(EdgeNode).where(EdgeNode.edge_id == edge_id).limit(1)
        )
        node = result.scalar_one_or_none()
        if node is None:
            raise ValueError(f"Edge node not found: {edge_id}")

        previous_state = node.state
        node.state = "ACTIVE"
        await _write_recovery_event(
            session,
            recovery_type="node_state_reset",
            target=edge_id,
            reason=f"Manual recovery by {initiated_by} (previous state: {previous_state})",
            initiated_by=initiated_by,
            detail={
                "edge_id":        edge_id,
                "domain":         node.domain,
                "previous_state": previous_state,
            },
        )
        await session.commit()

    return {"edge_id": edge_id, "previous_state": previous_state, "new_state": "ACTIVE"}


# ─────────────────────────────────────────────────────────────────────────────
# Query helpers (for API routes)
# ─────────────────────────────────────────────────────────────────────────────

async def list_recovery_events(
    *,
    recovery_type: str | None = None,
    status: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> dict:
    """Return paginated recovery event log."""
    factory = get_session_factory()
    async with factory() as session:
        where_clauses = ["1=1"]
        params: dict = {}
        if recovery_type:
            where_clauses.append("recovery_type = :rtype")
            params["rtype"] = recovery_type
        if status:
            where_clauses.append("status = :status")
            params["status"] = status

        where = " AND ".join(where_clauses)
        total_result = await session.execute(
            text(f"SELECT COUNT(*) FROM recovery_events WHERE {where}"), params
        )
        total = total_result.scalar_one()

        rows_result = await session.execute(
            text(
                f"SELECT id, recovered_at, recovery_type, target, reason, status, "
                f"detail_json, initiated_by FROM recovery_events "
                f"WHERE {where} ORDER BY recovered_at DESC "
                f"LIMIT :limit OFFSET :offset"
            ),
            {**params, "limit": limit, "offset": offset},
        )
        rows = rows_result.all()

    return {
        "total": total,
        "events": [
            {
                "id":            r.id,
                "recovered_at":  r.recovered_at.isoformat(),
                "recovery_type": r.recovery_type,
                "target":        r.target,
                "reason":        r.reason,
                "status":        r.status,
                "detail":        json.loads(r.detail_json or "{}"),
                "initiated_by":  r.initiated_by,
            }
            for r in rows
        ],
    }


async def get_recovery_stats() -> dict:
    """Return counts grouped by type and status for dashboard widgets."""
    factory = get_session_factory()
    async with factory() as session:
        result = await session.execute(
            text(
                "SELECT recovery_type, status, COUNT(*) as cnt "
                "FROM recovery_events "
                "WHERE recovered_at >= DATE_SUB(NOW(), INTERVAL 7 DAY) "
                "GROUP BY recovery_type, status"
            )
        )
        rows = result.all()

    by_type: dict[str, int] = {}
    by_status: dict[str, int] = {}
    for row in rows:
        by_type[row.recovery_type] = by_type.get(row.recovery_type, 0) + row.cnt
        by_status[row.status]      = by_status.get(row.status, 0)      + row.cnt

    return {
        "total_7d":  sum(by_type.values()),
        "by_type":   by_type,
        "by_status": by_status,
    }
