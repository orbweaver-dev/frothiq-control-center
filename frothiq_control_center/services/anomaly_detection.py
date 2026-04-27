"""
FrothIQ Anomaly Detection Subsystem

Runs on a 5-minute loop and scans the threat intelligence tables for patterns
that indicate coordinated or escalating attacks.  Results are written as
AnomalyEvent rows, deduplicated so the same condition does not flood the table.

Detection algorithms
────────────────────
traffic_spike       — tenant block rate is 2x+ above its own 7-day baseline
cross_tenant_attack — same IP is actively hitting 3+ distinct tenant sites
systematic_scan     — 10+ sequential IPs from one /24 CIDR blocked in 30 min
rapid_escalation    — IP threat_score jumped to 90+ with 5+ reports in 30 min
"""
from __future__ import annotations

import ipaddress
import json
import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from frothiq_control_center.integrations.database import get_session_factory
from frothiq_control_center.models.edge import AnomalyEvent, ThreatReport

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


def _ip_to_slash24(ip: str) -> str | None:
    """Return the /24 network string for an IPv4 address, or None for IPv6."""
    try:
        addr = ipaddress.ip_address(ip)
        if addr.version != 4:
            return None
        net = ipaddress.ip_network(f"{ip}/24", strict=False)
        return str(net)
    except ValueError:
        return None


async def _already_open(session: AsyncSession, anomaly_type: str,
                        tenant_id: str | None, ip: str | None,
                        window_minutes: int = 60) -> bool:
    """
    Return True if an unacknowledged event of this type+scope already exists
    within the dedup window. Prevents re-firing on every scan cycle.
    """
    q = (
        select(AnomalyEvent)
        .where(
            AnomalyEvent.anomaly_type  == anomaly_type,
            AnomalyEvent.acknowledged  == False,        # noqa: E712
            AnomalyEvent.detected_at   >= _ago(window_minutes),
        )
    )
    if tenant_id is not None:
        q = q.where(AnomalyEvent.tenant_id == tenant_id)
    if ip is not None:
        q = q.where(AnomalyEvent.ip == ip)

    result = await session.execute(q.limit(1))
    return result.scalar_one_or_none() is not None


async def _write_event(
    session: AsyncSession,
    *,
    anomaly_type: str,
    severity: str,
    description: str,
    detail: dict,
    tenant_id: str | None = None,
    edge_id: str | None = None,
    ip: str | None = None,
) -> AnomalyEvent:
    event = AnomalyEvent(
        anomaly_type=anomaly_type,
        severity=severity,
        tenant_id=tenant_id,
        edge_id=edge_id,
        ip=ip,
        description=description,
        detail_json=json.dumps(detail),
        detected_at=_utcnow(),
    )
    session.add(event)
    return event


# ─────────────────────────────────────────────────────────────────────────────
# Detection algorithms
# ─────────────────────────────────────────────────────────────────────────────

async def _detect_traffic_spike(session: AsyncSession) -> int:
    """
    Tenant block rate 2x+ above its own 7-day baseline.

    Uses ThreatReport.last_seen as a proxy for block rate per tenant — counts
    distinct IPs seen per tenant in the rolling window, compares against the
    daily average over the previous 7 days.

    Returns count of new anomaly events written.
    """
    # IPs per tenant in last 60 minutes
    recent_result = await session.execute(
        select(
            ThreatReport.tenant_id,
            func.count(func.distinct(ThreatReport.ip)).label("recent_count"),
        )
        .where(ThreatReport.last_seen >= _ago(60))
        .group_by(ThreatReport.tenant_id)
        .having(func.count(func.distinct(ThreatReport.ip)) >= 10)
    )
    recent_by_tenant: dict[str, int] = {r.tenant_id: r.recent_count for r in recent_result}

    if not recent_by_tenant:
        return 0

    # 7-day average (distinct IPs per day) per tenant
    baseline_result = await session.execute(
        select(
            ThreatReport.tenant_id,
            func.count(func.distinct(ThreatReport.ip)).label("total_count"),
        )
        .where(ThreatReport.last_seen >= _ago_days(7))
        .group_by(ThreatReport.tenant_id)
    )
    baseline: dict[str, float] = {
        r.tenant_id: r.total_count / 7.0 / 24.0   # per-hour rate over 7 days
        for r in baseline_result
    }

    written = 0
    for tenant_id, recent in recent_by_tenant.items():
        hourly_baseline = baseline.get(tenant_id, 0)
        if hourly_baseline < 1:
            hourly_baseline = 1  # avoid division by zero / over-sensitivity on new tenants

        multiplier = recent / hourly_baseline
        if multiplier < 2.0:
            continue

        severity = "critical" if multiplier >= 5.0 else ("high" if multiplier >= 3.0 else "medium")

        if await _already_open(session, "traffic_spike", tenant_id, None, window_minutes=60):
            continue

        await _write_event(
            session,
            anomaly_type="traffic_spike",
            severity=severity,
            tenant_id=tenant_id,
            description=(
                f"Traffic spike: {recent} distinct IPs blocked in the last hour "
                f"({multiplier:.1f}x above 7-day baseline of {hourly_baseline:.1f}/hr)."
            ),
            detail={
                "recent_count":      recent,
                "hourly_baseline":   round(hourly_baseline, 2),
                "multiplier":        round(multiplier, 2),
                "window_minutes":    60,
                "baseline_days":     7,
            },
        )
        written += 1

    return written


async def _detect_cross_tenant_attack(session: AsyncSession) -> int:
    """
    Same IP actively hitting 3+ distinct tenant sites in the last 2 hours.

    Uses ThreatReport.tenant_count (pre-computed on each upsert) and
    last_seen to filter for currently-active threats.
    """
    result = await session.execute(
        select(ThreatReport)
        .where(
            ThreatReport.last_seen      >= _ago(120),
            ThreatReport.tenant_count   >= 3,
        )
        .order_by(ThreatReport.tenant_count.desc())
        .limit(100)
    )
    rows = result.scalars().all()

    written = 0
    for row in rows:
        severity = "critical" if row.tenant_count >= 5 else "high"

        if await _already_open(session, "cross_tenant_attack", None, row.ip, window_minutes=120):
            continue

        await _write_event(
            session,
            anomaly_type="cross_tenant_attack",
            severity=severity,
            ip=row.ip,
            description=(
                f"Cross-tenant attack: {row.ip} is actively targeting "
                f"{row.tenant_count} distinct sites (threat_score={row.threat_score}, "
                f"report_count={row.report_count})."
            ),
            detail={
                "ip":           row.ip,
                "tenant_count": row.tenant_count,
                "threat_score": row.threat_score,
                "report_count": row.report_count,
                "last_seen":    row.last_seen.isoformat() if row.last_seen else None,
            },
        )
        written += 1

    return written


async def _detect_systematic_scan(session: AsyncSession) -> int:
    """
    10+ sequential IPs from the same /24 CIDR blocked per tenant in 30 minutes.

    Indicates a systematic network scan or distributed botnet coordinating
    from a single ISP block.
    """
    result = await session.execute(
        select(ThreatReport.tenant_id, ThreatReport.ip)
        .where(ThreatReport.last_seen >= _ago(30))
    )
    rows = result.all()

    # Group by (tenant_id, /24)
    buckets: dict[tuple[str, str], list[str]] = {}
    for row in rows:
        cidr24 = _ip_to_slash24(row.ip)
        if cidr24 is None:
            continue
        key = (row.tenant_id, cidr24)
        buckets.setdefault(key, []).append(row.ip)

    written = 0
    for (tenant_id, cidr24), ips in buckets.items():
        unique_ips = list(set(ips))
        if len(unique_ips) < 10:
            continue

        severity = "critical" if len(unique_ips) >= 20 else "high"

        if await _already_open(session, "systematic_scan", tenant_id, None, window_minutes=30):
            continue

        await _write_event(
            session,
            anomaly_type="systematic_scan",
            severity=severity,
            tenant_id=tenant_id,
            description=(
                f"Systematic scan: {len(unique_ips)} distinct IPs from {cidr24} "
                f"blocked in the last 30 minutes on tenant {tenant_id}."
            ),
            detail={
                "cidr24":        cidr24,
                "unique_ips":    len(unique_ips),
                "sample_ips":    unique_ips[:10],
                "window_minutes": 30,
            },
        )
        written += 1

    return written


async def _detect_rapid_escalation(session: AsyncSession) -> int:
    """
    IP threat_score jumped to 90+ with 5+ reports in the last 30 minutes.

    Catches IPs that went from obscure to highly dangerous very quickly —
    typical of newly-commissioned botnets or freshly-sold IP blocks.
    """
    result = await session.execute(
        select(ThreatReport)
        .where(
            ThreatReport.last_seen    >= _ago(30),
            ThreatReport.threat_score >= 90,
            ThreatReport.report_count >= 5,
        )
        .order_by(ThreatReport.threat_score.desc())
        .limit(50)
    )
    rows = result.scalars().all()

    written = 0
    for row in rows:
        severity = "critical" if row.threat_score >= 95 else "high"

        if await _already_open(session, "rapid_escalation", row.tenant_id, row.ip, window_minutes=30):
            continue

        await _write_event(
            session,
            anomaly_type="rapid_escalation",
            severity=severity,
            tenant_id=row.tenant_id,
            ip=row.ip,
            description=(
                f"Rapid escalation: {row.ip} reached threat_score={row.threat_score} "
                f"with {row.report_count} reports in the last 30 minutes."
            ),
            detail={
                "ip":           row.ip,
                "threat_score": row.threat_score,
                "report_count": row.report_count,
                "tenant_count": row.tenant_count,
                "last_seen":    row.last_seen.isoformat() if row.last_seen else None,
            },
        )
        written += 1

    return written


# ─────────────────────────────────────────────────────────────────────────────
# Main scan entry point
# ─────────────────────────────────────────────────────────────────────────────

async def run_scan() -> dict:
    """
    Run all four detection passes in a single DB session and commit results.

    Returns a summary dict suitable for logging or API response:
      {
        "traffic_spike": N,
        "cross_tenant_attack": N,
        "systematic_scan": N,
        "rapid_escalation": N,
        "total_new": N,
        "scanned_at": "ISO8601",
      }
    """
    factory = get_session_factory()
    counts: dict[str, int] = {}

    async with factory() as session:
        counts["traffic_spike"]       = await _detect_traffic_spike(session)
        counts["cross_tenant_attack"] = await _detect_cross_tenant_attack(session)
        counts["systematic_scan"]     = await _detect_systematic_scan(session)
        counts["rapid_escalation"]    = await _detect_rapid_escalation(session)
        await session.commit()

    total = sum(counts.values())
    if total > 0:
        logger.info(
            "anomaly_scan: %d new events — spike=%d cross_tenant=%d scan=%d escalation=%d",
            total,
            counts["traffic_spike"],
            counts["cross_tenant_attack"],
            counts["systematic_scan"],
            counts["rapid_escalation"],
        )

    return {**counts, "total_new": total, "scanned_at": _utcnow().isoformat()}


# ─────────────────────────────────────────────────────────────────────────────
# Acknowledge helper (used by API routes)
# ─────────────────────────────────────────────────────────────────────────────

async def acknowledge_event(event_id: str, acknowledged_by: str) -> bool:
    """
    Mark an anomaly event as acknowledged. Returns True on success, False if not found.
    """
    factory = get_session_factory()
    async with factory() as session:
        result = await session.execute(
            select(AnomalyEvent).where(AnomalyEvent.id == event_id).limit(1)
        )
        event = result.scalar_one_or_none()
        if not event:
            return False
        event.acknowledged    = True
        event.acknowledged_at = _utcnow()
        event.acknowledged_by = acknowledged_by
        await session.commit()
    return True


async def list_events(
    *,
    unacknowledged_only: bool = False,
    severity: str | None = None,
    anomaly_type: str | None = None,
    tenant_id: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> dict:
    """Return recent anomaly events with optional filters."""
    factory = get_session_factory()
    async with factory() as session:
        q = select(AnomalyEvent).order_by(AnomalyEvent.detected_at.desc())

        if unacknowledged_only:
            q = q.where(AnomalyEvent.acknowledged == False)  # noqa: E712
        if severity:
            q = q.where(AnomalyEvent.severity == severity)
        if anomaly_type:
            q = q.where(AnomalyEvent.anomaly_type == anomaly_type)
        if tenant_id:
            q = q.where(AnomalyEvent.tenant_id == tenant_id)

        total_result = await session.execute(
            select(func.count()).select_from(q.subquery())
        )
        total = total_result.scalar_one()

        rows_result = await session.execute(q.offset(offset).limit(limit))
        rows = rows_result.scalars().all()

    return {
        "total": total,
        "events": [
            {
                "id":               e.id,
                "detected_at":      e.detected_at.isoformat(),
                "anomaly_type":     e.anomaly_type,
                "severity":         e.severity,
                "tenant_id":        e.tenant_id,
                "edge_id":          e.edge_id,
                "ip":               e.ip,
                "description":      e.description,
                "detail":           json.loads(e.detail_json or "{}"),
                "acknowledged":     e.acknowledged,
                "acknowledged_at":  e.acknowledged_at.isoformat() if e.acknowledged_at else None,
                "acknowledged_by":  e.acknowledged_by,
            }
            for e in rows
        ],
    }


async def get_stats() -> dict:
    """Return counts grouped by type and severity for dashboard widgets."""
    factory = get_session_factory()
    async with factory() as session:
        result = await session.execute(
            select(
                AnomalyEvent.anomaly_type,
                AnomalyEvent.severity,
                func.count().label("count"),
            )
            .where(
                AnomalyEvent.acknowledged == False,  # noqa: E712
                AnomalyEvent.detected_at  >= (datetime.utcnow() - timedelta(days=7)),
            )
            .group_by(AnomalyEvent.anomaly_type, AnomalyEvent.severity)
        )
        rows = result.all()

    by_type: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    for row in rows:
        by_type[row.anomaly_type]     = by_type.get(row.anomaly_type, 0)     + row.count
        by_severity[row.severity]     = by_severity.get(row.severity, 0)     + row.count

    return {
        "open_total":   sum(by_type.values()),
        "by_type":      by_type,
        "by_severity":  by_severity,
    }
