"""
Edge Outage Service — detects and records site outage windows.

Outage sources:
  1. plugin_reported  — plugin calls POST /api/v1/edge/outage (e.g. block-caused lockout)
  2. heartbeat_miss   — background loop notices a node has gone silent

Alert flow:
  - On every new open outage window, send an email to the tenant's contact_email.
  - When a window closes, send a recovery notice.
"""

from __future__ import annotations

import asyncio
import logging
import smtplib
import socket
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from typing import Sequence

from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from frothiq_control_center.config import get_settings
from frothiq_control_center.models.edge import EdgeNode, EdgeTenant
from frothiq_control_center.models.outage import EdgeOutageEvent
from frothiq_control_center.services import frappe_ticket_client as _ftc

logger = logging.getLogger(__name__)

# Heartbeat-miss thresholds
_DEGRADED_MINUTES = 10
_OFFLINE_MINUTES  = 30


# ---------------------------------------------------------------------------
# Plugin-reported outage (called from the API route)
# ---------------------------------------------------------------------------

async def receive_plugin_outage(
    session: AsyncSession,
    edge_id: str,
    tenant_id: str,
    outage_type: str,
    cause: str,
    cause_detail: str,
    auto_resolved: bool,
    duration_sec: int,
    site_url: str,
) -> EdgeOutageEvent:
    """
    Process an outage report submitted directly by the plugin.
    Because the plugin self-heals before reporting, most plugin-reported
    outages arrive already resolved (auto_resolved=True).
    """
    node = await _get_node(session, edge_id)
    domain = node.domain if node else site_url.replace("https://", "").replace("http://", "").rstrip("/")

    severity = _severity_for_type(outage_type)
    now = datetime.now(timezone.utc)

    event = EdgeOutageEvent(
        edge_id      = edge_id,
        tenant_id    = tenant_id,
        domain       = domain,
        outage_type  = outage_type,
        cause        = cause[:128],
        cause_detail = cause_detail[:2000],
        started_at   = now if duration_sec == 0 else now - timedelta(seconds=duration_sec),
        resolved_at  = now if auto_resolved else None,
        duration_sec = duration_sec if auto_resolved else None,
        auto_resolved = auto_resolved,
        severity     = severity,
        is_open      = not auto_resolved,
    )
    session.add(event)
    await session.flush()

    # Send alert email regardless of auto_resolved — the site had an outage.
    await _send_outage_alert(session, event, tenant_id, domain, recovered=auto_resolved)

    # Frappe ticket: create new or amend existing (dedup by ref_tag)
    ref_tag   = f"edge:{edge_id[:24]}"
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    existing_ticket = await _ftc.find_open_issue(ref_tag)

    if not existing_ticket:
        ticket_name = await _ftc.create_issue(
            subject=f"Site outage on {domain} ({ref_tag})",
            description=(
                f"**Type:** {outage_type}\n"
                f"**Cause:** {cause}\n"
                f"**Detail:** {cause_detail}\n"
                f"**Auto-resolved:** {auto_resolved}\n"
                f"**Duration:** {duration_sec}s\n"
                f"**Edge ID:** {edge_id}\n"
                f"**Reported at:** {timestamp}"
            ),
            priority="Urgent" if not auto_resolved else "High",
        )
        if ticket_name:
            event.frappe_ticket_id = ticket_name
            logger.info(
                "outage_ticket_created edge=%s ticket=%s type=%s",
                edge_id[:16], ticket_name, outage_type,
            )
        else:
            logger.error(
                "outage_ticket_create_failed edge=%s domain=%s type=%s",
                edge_id[:16], domain, outage_type,
            )
    else:
        # Amend the existing ticket with details of this new occurrence
        event.frappe_ticket_id = existing_ticket
        note = (
            f"**Recurring failure — {timestamp}**\n"
            f"Type: {outage_type} | Cause: {cause}\n"
            f"Detail: {cause_detail}\n"
            f"Auto-resolved: {auto_resolved} | Duration: {duration_sec}s"
        )
        amended = await _ftc.append_to_issue(existing_ticket, note)
        logger.warning(
            "outage_ticket_amended edge=%s ticket=%s amended=%s type=%s",
            edge_id[:16], existing_ticket, amended, outage_type,
        )

    if auto_resolved and event.frappe_ticket_id:
        await _ftc.resolve_issue(
            event.frappe_ticket_id,
            resolution_note=f"Automatically resolved by plugin self-healing after {duration_sec}s.",
        )

    await session.commit()

    logger.warning(
        "outage_received edge=%s domain=%s type=%s auto_resolved=%s duration=%ds",
        edge_id[:16], domain, outage_type, auto_resolved, duration_sec,
    )
    return event


# ---------------------------------------------------------------------------
# Heartbeat-miss detector (called from background loop)
# ---------------------------------------------------------------------------

async def detect_offline_nodes(factory: async_sessionmaker[AsyncSession]) -> None:
    """
    Scan for edge nodes that have missed heartbeats beyond threshold.
    Opens a new outage window if none is already open for the node.
    Closes open windows for nodes that have since recovered.
    """
    now = datetime.now(timezone.utc)
    degraded_cutoff = now - timedelta(minutes=_DEGRADED_MINUTES)
    offline_cutoff  = now - timedelta(minutes=_OFFLINE_MINUTES)

    async with factory() as session:
        # Find all active nodes
        result = await session.execute(
            select(EdgeNode).where(
                EdgeNode.state.in_(["ACTIVE", "SYNCED", "DEGRADED"])
            )
        )
        nodes: Sequence[EdgeNode] = result.scalars().all()

        for node in nodes:
            last_seen = node.last_seen_at
            if last_seen is None:
                continue

            if last_seen.tzinfo is None:
                last_seen = last_seen.replace(tzinfo=timezone.utc)

            # Check for open outage windows on this node
            open_result = await session.execute(
                select(EdgeOutageEvent).where(
                    and_(
                        EdgeOutageEvent.edge_id == node.edge_id,
                        EdgeOutageEvent.is_open == True,  # noqa: E712
                    )
                )
            )
            open_window: EdgeOutageEvent | None = open_result.scalar_one_or_none()

            if last_seen < offline_cutoff:
                outage_type = "heartbeat_miss_offline"
                severity    = "critical"
            elif last_seen < degraded_cutoff:
                outage_type = "heartbeat_miss_degraded"
                severity    = "high"
            else:
                # Node is alive — close any open window
                if open_window and open_window.outage_type.startswith("heartbeat_miss"):
                    await _close_window(session, open_window, auto_resolved=True)
                continue

            # Node is offline/degraded
            min_silent = int((now - last_seen).total_seconds() // 60)
            if open_window:
                # Already tracking this outage; update severity if it worsened
                if severity == "critical" and open_window.severity != "critical":
                    open_window.severity = "critical"
                    await session.flush()
                    logger.warning(
                        "outage_escalated edge=%s ticket=%s severity=critical min_silent=%d",
                        node.edge_id[:16], open_window.frappe_ticket_id or "none", min_silent,
                    )
                # Amend the existing Frappe ticket with a status update
                if open_window.frappe_ticket_id:
                    timestamp = now.strftime("%Y-%m-%d %H:%M UTC")
                    note = (
                        f"**Still offline — {timestamp}**\n"
                        f"Type: {outage_type} | Severity: {severity}\n"
                        f"Last seen: {min_silent} minutes ago | Domain: {node.domain}"
                    )
                    amended = await _ftc.append_to_issue(open_window.frappe_ticket_id, note)
                    logger.warning(
                        "outage_ticket_updated edge=%s ticket=%s amended=%s min_silent=%d",
                        node.edge_id[:16], open_window.frappe_ticket_id, amended, min_silent,
                    )
            else:
                # Open a new window
                domain = node.domain
                cause_detail = (
                    f"Node {node.edge_id[:16]} last seen {min_silent} minutes ago."
                )
                event = EdgeOutageEvent(
                    edge_id      = node.edge_id,
                    tenant_id    = node.tenant_id,
                    domain       = domain,
                    outage_type  = outage_type,
                    cause        = "heartbeat_miss",
                    cause_detail = cause_detail,
                    severity     = severity,
                    is_open      = True,
                    alert_sent   = False,
                )
                session.add(event)
                await session.flush()
                await _send_outage_alert(session, event, node.tenant_id, domain, recovered=False)

                # Frappe ticket: create or amend
                ref_tag   = f"edge:{node.edge_id[:24]}"
                timestamp = now.strftime("%Y-%m-%d %H:%M UTC")
                existing_ticket = await _ftc.find_open_issue(ref_tag)
                if not existing_ticket:
                    ticket_name = await _ftc.create_issue(
                        subject=f"Site offline: {domain} ({ref_tag})",
                        description=(
                            f"**Type:** {outage_type}\n"
                            f"**Domain:** {domain}\n"
                            f"**Last seen:** {min_silent} minutes ago\n"
                            f"**Edge ID:** {node.edge_id}\n"
                            f"**Detected at:** {timestamp}"
                        ),
                        priority="Urgent",
                    )
                    if ticket_name:
                        event.frappe_ticket_id = ticket_name
                        logger.warning(
                            "outage_ticket_created edge=%s ticket=%s type=%s min_silent=%d",
                            node.edge_id[:16], ticket_name, outage_type, min_silent,
                        )
                    else:
                        logger.error(
                            "outage_ticket_create_failed edge=%s domain=%s type=%s",
                            node.edge_id[:16], domain, outage_type,
                        )
                else:
                    # Amend: existing ticket from a prior outage window still open in Frappe
                    event.frappe_ticket_id = existing_ticket
                    note = (
                        f"**New outage window — {timestamp}**\n"
                        f"Type: {outage_type} | Last seen: {min_silent} minutes ago\n"
                        f"Domain: {domain} | Edge: {node.edge_id[:16]}"
                    )
                    amended = await _ftc.append_to_issue(existing_ticket, note)
                    logger.warning(
                        "outage_ticket_amended edge=%s ticket=%s amended=%s type=%s",
                        node.edge_id[:16], existing_ticket, amended, outage_type,
                    )

                logger.warning(
                    "outage_opened edge=%s domain=%s type=%s min_silent=%d ticket=%s",
                    node.edge_id[:16], domain, outage_type, min_silent,
                    event.frappe_ticket_id or "none",
                )

        await session.commit()


async def close_open_windows_for_node(session: AsyncSession, edge_id: str) -> None:
    """
    Called by heartbeat processing when a node checks in.
    Closes any open heartbeat-miss outage window and sends a recovery email.
    """
    result = await session.execute(
        select(EdgeOutageEvent).where(
            and_(
                EdgeOutageEvent.edge_id == edge_id,
                EdgeOutageEvent.is_open == True,  # noqa: E712
                EdgeOutageEvent.outage_type.like("heartbeat_miss%"),
            )
        )
    )
    for window in result.scalars().all():
        await _close_window(session, window, auto_resolved=True)
        logger.info("outage_closed_on_heartbeat edge=%s outage_id=%s", edge_id[:16], window.id)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

async def _get_node(session: AsyncSession, edge_id: str) -> EdgeNode | None:
    result = await session.execute(select(EdgeNode).where(EdgeNode.edge_id == edge_id))
    return result.scalar_one_or_none()


async def _close_window(session: AsyncSession, window: EdgeOutageEvent, auto_resolved: bool) -> None:
    now = datetime.now(timezone.utc)
    started = window.started_at
    if started.tzinfo is None:
        started = started.replace(tzinfo=timezone.utc)
    window.resolved_at  = now
    window.duration_sec = max(0, int((now - started).total_seconds()))
    window.auto_resolved = auto_resolved
    window.is_open      = False
    await session.flush()
    await _send_recovery_alert(session, window)
    if window.frappe_ticket_id:
        await _ftc.resolve_issue(
            window.frappe_ticket_id,
            resolution_note=f"Site recovered. Outage duration: {window.duration_sec}s.",
        )


def _severity_for_type(outage_type: str) -> str:
    if outage_type == "block_rule_lockout":
        return "critical"
    if outage_type == "heartbeat_miss_offline":
        return "critical"
    if outage_type == "heartbeat_miss_degraded":
        return "high"
    return "high"


# ---------------------------------------------------------------------------
# Email alerting
# ---------------------------------------------------------------------------

async def _send_outage_alert(
    session: AsyncSession,
    event: EdgeOutageEvent,
    tenant_id: str,
    domain: str,
    recovered: bool,
) -> None:
    to_addr = await _get_contact_email(session, tenant_id)
    if not to_addr:
        logger.debug("no contact_email for tenant %s — skipping outage alert", tenant_id)
        return

    settings = get_settings()
    hostname  = socket.gethostname()
    from_addr = f"frothiq-alerts@{socket.getfqdn()}"
    subject   = (
        f"[FrothIQ] ✅ Site recovered: {domain}" if recovered
        else f"[FrothIQ] 🔴 Site outage detected: {domain}"
    )

    body_lines = [
        f"FrothIQ Defense has detected a site availability issue.",
        f"",
        f"Site:       {domain}",
        f"Event type: {event.outage_type}",
        f"Cause:      {event.cause}",
        f"Details:    {event.cause_detail}",
        f"Started:    {event.started_at.strftime('%Y-%m-%d %H:%M:%S UTC')}",
    ]
    if recovered:
        body_lines += [
            f"Resolved:   {event.resolved_at.strftime('%Y-%m-%d %H:%M:%S UTC') if event.resolved_at else 'now'}",
            f"Duration:   {event.duration_sec or 0} seconds",
            f"",
            f"The site is now responding normally. If you believe the block rule",
            f"that caused this outage should be re-applied, log in to your FrothIQ",
            f"dashboard to review and manually re-block the IP.",
        ]
    else:
        body_lines += [
            f"",
            f"This may indicate a plugin issue, server problem, or an incorrect",
            f"firewall rule. Please check your site immediately.",
            f"",
            f"FrothIQ Dashboard: https://mc3.orbweaver.dev",
        ]

    body_lines += [
        f"",
        f"— FrothIQ Defense by OrbWeaver",
        f"  {hostname}",
    ]

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"]    = f"FrothIQ Defense <{from_addr}>"
    msg["To"]      = to_addr
    msg.set_content("\n".join(body_lines))

    def _send():
        with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=10) as s:
            s.sendmail(from_addr, [to_addr], msg.as_string())

    try:
        await asyncio.to_thread(_send)
        event.alert_sent = True
        await session.flush()
        logger.info("outage_alert_sent to=%s domain=%s recovered=%s", to_addr, domain, recovered)
    except Exception as exc:
        logger.error("outage_alert_send_failed to=%s error=%s", to_addr, exc)


async def _send_recovery_alert(session: AsyncSession, window: EdgeOutageEvent) -> None:
    await _send_outage_alert(
        session, window, window.tenant_id, window.domain, recovered=True
    )


async def _get_contact_email(session: AsyncSession, tenant_id: str) -> str | None:
    result = await session.execute(
        select(EdgeTenant.contact_email).where(EdgeTenant.tenant_id == tenant_id)
    )
    row = result.scalar_one_or_none()
    return row if row else None


# ---------------------------------------------------------------------------
# Recent outages query (for dashboard)
# ---------------------------------------------------------------------------

async def get_recent_outages(session: AsyncSession, limit: int = 20) -> list[dict]:
    result = await session.execute(
        select(EdgeOutageEvent)
        .order_by(EdgeOutageEvent.started_at.desc())
        .limit(limit)
    )
    rows = result.scalars().all()
    return [
        {
            "id":           r.id,
            "edge_id":      r.edge_id,
            "domain":       r.domain,
            "outage_type":  r.outage_type,
            "cause":        r.cause,
            "severity":     r.severity,
            "is_open":      r.is_open,
            "alert_sent":   r.alert_sent,
            "auto_resolved": r.auto_resolved,
            "started_at":   r.started_at.isoformat(),
            "resolved_at":  r.resolved_at.isoformat() if r.resolved_at else None,
            "duration_sec":    r.duration_sec,
            "frappe_ticket_id": r.frappe_ticket_id,
        }
        for r in rows
    ]
