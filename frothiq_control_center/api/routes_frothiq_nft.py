"""
FrothIQ NFT Settings routes — service control, nftables viewer, IP/port management,
LFD configuration, validation, and decommission orchestration.

All system changes go through managed interfaces — never direct rule editing.
"""

from __future__ import annotations

import asyncio
import subprocess

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from frothiq_control_center.auth import TokenPayload, require_super_admin
from frothiq_control_center.integrations.database import get_session_factory
from frothiq_control_center.services import frothiq_nft_service as svc

router = APIRouter(prefix="/frothiq-nft", tags=["frothiq-nft"])


async def _db() -> AsyncSession:
    factory = get_session_factory()
    async with factory() as session:
        yield session


def _ip(request: Request) -> str | None:
    return request.client.host if request.client else None


# ---------------------------------------------------------------------------
# Service Status & Control
# ---------------------------------------------------------------------------

@router.get("/status")
async def service_status(_: TokenPayload = Depends(require_super_admin)):
    return await svc.get_service_status()


class ServiceActionBody(BaseModel):
    service: str
    action: str  # start | stop | restart


@router.post("/service/control")
async def service_control(
    body: ServiceActionBody,
    request: Request,
    token: TokenPayload = Depends(require_super_admin),
    session: AsyncSession = Depends(_db),
):
    result = await svc.control_service(
        session, body.service, body.action, token.email, _ip(request)
    )
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error", "Action failed"))
    return result


# ---------------------------------------------------------------------------
# nftables Viewer (read-only)
# ---------------------------------------------------------------------------

@router.get("/nft/view")
async def nft_view(_: TokenPayload = Depends(require_super_admin)):
    return await svc.get_nft_view()


# ---------------------------------------------------------------------------
# IP List (shared whitelist / blacklist)
# ---------------------------------------------------------------------------

@router.get("/ip-list")
async def list_ips(
    _: TokenPayload = Depends(require_super_admin),
    session: AsyncSession = Depends(_db),
):
    return {"entries": await svc.list_ip_entries(session)}


class AddIPBody(BaseModel):
    ip: str
    label: str
    list_type: str  # whitelist | blacklist
    notes: str | None = None


@router.post("/ip-list")
async def add_ip(
    body: AddIPBody,
    request: Request,
    token: TokenPayload = Depends(require_super_admin),
    session: AsyncSession = Depends(_db),
):
    result = await svc.add_ip_entry(
        session, body.ip, body.label, body.list_type, body.notes,
        token.email, _ip(request),
    )
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error"))
    return result


@router.delete("/ip-list/{entry_id}")
async def remove_ip(
    entry_id: str,
    request: Request,
    token: TokenPayload = Depends(require_super_admin),
    session: AsyncSession = Depends(_db),
):
    result = await svc.remove_ip_entry(session, entry_id, token.email, _ip(request))
    if not result.get("success"):
        raise HTTPException(status_code=404, detail=result.get("error"))
    return result


class RemoveNftElementBody(BaseModel):
    ip: str
    set_name: str  # "whitelist" | "blacklist"


@router.delete("/nft-element")
async def remove_nft_element(
    body: RemoveNftElementBody,
    _: TokenPayload = Depends(require_super_admin),
):
    """Remove an IP directly from a live nftables set (for entries not tracked in DB)."""
    if body.set_name not in ("whitelist", "blacklist"):
        raise HTTPException(status_code=400, detail="set_name must be whitelist or blacklist")

    def _do_remove() -> bool:
        try:
            r = subprocess.run(
                ["/usr/sbin/nft", "delete", "element", "inet", "frothiq",
                 body.set_name, f"{{ {body.ip} }}"],
                capture_output=True, timeout=5,
            )
            return r.returncode == 0
        except Exception:
            return False

    success = await asyncio.to_thread(_do_remove)
    if not success:
        raise HTTPException(status_code=400, detail=f"Failed to remove {body.ip} from {body.set_name}")
    return {"success": True, "ip": body.ip, "set_name": body.set_name}


# ---------------------------------------------------------------------------
# Port Rules
# ---------------------------------------------------------------------------

@router.get("/port-rules")
async def list_ports(
    _: TokenPayload = Depends(require_super_admin),
    session: AsyncSession = Depends(_db),
):
    return {"rules": await svc.list_port_rules(session)}


class AddPortBody(BaseModel):
    port: int
    protocol: str  # tcp | udp | both
    action: str    # accept | drop
    description: str = ""


@router.post("/port-rules")
async def add_port(
    body: AddPortBody,
    request: Request,
    token: TokenPayload = Depends(require_super_admin),
    session: AsyncSession = Depends(_db),
):
    result = await svc.add_port_rule(
        session, body.port, body.protocol, body.action, body.description,
        token.email, _ip(request),
    )
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error"))
    return result


@router.delete("/port-rules/{rule_id}")
async def remove_port(
    rule_id: str,
    request: Request,
    token: TokenPayload = Depends(require_super_admin),
    session: AsyncSession = Depends(_db),
):
    result = await svc.remove_port_rule(session, rule_id, token.email, _ip(request))
    if not result.get("success"):
        raise HTTPException(status_code=404, detail=result.get("error"))
    return result


# ---------------------------------------------------------------------------
# LFD Settings (per-service thresholds — mirrors CSF LF_SSHD, LF_FTPD, etc.)
# ---------------------------------------------------------------------------

@router.get("/lfd/settings")
async def lfd_settings(
    _: TokenPayload = Depends(require_super_admin),
    session: AsyncSession = Depends(_db),
):
    return await svc.get_category_settings(session, "lfd", svc.LFD_DEFAULTS)


@router.put("/lfd/settings")
async def update_lfd(
    body: dict,
    request: Request,
    token: TokenPayload = Depends(require_super_admin),
    session: AsyncSession = Depends(_db),
):
    return await svc.update_category_settings(session, "lfd", body, svc.LFD_DEFAULTS.keys(), token.email, _ip(request))


# ---------------------------------------------------------------------------
# Port Settings (TCP_IN, TCP_OUT, UDP_IN, etc. — mirrors CSF port config)
# ---------------------------------------------------------------------------

@router.get("/settings/ports")
async def get_port_settings(
    _: TokenPayload = Depends(require_super_admin),
    session: AsyncSession = Depends(_db),
):
    return await svc.get_category_settings(session, "ports", svc.PORT_DEFAULTS)


@router.put("/settings/ports")
async def update_port_settings(
    body: dict,
    request: Request,
    token: TokenPayload = Depends(require_super_admin),
    session: AsyncSession = Depends(_db),
):
    return await svc.update_category_settings(session, "ports", body, svc.PORT_DEFAULTS.keys(), token.email, _ip(request))


# ---------------------------------------------------------------------------
# Blocking Settings (SYNFLOOD, CONNLIMIT, CC_DENY, LF_PERMBLOCK, etc.)
# ---------------------------------------------------------------------------

@router.get("/settings/blocking")
async def get_blocking_settings(
    _: TokenPayload = Depends(require_super_admin),
    session: AsyncSession = Depends(_db),
):
    return await svc.get_category_settings(session, "blocking", svc.BLOCKING_DEFAULTS)


@router.put("/settings/blocking")
async def update_blocking_settings(
    body: dict,
    request: Request,
    token: TokenPayload = Depends(require_super_admin),
    session: AsyncSession = Depends(_db),
):
    return await svc.update_category_settings(session, "blocking", body, svc.BLOCKING_DEFAULTS.keys(), token.email, _ip(request))


# ---------------------------------------------------------------------------
# Alert Settings (LF_ALERT_TO, LF_EMAIL_ALERT, per-event toggles)
# ---------------------------------------------------------------------------

@router.get("/settings/alerts")
async def get_alert_settings(
    _: TokenPayload = Depends(require_super_admin),
    session: AsyncSession = Depends(_db),
):
    return await svc.get_category_settings(session, "alerts", svc.ALERT_DEFAULTS)


@router.put("/settings/alerts")
async def update_alert_settings(
    body: dict,
    request: Request,
    token: TokenPayload = Depends(require_super_admin),
    session: AsyncSession = Depends(_db),
):
    return await svc.update_category_settings(session, "alerts", body, svc.ALERT_DEFAULTS.keys(), token.email, _ip(request))


@router.post("/settings/alerts/test")
async def test_alert_email(
    token: TokenPayload = Depends(require_super_admin),
    session: AsyncSession = Depends(_db),
):
    """Send a test email using the current alert settings."""
    import smtplib
    import socket
    from email.message import EmailMessage

    settings = await svc.get_category_settings(session, "alerts", svc.ALERT_DEFAULTS)
    to_addr = settings.get("LF_ALERT_TO", "").strip()
    from_name = settings.get("LF_ALERT_FROM", "FrothIQ Defense").strip() or "FrothIQ Defense"
    smtp_host = settings.get("LF_ALERT_SMTP", "").strip()

    if not to_addr:
        raise HTTPException(status_code=400, detail="No alert destination address configured (LF_ALERT_TO is empty)")

    hostname = socket.gethostname()
    fqdn = socket.getfqdn()
    from_addr = f"frothiq-alerts@{fqdn}"

    msg = EmailMessage()
    msg["Subject"] = f"[FrothIQ Defense] Test Alert — {hostname}"
    msg["From"] = f"{from_name} <{from_addr}>"
    msg["To"] = to_addr
    msg.set_content(
        f"This is a test alert from FrothIQ Defense.\n\n"
        f"Host:      {hostname}\n"
        f"Sent by:   {token.email or token.sub}\n"
        f"Timestamp: {__import__('datetime').datetime.now().strftime('%Y-%m-%d %H:%M:%S %Z')}\n\n"
        f"If you received this email, alert delivery is working correctly."
    )

    def _send() -> None:
        host = smtp_host or "localhost"
        port = 25
        with smtplib.SMTP(host, port, timeout=10) as s:
            s.sendmail(from_addr, [to_addr], msg.as_string())

    try:
        await asyncio.to_thread(_send)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Email delivery failed: {exc}")

    return {"success": True, "to": to_addr, "from": from_addr, "smtp": smtp_host or "localhost"}


# ---------------------------------------------------------------------------
# CIDR Consolidation Analysis
# ---------------------------------------------------------------------------

@router.get("/cidr-analysis")
async def list_cidr_recommendations(
    status: str | None = Query(None, description="Filter by status: pending, applied, dismissed"),
    _: TokenPayload = Depends(require_super_admin),
    session: AsyncSession = Depends(_db),
):
    """
    List CIDR consolidation recommendations produced by background scans.

    Each recommendation represents a CIDR range that could replace multiple
    individual IP blacklist entries, reducing list size and improving coverage.
    """
    from frothiq_control_center.services import cidr_analyzer
    recs = await cidr_analyzer.list_recommendations(session, status)

    pending = [r for r in recs if r["status"] == "pending"]
    total_savings = sum(r["entries_saved"] for r in pending)
    return {
        "recommendations": recs,
        "count": len(recs),
        "pending_count": len(pending),
        "potential_entries_saved": total_savings,
    }


@router.post("/cidr-analysis/scan")
async def trigger_cidr_scan(
    token: TokenPayload = Depends(require_super_admin),
    session: AsyncSession = Depends(_db),
):
    """
    Trigger an immediate CIDR consolidation scan of the live blacklist.
    Results are persisted as recommendations for operator review.
    """
    from frothiq_control_center.services import cidr_analyzer
    result = await cidr_analyzer.run_scan(session)
    return result


@router.post("/cidr-analysis/{rec_id}/apply")
async def apply_cidr_recommendation(
    rec_id: str,
    request: Request,
    token: TokenPayload = Depends(require_super_admin),
    session: AsyncSession = Depends(_db),
):
    """
    Apply a pending CIDR recommendation:
    - Adds the CIDR to the live nftables blacklist
    - Removes individual IPs now covered by the CIDR from nftables
    - Removes covered IPs from the frothiq_ip_list DB table
    """
    from frothiq_control_center.services import cidr_analyzer
    result = await cidr_analyzer.apply_recommendation(session, rec_id, token.email)
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error"))
    return result


@router.post("/cidr-analysis/{rec_id}/dismiss")
async def dismiss_cidr_recommendation(
    rec_id: str,
    request: Request,
    token: TokenPayload = Depends(require_super_admin),
    session: AsyncSession = Depends(_db),
):
    """Dismiss a pending CIDR recommendation without applying it."""
    from frothiq_control_center.services import cidr_analyzer
    result = await cidr_analyzer.dismiss_recommendation(session, rec_id, token.email)
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error"))
    return result
