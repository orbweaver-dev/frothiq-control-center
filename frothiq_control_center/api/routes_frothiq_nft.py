"""
FrothIQ NFT Settings routes — service control, nftables viewer, IP/port management,
LFD configuration, validation, and decommission orchestration.

All system changes go through managed interfaces — never direct rule editing.
"""

from __future__ import annotations

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
