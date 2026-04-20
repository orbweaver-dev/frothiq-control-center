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
# LFD Settings
# ---------------------------------------------------------------------------

@router.get("/lfd/settings")
async def lfd_settings(
    _: TokenPayload = Depends(require_super_admin),
    session: AsyncSession = Depends(_db),
):
    return await svc.get_lfd_settings(session)


class LFDSettingsBody(BaseModel):
    block_threshold: str | None = None
    block_duration_minutes: str | None = None
    permanent_block: str | None = None
    email_alerts: str | None = None
    alert_email: str | None = None


@router.put("/lfd/settings")
async def update_lfd(
    body: LFDSettingsBody,
    request: Request,
    token: TokenPayload = Depends(require_super_admin),
    session: AsyncSession = Depends(_db),
):
    payload = {k: v for k, v in body.model_dump().items() if v is not None}
    return await svc.update_lfd_settings(session, payload, token.email, _ip(request))


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

@router.get("/validation/status")
async def validation_status(
    _: TokenPayload = Depends(require_super_admin),
    session: AsyncSession = Depends(_db),
):
    return await svc.get_validation_status(session)


class ValidationSettingsBody(BaseModel):
    interval_minutes: str | None = None
    passes_required: str | None = None


@router.put("/validation/settings")
async def update_validation(
    body: ValidationSettingsBody,
    request: Request,
    token: TokenPayload = Depends(require_super_admin),
    session: AsyncSession = Depends(_db),
):
    payload = {k: v for k, v in body.model_dump().items() if v is not None}
    return await svc.update_validation_settings(session, payload, token.email, _ip(request))


# ---------------------------------------------------------------------------
# Decommission
# ---------------------------------------------------------------------------

@router.get("/decommission/status")
async def decommission_status(
    _: TokenPayload = Depends(require_super_admin),
    session: AsyncSession = Depends(_db),
):
    return await svc.get_decommission_status(session)


@router.post("/decommission/run")
async def run_decommission(
    request: Request,
    token: TokenPayload = Depends(require_super_admin),
    session: AsyncSession = Depends(_db),
):
    return await svc.run_decommission(session, token.email, _ip(request))


# ---------------------------------------------------------------------------
# Defense Audit Log
# ---------------------------------------------------------------------------

@router.get("/audit")
async def defense_audit(
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    category: str | None = Query(None),
    _: TokenPayload = Depends(require_super_admin),
    session: AsyncSession = Depends(_db),
):
    return await svc.get_defense_audit(session, limit=limit, offset=offset, category=category)
