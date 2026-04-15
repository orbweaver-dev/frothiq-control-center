"""
Threat Propagation routes — /api/v1/cc/propagation/*

The Control Center is the distribution hub for global threat envelopes.
It polls frothiq-core for qualified signals, enforces tenant tier-policy gates,
signs envelopes (delegating to frothiq-core's signing layer via the core client),
and pushes signed envelopes to registered edge plugins.

Endpoints
---------
  GET  /propagation/status          — propagation engine health + stats
  POST /propagation/dispatch        — manually trigger a propagation run
  GET  /propagation/signals         — list qualified threat signals from core
  GET  /propagation/envelopes       — list pending envelopes from core
  POST /propagation/distribute      — push an envelope to a specific tenant's edge
  GET  /propagation/history         — recent dispatch history (last 100 runs)
  POST /propagation/receive         — edge plugin delivers an inbound envelope for
                                      CC-side validation (verify + audit only)
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field

from frothiq_control_center.auth import (
    TokenPayload,
    require_read_only,
    require_security_analyst,
    require_super_admin,
)
from frothiq_control_center.services.audit_service import log_action
from frothiq_control_center.services.core_client import CoreClientError, core_client

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/propagation", tags=["threat-propagation"])

# In-memory dispatch history (ring buffer, last 100 runs)
_dispatch_history: list[dict] = []
_MAX_HISTORY = 100

# Tier rank for policy gate evaluation (mirrors frothiq-core models.py)
_TIER_RANK = {"free": 0, "pro": 1, "enterprise": 2}


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class DistributeRequest(BaseModel):
    eid:       str  = Field(..., description="Envelope ID to distribute")
    tenant_id: str  = Field(..., description="Target tenant to push to")


class ReceiveEnvelopeRequest(BaseModel):
    """Edge plugin submits an inbound envelope for CC-side audit/validation."""
    wire: dict = Field(..., description="Full signed envelope wire dict")
    source_agent_id: Optional[str] = Field(None)
    source_tenant_id: Optional[str] = Field(None)


class DispatchResult(BaseModel):
    run_id:             str
    signals_evaluated:  int
    signals_qualified:  int
    envelopes_fetched:  int
    distributions_sent: int
    errors:             list[str]
    dispatched_at:      float


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _record_dispatch(result: dict) -> None:
    _dispatch_history.append(result)
    if len(_dispatch_history) > _MAX_HISTORY:
        _dispatch_history.pop(0)


async def _fetch_pending_envelopes() -> list[dict]:
    """Fetch envelopes from frothiq-core pending queue."""
    try:
        resp = await core_client.get("/api/v2/threat/envelopes/pending")
        return resp.get("envelopes", [])
    except (CoreClientError, Exception) as exc:
        logger.warning("Failed to fetch pending envelopes from core: %s", exc)
        return []


async def _ack_envelope(eid: str) -> None:
    """Acknowledge envelope receipt to remove it from the core's pending queue."""
    try:
        await core_client.post("/api/v2/threat/envelope/ack", {"eid": eid})
    except Exception as exc:
        logger.warning("Failed to ack envelope %s: %s", eid, exc)


async def _push_envelope_to_edge(tenant_id: str, wire: dict) -> bool:
    """
    Push a signed envelope to a tenant's registered edge plugin.

    Uses the edge management service to look up the tenant's plugin endpoint
    and deliver the envelope via HTTP POST.
    Returns True on success, False on failure.
    """
    from frothiq_control_center.services.edge_service import get_edge_endpoint

    try:
        endpoint = await get_edge_endpoint(tenant_id)
        if not endpoint:
            logger.warning("No edge endpoint registered for tenant %s", tenant_id)
            return False

        import httpx
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                f"{endpoint}/frothiq/receive-envelope",
                json={"envelope": wire},
                headers={"X-FrothIQ-Dispatch": "1"},
            )
            if resp.status_code == 200:
                logger.info("Pushed envelope %s to tenant %s", wire.get("eid"), tenant_id)
                return True
            else:
                logger.warning(
                    "Edge push failed for tenant %s: HTTP %d", tenant_id, resp.status_code
                )
                return False
    except Exception as exc:
        logger.warning("Edge push exception for tenant %s: %s", tenant_id, exc)
        return False


async def _get_eligible_tenants(tier_min: str) -> list[dict]:
    """
    Return tenants whose tier meets or exceeds *tier_min*.
    Falls back gracefully if the tenants list is unavailable.
    """
    tier_min_rank = _TIER_RANK.get(tier_min, 99)
    try:
        resp = await core_client.get("/api/v2/internal/tenants")
        tenants = resp.get("tenants", [])
        return [
            t for t in tenants
            if _TIER_RANK.get(t.get("tier", "free"), 0) >= tier_min_rank
        ]
    except Exception as exc:
        logger.warning("Could not fetch tenant list for propagation: %s", exc)
        return []


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get("/status", summary="Propagation engine health and statistics")
async def propagation_status(
    _: TokenPayload = Depends(require_read_only),
):
    try:
        core_stats = await core_client.get("/api/v2/threat/stats")
    except Exception:
        core_stats = {}

    return {
        "engine":           "threat-propagation",
        "core_stats":       core_stats,
        "dispatch_runs":    len(_dispatch_history),
        "last_dispatch":    _dispatch_history[-1].get("dispatched_at") if _dispatch_history else None,
    }


@router.get("/signals", summary="List qualified threat signals from frothiq-core")
async def list_threat_signals(
    min_score: int = 60,
    min_confidence: float = 0.55,
    token: TokenPayload = Depends(require_security_analyst),
):
    try:
        resp = await core_client.get(
            "/api/v2/threat/signals",
            params={"min_score": min_score, "min_confidence": min_confidence},
        )
        return resp
    except CoreClientError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail)


@router.get("/envelopes", summary="List pending envelopes from frothiq-core")
async def list_pending_envelopes(
    _: TokenPayload = Depends(require_security_analyst),
):
    envelopes = await _fetch_pending_envelopes()
    return {"envelopes": envelopes, "count": len(envelopes)}


@router.post("/dispatch", response_model=DispatchResult, summary="Run a propagation cycle")
async def dispatch_propagation(
    request: Request,
    token: TokenPayload = Depends(require_super_admin),
):
    """
    Fetch all qualified envelopes from frothiq-core, apply tier-policy gates,
    and push to eligible edge plugins. Acks each successfully distributed
    envelope back to core.
    """
    import uuid

    run_id = str(uuid.uuid4())[:8]
    started = time.time()
    errors: list[str] = []
    distributions_sent = 0

    await log_action(
        user=token.sub,
        action="propagation.dispatch.start",
        detail={"run_id": run_id},
        request=request,
    )

    # 1. Fetch pending envelopes
    envelopes = await _fetch_pending_envelopes()

    # 2. For each envelope, find eligible tenants and push
    for env_item in envelopes:
        wire      = env_item.get("wire", {})
        eid       = env_item.get("eid", wire.get("eid", ""))
        tier_min  = env_item.get("tier_min", "enterprise")
        policy    = env_item.get("policy", "alert_only")
        ip        = env_item.get("ip", "?")

        if not wire or not eid:
            errors.append(f"Malformed envelope item: missing wire/eid")
            continue

        # Get tenants qualified for this tier level
        eligible = await _get_eligible_tenants(tier_min)

        if not eligible:
            logger.debug("No eligible tenants for tier_min=%s (envelope %s)", tier_min, eid)
            # Still ack so it doesn't pile up indefinitely
            await _ack_envelope(eid)
            continue

        # Push to each eligible tenant
        pushed_to = 0
        for tenant in eligible:
            tenant_id = tenant.get("tenant_id") or tenant.get("id", "")
            if not tenant_id:
                continue
            ok = await _push_envelope_to_edge(tenant_id, wire)
            if ok:
                pushed_to += 1
                distributions_sent += 1
            else:
                errors.append(f"Push failed: eid={eid} tenant={tenant_id}")

        if pushed_to > 0:
            await _ack_envelope(eid)
            logger.info(
                "Propagated envelope %s (ip=%s policy=%s) to %d tenants",
                eid, ip, policy, pushed_to,
            )

    elapsed = round(time.time() - started, 3)
    result = {
        "run_id":             run_id,
        "signals_evaluated":  len(envelopes),
        "signals_qualified":  len(envelopes),
        "envelopes_fetched":  len(envelopes),
        "distributions_sent": distributions_sent,
        "errors":             errors,
        "dispatched_at":      started,
        "elapsed_seconds":    elapsed,
    }
    _record_dispatch(result)

    await log_action(
        user=token.sub,
        action="propagation.dispatch.complete",
        detail=result,
        request=request,
    )

    return DispatchResult(**{k: result[k] for k in DispatchResult.__fields__})


@router.post(
    "/distribute",
    summary="Push a specific envelope to a specific tenant",
)
async def distribute_envelope(
    body: DistributeRequest,
    request: Request,
    token: TokenPayload = Depends(require_super_admin),
):
    """Manually push a single envelope to a single tenant's edge plugin."""
    envelopes = await _fetch_pending_envelopes()
    match = next((e for e in envelopes if e.get("eid") == body.eid), None)
    if not match:
        raise HTTPException(
            status_code=404,
            detail=f"Envelope {body.eid!r} not found in pending queue",
        )

    wire = match.get("wire", {})
    ok = await _push_envelope_to_edge(body.tenant_id, wire)
    if not ok:
        raise HTTPException(
            status_code=502,
            detail=f"Failed to push envelope to tenant {body.tenant_id!r}",
        )

    await _ack_envelope(body.eid)
    await log_action(
        user=token.sub,
        action="propagation.manual_distribute",
        detail={"eid": body.eid, "tenant_id": body.tenant_id},
        request=request,
    )
    return {"distributed": True, "eid": body.eid, "tenant_id": body.tenant_id}


@router.get("/history", summary="Recent propagation dispatch history")
async def propagation_history(
    _: TokenPayload = Depends(require_read_only),
):
    return {
        "history": list(reversed(_dispatch_history)),
        "count":   len(_dispatch_history),
    }


@router.post(
    "/receive",
    summary="CC-side envelope validation (audit only — does not apply blocks)",
)
async def receive_envelope_audit(
    body: ReceiveEnvelopeRequest,
    request: Request,
    token: TokenPayload = Depends(require_security_analyst),
):
    """
    Validate an inbound signed envelope for audit/inspection purposes.
    The CC never applies blocks itself — it only verifies authenticity.
    """
    try:
        resp = await core_client.post(
            "/api/v2/threat/envelope/verify",
            body.wire,
        )
        await log_action(
            user=token.sub,
            action="propagation.envelope_verified",
            detail={
                "eid": body.wire.get("eid"),
                "source_agent": body.source_agent_id,
                "source_tenant": body.source_tenant_id,
            },
            request=request,
        )
        return resp
    except CoreClientError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail)
