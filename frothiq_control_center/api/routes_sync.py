"""
Sync routes — read-only subscription state and license state from ERPNext.

These routes proxy calls to the frothiq_frappe billing bridge API.
The CC backend is a pass-through; ERPNext remains the authoritative source.

Rules enforced here:
  - NO billing logic (no plan changes, no invoice creation, no Stripe calls)
  - NO write operations on subscription state
  - ALL data originates from Frappe billing bridge
  - Admin-only endpoints enforce super_admin role
  - Read endpoints enforce read_only (any authenticated user)

Endpoints:
  GET  /sync/subscription-state/summary               — aggregate (admin only)
  GET  /sync/subscription-state/{tenant_id}           — single tenant state
  POST /sync/subscription-state/{tenant_id}/sync      — force cache bust (admin)
  POST /sync/subscription-state/invalidate-cache      — invalidate cache (admin)
  GET  /sync/license-state/bulk                       — all tenants (admin)
  GET  /sync/license-state/{tenant_id}                — single tenant license
"""

from __future__ import annotations

import logging
import time
from typing import Optional

import httpx
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from frothiq_control_center.auth import TokenPayload, require_read_only, require_super_admin
from frothiq_control_center.services.core_client import CoreClientError

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/sync", tags=["sync"])

# ---------------------------------------------------------------------------
# Frappe billing bridge HTTP client helpers
# ---------------------------------------------------------------------------

import os

_FRAPPE_BASE = os.getenv("FRAPPE_SITE_URL", "http://localhost:8000")
_FRAPPE_API_KEY = os.getenv("FRAPPE_API_KEY", "")
_FRAPPE_API_SECRET = os.getenv("FRAPPE_API_SECRET", "")
_TIMEOUT = 15


def _frappe_headers() -> dict[str, str]:
    """Build Frappe API authentication headers."""
    if _FRAPPE_API_KEY and _FRAPPE_API_SECRET:
        return {"Authorization": f"token {_FRAPPE_API_KEY}:{_FRAPPE_API_SECRET}"}
    return {}


async def _frappe_get(path: str, params: dict | None = None) -> dict:
    """
    Make a GET request to the Frappe billing bridge API.
    Raises HTTPException on failure — caller gets a clean 502.
    """
    url = f"{_FRAPPE_BASE}{path}"
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(url, params=params, headers=_frappe_headers())
        if resp.status_code == 403:
            raise HTTPException(status_code=403, detail="Frappe access denied")
        if resp.status_code >= 400:
            body = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {}
            raise HTTPException(
                status_code=502,
                detail=body.get("exc", f"Frappe returned {resp.status_code}"),
            )
        data = resp.json()
        # Frappe wraps responses in {"message": <payload>}
        return data.get("message", data)
    except httpx.TimeoutException:
        raise HTTPException(status_code=504, detail="Frappe billing bridge timed out")
    except httpx.ConnectError:
        raise HTTPException(status_code=502, detail="Frappe billing bridge unreachable")


async def _frappe_post(path: str, body: dict | None = None) -> dict:
    """Make a POST request to the Frappe billing bridge API."""
    url = f"{_FRAPPE_BASE}{path}"
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.post(
                url,
                json=body or {},
                headers={**_frappe_headers(), "Content-Type": "application/json"},
            )
        if resp.status_code == 403:
            raise HTTPException(status_code=403, detail="Frappe access denied")
        if resp.status_code >= 400:
            body_data = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {}
            raise HTTPException(
                status_code=502,
                detail=body_data.get("exc", f"Frappe returned {resp.status_code}"),
            )
        data = resp.json()
        return data.get("message", data)
    except httpx.TimeoutException:
        raise HTTPException(status_code=504, detail="Frappe billing bridge timed out")
    except httpx.ConnectError:
        raise HTTPException(status_code=502, detail="Frappe billing bridge unreachable")


# ---------------------------------------------------------------------------
# Frappe billing bridge endpoint paths
# ---------------------------------------------------------------------------

_SUB_STATE_API = "/api/method/frothiq_frappe.frothiq_billing_bridge.subscription_state_api"


# ---------------------------------------------------------------------------
# Subscription state (read-only proxies)
# ---------------------------------------------------------------------------

@router.get("/subscription-state/summary")
async def subscription_summary(
    _: TokenPayload = Depends(require_super_admin),
):
    """
    Aggregate subscription state across all tenants.
    Admin only. Data sourced from ERPNext via billing bridge.
    """
    return await _frappe_get(f"{_SUB_STATE_API}.subscription_state_summary")


@router.get("/subscription-state/{tenant_id}")
async def get_subscription_state(
    tenant_id: str,
    _: TokenPayload = Depends(require_read_only),
):
    """
    Read-only subscription state for a single tenant.
    Data originates from ERPNext; returned as-is with no modification.
    """
    return await _frappe_get(
        f"{_SUB_STATE_API}.get_subscription_state",
        params={"tenant_id": tenant_id},
    )


@router.post("/subscription-state/{tenant_id}/sync")
async def sync_subscription_state(
    tenant_id: str,
    _: TokenPayload = Depends(require_super_admin),
):
    """
    Force a cache bust + fresh ERPNext fetch for one tenant.
    Admin only. Does not modify any billing state — cache only.
    """
    return await _frappe_post(
        f"{_SUB_STATE_API}.sync_subscription_state",
        body={"tenant_id": tenant_id},
    )


class InvalidateCacheRequest(BaseModel):
    tenant_id: Optional[str] = None


@router.post("/subscription-state/invalidate-cache")
async def invalidate_subscription_cache(
    payload: InvalidateCacheRequest,
    _: TokenPayload = Depends(require_super_admin),
):
    """
    Invalidate subscription cache for one tenant (or all if tenant_id is null).
    Admin only.
    """
    return await _frappe_post(
        f"{_SUB_STATE_API}.invalidate_subscription_cache",
        body={"tenant_id": payload.tenant_id},
    )


# ---------------------------------------------------------------------------
# License state (derived from subscription state — read-only)
# ---------------------------------------------------------------------------

def _derive_license_status(sub_state: dict) -> dict:
    """
    Derive license status from a subscription state dict.

    License state is NOT independent — it is a view over subscription state.
    This derivation mirrors the logic in subscription_state_resolver.py.

    Never add billing logic here — only map subscription fields to license fields.
    """
    status = sub_state.get("subscription_status", "expired")
    grace_until = sub_state.get("grace_until")
    now = time.time()

    if status == "active":
        license_status = "valid"
        license_valid = True
    elif status == "past_due" and grace_until and now < grace_until:
        license_status = "grace_period"
        license_valid = True
    elif status == "past_due":
        license_status = "suspended"
        license_valid = False
    elif status == "cancelled":
        license_status = "suspended"
        license_valid = False
    else:  # expired or unknown
        license_status = "expired"
        license_valid = False

    return {
        "tenant_id":       sub_state.get("tenant_id"),
        "license_valid":   license_valid,
        "license_status":  license_status,
        "effective_plan":  sub_state.get("effective_plan", "free"),
        "enforcement_mode": sub_state.get("enforcement_mode", "alert_only"),
        "features":        sub_state.get("features", {}),
        "limits":          sub_state.get("limits", {}),
        "expiry":          sub_state.get("expiry"),
        "grace_until":     grace_until,
        "last_synced":     sub_state.get("last_updated", now),
        "sync_source":     sub_state.get("source", "fallback"),
    }


def _edge_tenant_to_license(t: dict) -> dict:
    """
    Derive a LicenseStatus-shaped dict from an edge_tenants record.
    Status comes from the CC's own database — no Frappe billing bridge dependency.
    """
    status = t.get("status", "expired")
    license_valid = status == "active"
    license_status = "valid" if license_valid else ("suspended" if status == "suspended" else "expired")
    import time
    last_sync = t.get("last_sync")
    last_synced = time.time()
    if last_sync:
        try:
            from datetime import datetime
            last_synced = datetime.fromisoformat(last_sync).timestamp()
        except Exception:
            pass
    return {
        "tenant_id":        t.get("tenant_id"),
        "domain":           t.get("domain"),
        "license_valid":    license_valid,
        "license_status":   license_status,
        "effective_plan":   t.get("plan", "free"),
        "enforcement_mode": "alert_only",
        "features":         {},
        "limits":           {},
        "expiry":           None,
        "grace_until":      None,
        "last_synced":      last_synced,
        "sync_source":      "edge_db",
    }


@router.get("/license-state/bulk")
async def license_state_bulk(
    _: TokenPayload = Depends(require_super_admin),
):
    """
    Bulk license status for all tenants.
    Derived from CC's own edge_tenants database — no Frappe billing bridge dependency.
    """
    from frothiq_control_center.services.license_service import get_all_license_states
    data = await get_all_license_states()
    tenants_edge = data.get("tenants", [])

    license_tenants = []
    counts: dict[str, int] = {"valid": 0, "grace_period": 0, "suspended": 0, "expired": 0}

    for t in tenants_edge:
        lic = _edge_tenant_to_license(t)
        license_tenants.append(lic)
        ls = lic["license_status"]
        counts[ls] = counts.get(ls, 0) + 1

    return {
        "total":        len(license_tenants),
        "valid":        counts["valid"],
        "grace_period": counts["grace_period"],
        "suspended":    counts["suspended"],
        "expired":      counts["expired"],
        "tenants":      license_tenants,
    }


@router.get("/license-state/{tenant_id}")
async def get_license_state(
    tenant_id: str,
    _: TokenPayload = Depends(require_read_only),
):
    """
    License status for a single tenant.
    Derived from CC's own edge_tenants database.
    """
    from frothiq_control_center.services.license_service import get_tenant_license
    t = await get_tenant_license(tenant_id)
    return _edge_tenant_to_license(t)
