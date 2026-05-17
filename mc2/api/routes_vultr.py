"""
ServOps — Vultr cloud storage management.

Object Storage:
  GET  /vultr/object-storage                  — list clusters + buckets
  POST /vultr/object-storage/buckets          — create bucket
  DELETE /vultr/object-storage/buckets/{id}   — delete bucket
  GET  /vultr/object-storage/{id}/credentials — fetch S3 credentials for a subscription

Block Storage:
  GET  /vultr/block-storage                   — list volumes
  POST /vultr/block-storage                   — create volume
  POST /vultr/block-storage/{id}/attach       — attach to instance
  POST /vultr/block-storage/{id}/detach       — detach
  DELETE /vultr/block-storage/{id}            — delete volume

Settings:
  GET  /vultr/settings                        — fetch stored API key (masked)
  POST /vultr/settings                        — save Vultr API key

All endpoints require super_admin.
"""

from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path
from typing import Any, Optional

import httpx
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from .routes_auth import require_super_admin

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/vultr", tags=["vultr"])

# ---------------------------------------------------------------------------
# Settings persistence
# ---------------------------------------------------------------------------

_SETTINGS_FILE = Path(os.environ.get("CC_VULTR_SETTINGS", "/var/lib/mc2/vultr-settings.json"))


def _load_settings() -> dict:
    try:
        if _SETTINGS_FILE.exists():
            return json.loads(_SETTINGS_FILE.read_text())
    except (json.JSONDecodeError, OSError):
        pass
    return {}


def _save_settings(data: dict) -> None:
    _SETTINGS_FILE.parent.mkdir(parents=True, exist_ok=True)
    _SETTINGS_FILE.write_text(json.dumps(data, indent=2))


def _get_api_key() -> str:
    key = _load_settings().get("api_key", "")
    if not key:
        raise HTTPException(status_code=400, detail="Vultr API key not configured. Set it in ServOps → Cloud Storage → Settings.")
    return key


# ---------------------------------------------------------------------------
# Vultr API client
# ---------------------------------------------------------------------------

VULTR_BASE = "https://api.vultr.com/v2"


async def _vultr(method: str, path: str, body: dict | None = None) -> Any:
    key = _get_api_key()
    url = f"{VULTR_BASE}{path}"
    headers = {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}
    async with httpx.AsyncClient(timeout=20.0) as client:
        resp = await client.request(method, url, headers=headers, json=body)
    if resp.status_code in (200, 201, 204):
        return resp.json() if resp.content else {}
    detail = resp.text[:400] if resp.content else resp.reason_phrase
    raise HTTPException(status_code=resp.status_code, detail=f"Vultr API error: {detail}")


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class VultrSettings(BaseModel):
    api_key: str


class CreateBucket(BaseModel):
    cluster_id: int
    label: str


class CreateVolume(BaseModel):
    region: str
    size_gb: int
    label: Optional[str] = None
    block_type: Optional[str] = "high_perf"


class AttachVolume(BaseModel):
    instance_id: str
    live: Optional[bool] = True


# ---------------------------------------------------------------------------
# Settings endpoints
# ---------------------------------------------------------------------------

@router.get("/settings")
async def get_settings(_user=Depends(require_super_admin)):
    s = _load_settings()
    key = s.get("api_key", "")
    masked = f"{'*' * (len(key) - 6)}{key[-6:]}" if len(key) > 6 else ("****" if key else "")
    return {"configured": bool(key), "api_key_masked": masked}


@router.post("/settings")
async def save_settings(payload: VultrSettings, _user=Depends(require_super_admin)):
    if len(payload.api_key) < 20:
        raise HTTPException(status_code=400, detail="API key looks too short — check the value")
    data = _load_settings()
    data["api_key"] = payload.api_key.strip()
    _save_settings(data)
    return {"ok": True}


# ---------------------------------------------------------------------------
# Object Storage endpoints
# ---------------------------------------------------------------------------

@router.get("/object-storage")
async def list_object_storage(_user=Depends(require_super_admin)):
    """List all Vultr Object Storage subscriptions and clusters."""
    try:
        subs_raw = await _vultr("GET", "/object-storage")
        clusters_raw = await _vultr("GET", "/object-storage/clusters")
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    subs = subs_raw.get("object_storages", [])
    clusters = clusters_raw.get("clusters", [])

    # Enrich each subscription with its cluster label
    cluster_map = {c["id"]: c for c in clusters}
    for s in subs:
        cid = s.get("cluster_id")
        c = cluster_map.get(cid, {})
        s["cluster_label"] = c.get("label", "")
        s["cluster_hostname"] = c.get("hostname", "")
        s["cluster_region"] = c.get("region", "")

    return {
        "subscriptions": subs,
        "clusters": clusters,
        "checked_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


@router.post("/object-storage/buckets")
async def create_bucket(payload: CreateBucket, _user=Depends(require_super_admin)):
    """Create a new object storage subscription/bucket."""
    result = await _vultr("POST", "/object-storage", {
        "cluster_id": payload.cluster_id,
        "label": payload.label,
    })
    return {"ok": True, "subscription": result.get("object_storage", {})}


@router.delete("/object-storage/buckets/{subscription_id}")
async def delete_bucket(subscription_id: str, _user=Depends(require_super_admin)):
    """Delete an object storage subscription."""
    await _vultr("DELETE", f"/object-storage/{subscription_id}")
    return {"ok": True}


@router.get("/object-storage/{subscription_id}/credentials")
async def get_bucket_credentials(subscription_id: str, _user=Depends(require_super_admin)):
    """Fetch S3 access key + secret for an object storage subscription."""
    result = await _vultr("GET", f"/object-storage/{subscription_id}")
    sub = result.get("object_storage", {})
    return {
        "subscription_id": subscription_id,
        "label": sub.get("label", ""),
        "hostname": sub.get("hostname", ""),
        "s3_access_key": sub.get("s3_access_key", ""),
        "s3_secret_key": sub.get("s3_secret_key", ""),
        "region": sub.get("region", ""),
        "status": sub.get("status", ""),
    }


# ---------------------------------------------------------------------------
# Block Storage endpoints
# ---------------------------------------------------------------------------

@router.get("/block-storage")
async def list_block_storage(_user=Depends(require_super_admin)):
    """List all block storage volumes."""
    result = await _vultr("GET", "/blocks")
    volumes = result.get("blocks", [])
    return {
        "volumes": volumes,
        "total": len(volumes),
        "checked_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


@router.post("/block-storage")
async def create_volume(payload: CreateVolume, _user=Depends(require_super_admin)):
    """Create a new block storage volume."""
    body: dict[str, Any] = {
        "region": payload.region,
        "size_gb": payload.size_gb,
        "block_type": payload.block_type,
    }
    if payload.label:
        body["label"] = payload.label
    result = await _vultr("POST", "/blocks", body)
    return {"ok": True, "volume": result.get("block", {})}


@router.post("/block-storage/{volume_id}/attach")
async def attach_volume(volume_id: str, payload: AttachVolume, _user=Depends(require_super_admin)):
    """Attach a block volume to an instance."""
    await _vultr("POST", f"/blocks/{volume_id}/attach", {
        "instance_id": payload.instance_id,
        "live": payload.live,
    })
    return {"ok": True}


@router.post("/block-storage/{volume_id}/detach")
async def detach_volume(volume_id: str, _user=Depends(require_super_admin)):
    """Detach a block volume from its current instance."""
    await _vultr("POST", f"/blocks/{volume_id}/detach", {"live": True})
    return {"ok": True}


@router.delete("/block-storage/{volume_id}")
async def delete_volume(volume_id: str, _user=Depends(require_super_admin)):
    """Permanently delete a block storage volume."""
    await _vultr("DELETE", f"/blocks/{volume_id}")
    return {"ok": True}


# ---------------------------------------------------------------------------
# Convenience: list Vultr regions (for creating volumes)
# ---------------------------------------------------------------------------

@router.get("/regions")
async def list_regions(_user=Depends(require_super_admin)):
    result = await _vultr("GET", "/regions")
    return {"regions": result.get("regions", [])}
