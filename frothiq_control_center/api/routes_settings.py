"""
Portal settings routes — branding, security, and feature configuration.

GET  /settings/portal         — public (no auth); used by login page pre-auth
PATCH /settings/portal        — super_admin
POST  /settings/portal/logo   — super_admin; multipart upload
DELETE /settings/portal/logo  — super_admin
GET   /settings/portal/logo   — public; serves the uploaded logo file
"""

from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status
from fastapi.responses import FileResponse
from pydantic import BaseModel

from frothiq_control_center.auth import TokenPayload, require_super_admin

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/settings", tags=["settings"])

# ---------------------------------------------------------------------------
# Storage paths
# ---------------------------------------------------------------------------

_SETTINGS_ROOT = Path(
    os.environ.get("CC_PORTAL_SETTINGS_DIR", "/var/lib/frothiq/control-center")
)
_SETTINGS_FILE = _SETTINGS_ROOT / "portal_settings.json"
_UPLOADS_DIR = _SETTINGS_ROOT / "uploads"

_ALLOWED_TYPES = {
    "image/png",
    "image/jpeg",
    "image/svg+xml",
    "image/gif",
    "image/webp",
}
_MAX_LOGO_BYTES = 2 * 1024 * 1024  # 2 MB


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------


class PortalSettings(BaseModel):
    portal_title: str = "FrothIQ MC³"
    logo_filename: Optional[str] = None
    theme_accent: str = "#4f8ef7"
    session_timeout_minutes: int = 60
    login_notice: str = ""
    maintenance_mode: bool = False
    updated_at: Optional[float] = None
    updated_by: Optional[str] = None


class PortalSettingsPatch(BaseModel):
    portal_title: Optional[str] = None
    theme_accent: Optional[str] = None
    session_timeout_minutes: Optional[int] = None
    login_notice: Optional[str] = None
    maintenance_mode: Optional[bool] = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _load() -> PortalSettings:
    if _SETTINGS_FILE.exists():
        try:
            return PortalSettings(**json.loads(_SETTINGS_FILE.read_text()))
        except Exception as exc:
            logger.warning("Failed to load portal_settings.json: %s", exc)
    return PortalSettings()


def _save(s: PortalSettings) -> None:
    _SETTINGS_ROOT.mkdir(parents=True, exist_ok=True)
    _SETTINGS_FILE.write_text(s.model_dump_json(indent=2))


def _logo_url(filename: str | None) -> str | None:
    return "/api/v1/cc/settings/portal/logo" if filename else None


def _public_view(s: PortalSettings) -> dict:
    return {**s.model_dump(exclude={"logo_filename"}), "logo_url": _logo_url(s.logo_filename)}


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get("/portal")
async def get_portal_settings():
    """
    Returns current portal settings.
    Public — no authentication required.
    Called by the login page before the user authenticates.
    """
    return _public_view(_load())


@router.patch("/portal")
async def update_portal_settings(
    patch: PortalSettingsPatch,
    user: TokenPayload = Depends(require_super_admin),
):
    """Update portal settings. Requires super_admin."""
    s = _load()

    if patch.portal_title is not None:
        s.portal_title = patch.portal_title.strip() or "FrothIQ MC³"
    if patch.theme_accent is not None:
        # Basic validation — must look like a CSS colour
        val = patch.theme_accent.strip()
        if not (val.startswith("#") and len(val) in (4, 7)):
            raise HTTPException(status_code=422, detail="theme_accent must be a hex colour (#RGB or #RRGGBB)")
        s.theme_accent = val
    if patch.session_timeout_minutes is not None:
        s.session_timeout_minutes = max(5, min(480, patch.session_timeout_minutes))
    if patch.login_notice is not None:
        s.login_notice = patch.login_notice[:500]   # hard cap
    if patch.maintenance_mode is not None:
        s.maintenance_mode = patch.maintenance_mode

    s.updated_at = time.time()
    s.updated_by = user.sub
    _save(s)

    logger.info("Portal settings updated by %s", user.sub)
    return {"ok": True, "settings": _public_view(s)}


@router.post("/portal/logo", status_code=status.HTTP_200_OK)
async def upload_logo(
    file: UploadFile = File(...),
    user: TokenPayload = Depends(require_super_admin),
):
    """
    Upload a new portal logo.
    Accepted: PNG, JPEG, SVG, GIF, WebP — max 2 MB.
    """
    if file.content_type not in _ALLOWED_TYPES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Unsupported type '{file.content_type}'. Allowed: {', '.join(sorted(_ALLOWED_TYPES))}",
        )

    content = await file.read()
    if len(content) > _MAX_LOGO_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="Logo exceeds 2 MB limit",
        )

    _UPLOADS_DIR.mkdir(parents=True, exist_ok=True)
    suffix = Path(file.filename or "logo").suffix or ".png"
    dest = _UPLOADS_DIR / f"portal_logo{suffix}"
    dest.write_bytes(content)

    s = _load()
    s.logo_filename = dest.name
    s.updated_at = time.time()
    s.updated_by = user.sub
    _save(s)

    logger.info("Portal logo uploaded by %s → %s", user.sub, dest.name)
    return {"ok": True, "logo_url": "/api/v1/cc/settings/portal/logo", "filename": dest.name}


@router.delete("/portal/logo", status_code=status.HTTP_200_OK)
async def delete_logo(user: TokenPayload = Depends(require_super_admin)):
    """Remove the custom logo and revert to the default."""
    s = _load()
    if s.logo_filename:
        path = _UPLOADS_DIR / s.logo_filename
        if path.exists():
            path.unlink()
        s.logo_filename = None
        s.updated_at = time.time()
        s.updated_by = user.sub
        _save(s)
        logger.info("Portal logo removed by %s", user.sub)
    return {"ok": True, "logo_url": None}


@router.get("/portal/logo")
async def serve_logo():
    """Serve the uploaded portal logo. Public endpoint."""
    s = _load()
    if not s.logo_filename:
        raise HTTPException(status_code=404, detail="No custom logo configured")
    path = _UPLOADS_DIR / s.logo_filename
    if not path.exists():
        raise HTTPException(status_code=404, detail="Logo file not found on disk")
    return FileResponse(str(path))
