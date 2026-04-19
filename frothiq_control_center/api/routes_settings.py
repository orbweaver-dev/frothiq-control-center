"""
Portal settings routes — branding, security, and feature configuration.

GET    /settings/portal              — public (no auth); used by login page pre-auth
PATCH  /settings/portal              — super_admin
POST   /settings/portal/logo         — super_admin; multipart upload (portal/login logo)
DELETE /settings/portal/logo         — super_admin
GET    /settings/portal/logo         — public; serves the uploaded portal logo file
POST   /settings/portal/menu-logo    — super_admin; multipart upload (sidebar logo)
DELETE /settings/portal/menu-logo    — super_admin
GET    /settings/portal/menu-logo    — public; serves the uploaded menu logo file
POST   /settings/portal/favicon      — super_admin; multipart upload (browser tab favicon)
DELETE /settings/portal/favicon      — super_admin
GET    /settings/portal/favicon      — public; serves the uploaded favicon file

Logo/favicon source priority (per slot):
  1. url_override — external URL stored in settings JSON
  2. filename     — file uploaded to /var/lib/frothiq/control-center/uploads/
  Setting one clears the other so they are always mutually exclusive.
"""

from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path
from typing import Optional

import io

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status
from fastapi.responses import FileResponse
from PIL import Image
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
_UPLOADS_DIR   = _SETTINGS_ROOT / "uploads"
# Canonical static brand files — served directly by Apache, no backend dependency.
# Always these fixed filenames regardless of the original upload extension/format.
_BRAND_DIR     = _SETTINGS_ROOT / "brand"

_ALLOWED_TYPES = {
    "image/png",
    "image/jpeg",
    "image/svg+xml",
    "image/gif",
    "image/webp",
    "image/x-icon",
    "image/vnd.microsoft.icon",
}
_MAX_LOGO_BYTES = 2 * 1024 * 1024  # 2 MB

# Canonical brand filenames — Apache serves /brand/<name> directly.
_BRAND_SLOTS: dict[str, str] = {
    "logo":      "logo.png",
    "menu_logo": "menu-logo.png",
    "favicon":   "favicon.ico",
}


def _normalize_favicon(raw: bytes) -> bytes:
    """Convert any uploaded image to a multi-size ICO file (industry standard).

    Produces an ICO containing 16×16, 32×32, 48×48, and 256×256 frames so the
    browser can pick the best resolution for each context (tab, taskbar, bookmark).
    """
    try:
        img = Image.open(io.BytesIO(raw))
        if img.mode not in ("RGBA", "LA"):
            img = img.convert("RGBA")
        sizes = [16, 32, 48, 256]
        frames = [img.resize((s, s), Image.LANCZOS) for s in sizes]
        buf = io.BytesIO()
        frames[0].save(
            buf,
            format="ICO",
            sizes=[(s, s) for s in sizes],
            append_images=frames[1:],
        )
        return buf.getvalue()
    except Exception:
        logger.warning("favicon ICO conversion failed — storing raw bytes")
        return raw


def _publish_brand(slot: str, content: bytes) -> None:
    """Write brand asset content to the canonical static filesystem path."""
    _BRAND_DIR.mkdir(parents=True, exist_ok=True)
    dest = _BRAND_DIR / _BRAND_SLOTS[slot]
    dest.write_bytes(content)
    dest.chmod(0o644)


def _remove_brand(slot: str) -> None:
    """Remove canonical brand file (leaves Apache serving a 404 for that slot)."""
    dest = _BRAND_DIR / _BRAND_SLOTS[slot]
    if dest.exists():
        dest.unlink()


async def _download_url_to_brand(slot: str, url: str) -> None:
    """Download an external URL and publish it to the canonical brand path."""
    import urllib.request
    import ssl
    try:
        ctx = ssl.create_default_context()
        req = urllib.request.Request(url, headers={"User-Agent": "FrothIQ-MC3-BrandSync/1.0"})
        with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
            content = resp.read(_MAX_LOGO_BYTES + 1)
        if len(content) > _MAX_LOGO_BYTES:
            logger.warning("Brand URL %s too large for slot %s — skipped", url, slot)
            return
        publish_content = _normalize_favicon(content) if slot == "favicon" else content
        _publish_brand(slot, publish_content)
    except Exception as exc:
        logger.warning("Failed to download brand asset for slot %s from %s: %s", slot, url, exc)


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

class PortalSettings(BaseModel):
    portal_title:          str           = "FrothIQ MC³"
    # Portal / login logo
    logo_filename:         Optional[str] = None   # uploaded file (mutually exclusive with override)
    logo_url_override:     Optional[str] = None   # external URL  (mutually exclusive with filename)
    # Sidebar / menu logo
    menu_logo_filename:    Optional[str] = None
    menu_logo_url_override: Optional[str] = None
    # Browser tab favicon
    favicon_filename:      Optional[str] = None
    favicon_url_override:  Optional[str] = None
    # Appearance
    theme_accent:          str           = "#4f8ef7"
    # Security
    session_timeout_minutes: int         = 60
    login_notice:          str           = ""
    maintenance_mode:      bool          = False
    # Network access — IP/CIDR allowlist for the control center UI
    # Empty list = allow all (default). Non-empty = restrict to listed IPs/CIDRs.
    safe_ips:              list[str]     = []
    # Audit
    updated_at:            Optional[float] = None
    updated_by:            Optional[str]   = None


class PortalSettingsPatch(BaseModel):
    portal_title:            Optional[str]  = None
    theme_accent:            Optional[str]  = None
    session_timeout_minutes: Optional[int]  = None
    login_notice:            Optional[str]  = None
    maintenance_mode:        Optional[bool] = None
    # Pass empty string to clear; non-empty to set (clears the filename counterpart)
    logo_url_override:       Optional[str]  = None
    menu_logo_url_override:  Optional[str]  = None
    favicon_url_override:    Optional[str]  = None
    # Replace the entire safe_ips list (null = no change)
    safe_ips:                Optional[list[str]] = None


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


def _resolve_logo_url(
    url_override: str | None,
    filename: str | None,
    serve_path: str,
    updated_at: float | None,
) -> str | None:
    """
    Return the effective logo URL for a slot.
    External URL takes priority; uploaded file is cache-busted via updated_at.
    """
    if url_override:
        return url_override
    if filename:
        v = int(updated_at or time.time())
        return f"{serve_path}?v={v}"
    return None


def _public_view(s: PortalSettings) -> dict:
    return {
        **s.model_dump(exclude={"logo_filename", "menu_logo_filename", "favicon_filename"}),
        "logo_url": _resolve_logo_url(
            s.logo_url_override, s.logo_filename,
            "/api/v1/cc/settings/portal/logo", s.updated_at,
        ),
        "menu_logo_url": _resolve_logo_url(
            s.menu_logo_url_override, s.menu_logo_filename,
            "/api/v1/cc/settings/portal/menu-logo", s.updated_at,
        ),
        "favicon_url": _resolve_logo_url(
            s.favicon_url_override, s.favicon_filename,
            "/api/v1/cc/settings/portal/favicon", s.updated_at,
        ),
    }


def _delete_file(filename: str | None) -> None:
    if filename:
        p = _UPLOADS_DIR / filename
        if p.exists():
            p.unlink()


async def _save_upload(file: UploadFile, dest_stem: str) -> Path:
    """Validate, read, and persist an uploaded image. Returns the saved Path."""
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
    dest = _UPLOADS_DIR / f"{dest_stem}{suffix}"
    dest.write_bytes(content)
    return dest


def _serve_file(filename: str | None, label: str) -> FileResponse:
    if not filename:
        raise HTTPException(status_code=404, detail=f"No {label} configured")
    path = _UPLOADS_DIR / filename
    if not path.exists():
        raise HTTPException(status_code=404, detail=f"{label} file not found on disk")
    return FileResponse(
        str(path),
        headers={"Cache-Control": "no-cache, no-store, must-revalidate"},
    )


# ---------------------------------------------------------------------------
# Routes — portal settings
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
        val = patch.theme_accent.strip()
        if not (val.startswith("#") and len(val) in (4, 7)):
            raise HTTPException(status_code=422, detail="theme_accent must be a hex colour (#RGB or #RRGGBB)")
        s.theme_accent = val
    if patch.session_timeout_minutes is not None:
        s.session_timeout_minutes = max(5, min(480, patch.session_timeout_minutes))
    if patch.login_notice is not None:
        s.login_notice = patch.login_notice[:500]
    if patch.maintenance_mode is not None:
        s.maintenance_mode = patch.maintenance_mode

    # URL override for portal logo — setting it clears any uploaded file
    if patch.logo_url_override is not None:
        if patch.logo_url_override:
            _delete_file(s.logo_filename)
            s.logo_filename    = None
            s.logo_url_override = patch.logo_url_override
            await _download_url_to_brand("logo", patch.logo_url_override)
        else:
            s.logo_url_override = None   # empty string = clear override
            _remove_brand("logo")

    # URL override for menu logo
    if patch.menu_logo_url_override is not None:
        if patch.menu_logo_url_override:
            _delete_file(s.menu_logo_filename)
            s.menu_logo_filename    = None
            s.menu_logo_url_override = patch.menu_logo_url_override
            await _download_url_to_brand("menu_logo", patch.menu_logo_url_override)
        else:
            s.menu_logo_url_override = None
            _remove_brand("menu_logo")

    # URL override for favicon
    if patch.favicon_url_override is not None:
        if patch.favicon_url_override:
            _delete_file(s.favicon_filename)
            s.favicon_filename    = None
            s.favicon_url_override = patch.favicon_url_override
            await _download_url_to_brand("favicon", patch.favicon_url_override)
        else:
            s.favicon_url_override = None
            _remove_brand("favicon")

    # Safe IP / CIDR allowlist
    if patch.safe_ips is not None:
        import ipaddress as _ip
        validated: list[str] = []
        for entry in patch.safe_ips:
            entry = entry.strip()
            if not entry:
                continue
            try:
                _ip.ip_network(entry, strict=False) if "/" in entry else _ip.ip_address(entry)
                validated.append(entry)
            except ValueError:
                raise HTTPException(status_code=422, detail=f"Invalid IP/CIDR: {entry!r}")
        s.safe_ips = validated

    s.updated_at = time.time()
    s.updated_by = user.sub
    _save(s)

    logger.info("Portal settings updated by %s", user.sub)
    return {"ok": True, "settings": _public_view(s)}


# ---------------------------------------------------------------------------
# Routes — portal logo (login page)
# ---------------------------------------------------------------------------

@router.post("/portal/logo", status_code=status.HTTP_200_OK)
async def upload_logo(
    file: UploadFile = File(...),
    user: TokenPayload = Depends(require_super_admin),
):
    """Upload a new portal (login page) logo. Clears any URL override."""
    dest = await _save_upload(file, "portal_logo")
    s = _load()
    old_filename = s.logo_filename
    s.logo_filename    = dest.name
    s.logo_url_override = None             # file takes over; clear URL override
    s.updated_at = time.time()
    s.updated_by = user.sub
    _save(s)
    # Only delete old file after settings are saved, and only when name differs
    # (same name means new content already overwrote the old file in _save_upload)
    if old_filename and old_filename != dest.name:
        _delete_file(old_filename)
    _publish_brand("logo", dest.read_bytes())
    logo_url = _resolve_logo_url(None, dest.name, "/api/v1/cc/settings/portal/logo", s.updated_at)
    logger.info("Portal logo uploaded by %s → %s", user.sub, dest.name)
    return {"ok": True, "logo_url": logo_url, "filename": dest.name}


@router.delete("/portal/logo", status_code=status.HTTP_200_OK)
async def delete_logo(user: TokenPayload = Depends(require_super_admin)):
    """Remove the uploaded portal logo."""
    s = _load()
    _delete_file(s.logo_filename)
    s.logo_filename = None
    s.updated_at = time.time()
    s.updated_by = user.sub
    _save(s)
    logger.info("Portal logo removed by %s", user.sub)
    return {"ok": True, "logo_url": None}


@router.get("/portal/logo")
async def serve_logo():
    """Serve the uploaded portal logo. Public endpoint."""
    return _serve_file(_load().logo_filename, "portal logo")


# ---------------------------------------------------------------------------
# Routes — menu / sidebar logo
# ---------------------------------------------------------------------------

@router.post("/portal/menu-logo", status_code=status.HTTP_200_OK)
async def upload_menu_logo(
    file: UploadFile = File(...),
    user: TokenPayload = Depends(require_super_admin),
):
    """Upload a new menu (sidebar) logo. Clears any URL override."""
    dest = await _save_upload(file, "menu_logo")
    s = _load()
    old_filename = s.menu_logo_filename
    s.menu_logo_filename    = dest.name
    s.menu_logo_url_override = None
    s.updated_at = time.time()
    s.updated_by = user.sub
    _save(s)
    if old_filename and old_filename != dest.name:
        _delete_file(old_filename)
    _publish_brand("menu_logo", dest.read_bytes())
    logo_url = _resolve_logo_url(None, dest.name, "/api/v1/cc/settings/portal/menu-logo", s.updated_at)
    logger.info("Menu logo uploaded by %s → %s", user.sub, dest.name)
    return {"ok": True, "logo_url": logo_url, "filename": dest.name}


@router.delete("/portal/menu-logo", status_code=status.HTTP_200_OK)
async def delete_menu_logo(user: TokenPayload = Depends(require_super_admin)):
    """Remove the uploaded menu logo."""
    s = _load()
    _delete_file(s.menu_logo_filename)
    s.menu_logo_filename = None
    s.updated_at = time.time()
    s.updated_by = user.sub
    _save(s)
    logger.info("Menu logo removed by %s", user.sub)
    return {"ok": True, "logo_url": None}


@router.get("/portal/menu-logo")
async def serve_menu_logo():
    """Serve the uploaded menu logo. Public endpoint."""
    return _serve_file(_load().menu_logo_filename, "menu logo")


# ---------------------------------------------------------------------------
# Routes — favicon
# ---------------------------------------------------------------------------

@router.post("/portal/favicon", status_code=status.HTTP_200_OK)
async def upload_favicon(
    file: UploadFile = File(...),
    user: TokenPayload = Depends(require_super_admin),
):
    """Upload a new browser tab favicon. Accepted: ICO, PNG, SVG — max 2 MB."""
    dest = await _save_upload(file, "favicon")
    s = _load()
    old_filename = s.favicon_filename
    s.favicon_filename    = dest.name
    s.favicon_url_override = None
    s.updated_at = time.time()
    s.updated_by = user.sub
    _save(s)
    if old_filename and old_filename != dest.name:
        _delete_file(old_filename)
    _publish_brand("favicon", _normalize_favicon(dest.read_bytes()))
    favicon_url = _resolve_logo_url(None, dest.name, "/api/v1/cc/settings/portal/favicon", s.updated_at)
    logger.info("Favicon uploaded by %s → %s", user.sub, dest.name)
    return {"ok": True, "favicon_url": favicon_url, "filename": dest.name}


@router.delete("/portal/favicon", status_code=status.HTTP_200_OK)
async def delete_favicon(user: TokenPayload = Depends(require_super_admin)):
    """Remove the uploaded favicon and revert to default."""
    s = _load()
    _delete_file(s.favicon_filename)
    s.favicon_filename = None
    s.updated_at = time.time()
    s.updated_by = user.sub
    _save(s)
    logger.info("Favicon removed by %s", user.sub)
    return {"ok": True, "favicon_url": None}


@router.get("/portal/favicon")
async def serve_favicon():
    """Serve the uploaded favicon. Public endpoint."""
    return _serve_file(_load().favicon_filename, "favicon")
