"""
Auto-Update Engine — FrothIQ plugin and MC3 service deployment.

Provides version status checks and controlled deployment for:
  - FrothIQ WordPress plugin (rsync from source to each WP site)
  - MC3 backend service (rsync + systemctl restart)
  - MC3 frontend UI (npm build + rsync + systemctl restart)
"""

from __future__ import annotations

import asyncio
import json
import re
import subprocess
from pathlib import Path
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from mc3.auth import require_super_admin

router = APIRouter(prefix="/updates", tags=["autoupdate"])

# ── Paths ────────────────────────────────────────────────────────────────────

_PLUGIN_SRC = Path("/home/frothiq/frothiq-wordpress")
_MC3_BACKEND_SRC = Path("/home/frothiq/frothiq-control-center/mc3")
_MC3_BACKEND_MAIN = Path("/home/frothiq/frothiq-control-center/main.py")
_MC3_BACKEND_DEPLOY = Path("/usr/lib/frothiq-control-center/backend/mc3")
_MC3_BACKEND_DEPLOY_MAIN = Path("/usr/lib/frothiq-control-center/backend/main.py")
_MC3_UI_SRC = Path("/home/frothiq/frothiq-control-center-ui")
_MC3_UI_DEPLOY = Path("/usr/lib/frothiq-control-center/ui")

_SEARCH_ROOTS = [Path("/home"), Path("/var/www")]
_WP_CLI = "/usr/local/bin/wp"
_WP_CLI_FLAGS = ["--allow-root", "--skip-plugins", "--skip-themes", "--format=json"]


# ── Helpers ──────────────────────────────────────────────────────────────────

def _run(cmd: list[str], timeout: int = 60) -> tuple[str, str, int]:
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return result.stdout, result.stderr, result.returncode


def _read_version_from_php(path: Path) -> str:
    """Extract Version: from a WP plugin PHP header."""
    try:
        content = path.read_text(encoding="utf-8", errors="ignore")
        m = re.search(r"^\s*\*?\s*Version:\s*(.+)$", content, re.MULTILINE | re.IGNORECASE)
        return m.group(1).strip() if m else "unknown"
    except OSError:
        return "unknown"


def _read_mc3_backend_version() -> str:
    init_src = _PLUGIN_SRC.parent / "frothiq-control-center" / "mc3" / "__init__.py"
    try:
        content = init_src.read_text()
        m = re.search(r'__version__\s*=\s*["\']([^"\']+)["\']', content)
        return m.group(1) if m else "unknown"
    except OSError:
        return "unknown"


def _read_mc3_backend_deployed_version() -> str:
    init_dep = _MC3_BACKEND_DEPLOY / "__init__.py"
    try:
        content = init_dep.read_text()
        m = re.search(r'__version__\s*=\s*["\']([^"\']+)["\']', content)
        return m.group(1) if m else "unknown"
    except OSError:
        return "unknown"


def _find_wp_sites() -> list[dict]:
    """
    Find all WordPress installs that have the frothiq plugin present.
    Returns list of {path, domain, owner, plugin_path}.
    """
    sites = []
    for root in _SEARCH_ROOTS:
        if not root.exists():
            continue
        for user_dir in root.iterdir():
            if not user_dir.is_dir():
                continue
            # Walk common WP install locations
            for subpath in ["public_html", "www", "htdocs", user_dir.name]:
                wp_dir = user_dir / subpath
                wp_config = wp_dir / "wp-config.php"
                frothiq_main = wp_dir / "wp-content" / "plugins" / "frothiq" / "frothiq.php"
                if wp_config.exists() and frothiq_main.exists():
                    sites.append({
                        "path": str(wp_dir),
                        "domain": user_dir.name,
                        "owner": user_dir.name,
                        "plugin_path": str(wp_dir / "wp-content" / "plugins" / "frothiq"),
                        "installed_version": _read_version_from_php(frothiq_main),
                    })
                    break
    return sites


def _service_active(name: str) -> bool:
    try:
        out, _, rc = _run(["sudo", "systemctl", "is-active", name], timeout=5)
        return rc == 0 and out.strip() == "active"
    except Exception:
        return False


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ── Status ───────────────────────────────────────────────────────────────────

def _build_status() -> dict:
    source_version = _read_version_from_php(_PLUGIN_SRC / "frothiq.php")
    sites = _find_wp_sites()

    plugin_sites = []
    for s in sites:
        plugin_sites.append({
            "domain": s["domain"],
            "path": s["path"],
            "installed_version": s["installed_version"],
            "up_to_date": s["installed_version"] == source_version,
        })

    mc3_src_ver = _read_mc3_backend_version()
    mc3_dep_ver = _read_mc3_backend_deployed_version()
    mc3_backend_active = _service_active("frothiq-control-center")
    mc3_ui_active = _service_active("frothiq-ui")

    return {
        "checked_at": _now_iso(),
        "plugin": {
            "source_version": source_version,
            "source_path": str(_PLUGIN_SRC),
            "sites": plugin_sites,
            "sites_up_to_date": sum(1 for s in plugin_sites if s["up_to_date"]),
            "sites_outdated": sum(1 for s in plugin_sites if not s["up_to_date"]),
        },
        "mc3_backend": {
            "source_version": mc3_src_ver,
            "deployed_version": mc3_dep_ver,
            "up_to_date": mc3_src_ver == mc3_dep_ver,
            "service_active": mc3_backend_active,
        },
        "mc3_frontend": {
            "source_path": str(_MC3_UI_SRC),
            "deployed_path": str(_MC3_UI_DEPLOY),
            "service_active": mc3_ui_active,
        },
    }


@router.get("/status")
async def get_status(_: str = Depends(require_super_admin)) -> dict:
    return await asyncio.to_thread(_build_status)


# ── Plugin Deploy ─────────────────────────────────────────────────────────────

class DeployPluginRequest(BaseModel):
    site_path: str | None = None  # None = all sites


def _deploy_plugin_to(site: dict) -> dict:
    """rsync plugin source → WP plugin directory + fix ownership."""
    plugin_dest = site["plugin_path"]
    owner = site["owner"]

    # rsync from source (trailing slash = contents of dir)
    rsync_out, rsync_err, rc = _run(
        ["sudo", "rsync", "-a", "--delete", "--exclude=.git",
         str(_PLUGIN_SRC) + "/", plugin_dest + "/"],
        timeout=30,
    )
    if rc != 0:
        return {"domain": site["domain"], "ok": False, "error": rsync_err.strip() or "rsync failed"}

    # Fix ownership
    chown_out, chown_err, rc2 = _run(
        ["sudo", "chown", "-R", f"{owner}:{owner}", plugin_dest],
        timeout=10,
    )
    if rc2 != 0:
        return {"domain": site["domain"], "ok": False, "error": chown_err.strip() or "chown failed"}

    new_ver = _read_version_from_php(
        Path(plugin_dest) / "frothiq.php"
    )
    return {"domain": site["domain"], "ok": True, "deployed_version": new_ver}


@router.post("/deploy/plugin")
async def deploy_plugin(
    req: DeployPluginRequest,
    _: str = Depends(require_super_admin),
) -> dict:
    sites = await asyncio.to_thread(_find_wp_sites)

    if req.site_path:
        sites = [s for s in sites if s["path"] == req.site_path]
        if not sites:
            raise HTTPException(status_code=404, detail="Site not found or frothiq not installed")

    results = await asyncio.gather(
        *[asyncio.to_thread(_deploy_plugin_to, s) for s in sites]
    )
    success = sum(1 for r in results if r["ok"])
    return {
        "ok": success == len(results),
        "deployed": success,
        "failed": len(results) - success,
        "results": list(results),
        "deployed_at": _now_iso(),
    }


# ── MC3 Backend Deploy ────────────────────────────────────────────────────────

def _deploy_mc3_backend() -> dict:
    steps = []
    errors = []

    # Sync mc3 package
    _, err, rc = _run(
        ["sudo", "rsync", "-a", "--delete",
         str(_MC3_BACKEND_SRC) + "/",
         str(_MC3_BACKEND_DEPLOY) + "/"],
        timeout=30,
    )
    if rc != 0:
        errors.append(f"rsync mc3: {err.strip()}")
    else:
        steps.append("Synced mc3 package")

    # Sync main.py
    _, err, rc = _run(
        ["sudo", "rsync", "-a",
         str(_MC3_BACKEND_MAIN),
         str(_MC3_BACKEND_DEPLOY_MAIN)],
        timeout=10,
    )
    if rc != 0:
        errors.append(f"rsync main.py: {err.strip()}")
    else:
        steps.append("Synced main.py")

    # Restart service
    _, err, rc = _run(["sudo", "systemctl", "restart", "frothiq-control-center"], timeout=15)
    if rc != 0:
        errors.append(f"restart: {err.strip()}")
    else:
        steps.append("Service restarted")

    # Verify
    active = _service_active("frothiq-control-center")
    steps.append(f"Service status: {'active' if active else 'FAILED'}")

    deployed_ver = _read_mc3_backend_deployed_version()
    return {
        "ok": not errors and active,
        "deployed_version": deployed_ver,
        "service_active": active,
        "steps": steps,
        "errors": errors,
        "deployed_at": _now_iso(),
    }


@router.post("/deploy/mc3/backend")
async def deploy_mc3_backend(_: str = Depends(require_super_admin)) -> dict:
    return await asyncio.to_thread(_deploy_mc3_backend)


# ── MC3 Frontend Deploy ───────────────────────────────────────────────────────

def _deploy_mc3_frontend() -> dict:
    steps = []
    errors = []

    # npm run build
    build_out, build_err, rc = _run(
        ["npm", "run", "build"],
        timeout=300,
    )
    if rc != 0:
        return {
            "ok": False,
            "steps": ["npm build failed"],
            "errors": [build_err[-2000:] or build_out[-2000:]],
            "deployed_at": _now_iso(),
        }
    steps.append("npm run build succeeded")

    # Sync .next/
    _, err, rc = _run(
        ["sudo", "rsync", "-a", "--delete",
         str(_MC3_UI_SRC / ".next") + "/",
         str(_MC3_UI_DEPLOY / ".next") + "/"],
        timeout=60,
    )
    if rc != 0:
        errors.append(f"rsync .next: {err.strip()}")
    else:
        steps.append("Synced .next/")

    # Sync public/
    _, err, rc = _run(
        ["sudo", "rsync", "-a",
         str(_MC3_UI_SRC / "public") + "/",
         str(_MC3_UI_DEPLOY / "public") + "/"],
        timeout=30,
    )
    if rc != 0:
        errors.append(f"rsync public: {err.strip()}")
    else:
        steps.append("Synced public/")

    # Restart UI service
    _, err, rc = _run(["sudo", "systemctl", "restart", "frothiq-ui"], timeout=15)
    if rc != 0:
        errors.append(f"restart frothiq-ui: {err.strip()}")
    else:
        steps.append("frothiq-ui restarted")

    active = _service_active("frothiq-ui")
    steps.append(f"UI service: {'active' if active else 'FAILED'}")

    return {
        "ok": not errors and active,
        "service_active": active,
        "steps": steps,
        "errors": errors,
        "deployed_at": _now_iso(),
    }


@router.post("/deploy/mc3/frontend")
async def deploy_mc3_frontend(_: str = Depends(require_super_admin)) -> dict:
    # npm run build has a cwd requirement
    import subprocess as _sp
    steps = []
    errors = []

    proc = _sp.run(
        ["npm", "run", "build"],
        capture_output=True, text=True, timeout=300,
        cwd=str(_MC3_UI_SRC),
    )
    if proc.returncode != 0:
        return {
            "ok": False,
            "steps": [],
            "errors": [(proc.stderr or proc.stdout)[-2000:]],
            "service_active": _service_active("frothiq-ui"),
            "deployed_at": _now_iso(),
        }
    steps.append("npm run build succeeded")

    for src, dst in [
        (str(_MC3_UI_SRC / ".next") + "/", str(_MC3_UI_DEPLOY / ".next") + "/"),
        (str(_MC3_UI_SRC / "public") + "/", str(_MC3_UI_DEPLOY / "public") + "/"),
    ]:
        _, err, rc = _run(["sudo", "rsync", "-a", "--delete", src, dst], timeout=60)
        if rc != 0:
            errors.append(f"rsync {src}: {err.strip()}")
        else:
            steps.append(f"Synced {src.split('/')[-2] or src}")

    _, err, rc = _run(["sudo", "systemctl", "restart", "frothiq-ui"], timeout=15)
    if rc != 0:
        errors.append(f"restart: {err.strip()}")
    else:
        steps.append("frothiq-ui restarted")

    active = _service_active("frothiq-ui")
    return {
        "ok": not errors and active,
        "service_active": active,
        "steps": steps,
        "errors": errors,
        "deployed_at": _now_iso(),
    }
