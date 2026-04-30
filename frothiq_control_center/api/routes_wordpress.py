"""
WordPress Monitor — discovers WP installs on this server and exposes
health, plugin update counts, and core version via WP-CLI.

Requires: /usr/local/bin/wp (WP-CLI) installed on the host.
Commands are run as root with --allow-root --skip-plugins --skip-themes
to bypass plugins that might block CLI access.
"""

from __future__ import annotations

import asyncio
import json
import subprocess
from pathlib import Path

from fastapi import APIRouter, Depends

from frothiq_control_center.auth import TokenPayload, require_super_admin

router = APIRouter(prefix="/sysinfo/wordpress", tags=["wordpress"])

_WP_CLI = "/usr/local/bin/wp"
_WP_CLI_FLAGS = ["--allow-root", "--skip-plugins", "--skip-themes", "--format=json"]

# Known home directories to search for WordPress installs
_SEARCH_ROOTS = [Path("/home"), Path("/var/www")]

# Frappe bench sites directory — any home dir matching a site here is excluded
_FRAPPE_SITES_DIR = Path("/home/frappe/frappe-bench/sites")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _frappe_site_home_users() -> set[str]:
    """
    Return the set of home-directory usernames that belong to Frappe bench sites.

    Frappe sites are named like 'agiient.com' or 'emeraldshield.org'.
    Their Virtualmin home dirs are typically /home/agiient or /home/emeraldshield
    (the part before the first dot). We collect both the full site name and the
    subdomain prefix so we can match either form found in _SEARCH_ROOTS.
    """
    names: set[str] = set()
    try:
        for p in _FRAPPE_SITES_DIR.iterdir():
            if p.is_dir() and (p / "site_config.json").exists():
                names.add(p.name)                    # e.g. "agiient.com"
                names.add(p.name.split(".")[0])      # e.g. "agiient"
    except (PermissionError, OSError):
        pass
    return names


def _is_real_wordpress(wp_dir: Path) -> bool:
    """
    Confirm a directory is an active WordPress install, not just a leftover
    wp-config.php.  Requires wp-login.php AND wp-includes/version.php.
    """
    return (wp_dir / "wp-login.php").exists() and (wp_dir / "wp-includes" / "version.php").exists()


def _discover_installs() -> list[dict]:
    """
    Walk _SEARCH_ROOTS to find real WordPress installs.

    Exclusion rules (applied in order):
      1. Path depth > 5 — skip buried configs
      2. Home-dir username matches a Frappe bench site — not WordPress
      3. wp-login.php or wp-includes/version.php missing — not a real WP install
    """
    frappe_users = _frappe_site_home_users()
    found: list[dict] = []
    for root in _SEARCH_ROOTS:
        if not root.exists():
            continue
        try:
            for config in root.rglob("wp-config.php"):
                parts = config.relative_to(root).parts
                if len(parts) > 5:
                    continue
                # Rule 2: exclude Frappe bench sites
                home_user = parts[0] if parts else ""
                if home_user in frappe_users:
                    continue
                # Rule 3: must have real WordPress core files
                wp_dir = config.parent
                if not _is_real_wordpress(wp_dir):
                    continue
                found.append({"path": str(wp_dir), "domain": _guess_domain(config)})
        except (PermissionError, OSError):
            continue
    # Deduplicate by path
    seen: set[str] = set()
    unique = []
    for item in found:
        if item["path"] not in seen:
            seen.add(item["path"])
            unique.append(item)
    return unique


def _guess_domain(config_path: Path) -> str:
    """Heuristic: extract domain from path like /home/<domain>/public_html/."""
    parts = config_path.parts
    for i, part in enumerate(parts):
        if part in ("home", "www") and i + 1 < len(parts):
            candidate = parts[i + 1]
            # Filter out obvious non-domains
            if "." in candidate or candidate not in ("public_html", "html", "web"):
                return candidate
    return config_path.parent.name


def _run_wp(path: str, subcommand: list[str], timeout: int = 20) -> tuple[str, str, int]:
    cmd = [_WP_CLI, f"--path={path}"] + _WP_CLI_FLAGS + subcommand
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    except subprocess.TimeoutExpired:
        return "", "wp-cli timed out", 1
    except FileNotFoundError:
        return "", "wp-cli not found", 1
    except Exception as e:
        return "", str(e), 1


def _scan_install(info: dict) -> dict:
    path = info["path"]
    domain = info["domain"]

    # Core version
    stdout, stderr, rc = _run_wp(path, ["core", "version"])
    if rc != 0:
        return {
            "path": path,
            "domain": domain,
            "reachable": False,
            "error": stderr or "wp-cli failed",
        }

    wp_version = stdout.strip()

    # Core update check
    update_out, _, _ = _run_wp(path, ["core", "check-update"])
    core_update_available = False
    core_update_version = ""
    try:
        updates = json.loads(update_out)
        if updates:
            core_update_available = True
            core_update_version = updates[0].get("version", "")
    except (json.JSONDecodeError, IndexError, KeyError):
        pass

    # Plugin list
    plugin_out, _, _ = _run_wp(path, ["plugin", "list"])
    plugins: list[dict] = []
    plugins_needing_update = 0
    try:
        plugins = json.loads(plugin_out)
        plugins_needing_update = sum(
            1 for p in plugins if p.get("update") == "available"
        )
    except (json.JSONDecodeError, TypeError):
        pass

    # Theme list
    theme_out, _, _ = _run_wp(path, ["theme", "list"])
    themes: list[dict] = []
    themes_needing_update = 0
    try:
        themes = json.loads(theme_out)
        themes_needing_update = sum(
            1 for t in themes if t.get("update") == "available"
        )
    except (json.JSONDecodeError, TypeError):
        pass

    # PHP version (read from wp eval)
    php_out, _, _ = _run_wp(path, ["eval", "echo PHP_VERSION;"], timeout=10)
    php_version = php_out.strip() if php_out else "unknown"

    return {
        "path": path,
        "domain": domain,
        "reachable": True,
        "wp_version": wp_version,
        "php_version": php_version,
        "core_update_available": core_update_available,
        "core_update_version": core_update_version,
        "plugin_count": len(plugins),
        "plugins_needing_update": plugins_needing_update,
        "theme_count": len(themes),
        "themes_needing_update": themes_needing_update,
        "active_plugins": [
            {
                "name": p.get("name", ""),
                "version": p.get("version", ""),
                "update": p.get("update", "none"),
                "update_version": p.get("update_version", ""),
                "status": p.get("status", ""),
            }
            for p in plugins
            if p.get("status") == "active"
        ],
        "active_theme": next(
            (
                {
                    "name": t.get("name", ""),
                    "version": t.get("version", ""),
                    "update": t.get("update", "none"),
                    "update_version": t.get("update_version", ""),
                }
                for t in themes
                if t.get("status") == "active"
            ),
            None,
        ),
    }


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.get("/installs")
async def list_installs(
    _: TokenPayload = Depends(require_super_admin),
):
    """Discover all WordPress installations on this server."""
    installs = await asyncio.to_thread(_discover_installs)
    return {"installs": installs, "count": len(installs)}


@router.get("/scan")
async def scan_all(
    _: TokenPayload = Depends(require_super_admin),
):
    """Scan all discovered WordPress installs and return health data."""
    installs = await asyncio.to_thread(_discover_installs)

    results = await asyncio.gather(
        *[asyncio.to_thread(_scan_install, info) for info in installs]
    )

    total_plugin_updates = sum(
        r.get("plugins_needing_update", 0) for r in results if r.get("reachable")
    )
    total_theme_updates = sum(
        r.get("themes_needing_update", 0) for r in results if r.get("reachable")
    )
    core_updates = sum(
        1 for r in results if r.get("reachable") and r.get("core_update_available")
    )
    reachable = sum(1 for r in results if r.get("reachable"))

    return {
        "sites": list(results),
        "summary": {
            "total": len(results),
            "reachable": reachable,
            "unreachable": len(results) - reachable,
            "core_updates_available": core_updates,
            "total_plugin_updates": total_plugin_updates,
            "total_theme_updates": total_theme_updates,
        },
    }


@router.get("/scan/{site_path:path}")
async def scan_one(
    site_path: str,
    _: TokenPayload = Depends(require_super_admin),
):
    """Scan a single WordPress install by filesystem path."""
    # Sanitize path — must start with /home or /var/www
    path = "/" + site_path.lstrip("/")
    allowed = any(path.startswith(str(r)) for r in _SEARCH_ROOTS)
    if not allowed:
        from fastapi import HTTPException
        raise HTTPException(status_code=400, detail="Path not in allowed roots")

    result = await asyncio.to_thread(
        _scan_install, {"path": path, "domain": Path(path).name}
    )
    return result
