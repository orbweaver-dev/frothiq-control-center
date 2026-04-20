"""
Frappe Bench management API — super_admin only.
All filesystem access runs as the 'frappe' user via sudo because
/home/frappe has 750 permissions and frothiq cannot traverse it directly.
"""

from __future__ import annotations

import json
import os
import subprocess
from datetime import UTC, datetime
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from .routes_auth import require_super_admin

router = APIRouter(prefix="/frappe", tags=["frappe"])

BENCH_DIR = Path("/home/frappe/frappe-bench")
SITES_DIR = BENCH_DIR / "sites"
APPS_DIR = BENCH_DIR / "apps"
FRAPPE_USER = "frappe"


# ---------------------------------------------------------------------------
# Low-level helpers
# ---------------------------------------------------------------------------

def _run(cmd: list[str], timeout: int = 30, cwd: str | None = None,
         stdin_data: str | None = None) -> tuple[str, str, int]:
    try:
        r = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            cwd=cwd or "/tmp",
            env={**os.environ, "HOME": f"/home/{FRAPPE_USER}"},
            input=stdin_data,
        )
        return r.stdout, r.stderr, r.returncode
    except subprocess.TimeoutExpired:
        return "", f"Command timed out after {timeout}s", 1
    except Exception as e:
        return "", str(e), 1


def _bench(args: list[str], timeout: int = 60) -> tuple[str, str, int]:
    """Run a bench command as the frappe user via the frothiq-bench wrapper.
    The wrapper cds into BENCH_DIR first (as frappe), so bench can find its
    directory without frothiq needing to chdir into /home/frappe."""
    return _run(
        ["sudo", "-u", FRAPPE_USER, "/usr/local/bin/frothiq-bench"] + args,
        timeout=timeout,
        cwd="/tmp",
    )


def _sudo_cat(path: str | Path) -> str:
    """Read a file as the frappe user via sudo cat."""
    out, _, rc = _run(["sudo", "-u", FRAPPE_USER, "cat", str(path)])
    return out if rc == 0 else ""


def _sudo_exists(path: str | Path) -> bool:
    """Check if a path exists as the frappe user (uses stat which is in sudoers)."""
    _, _, rc = _run(["sudo", "-u", FRAPPE_USER, "stat", str(path)])
    return rc == 0


def _sudo_is_dir(path: str | Path) -> bool:
    """Check if a path is a directory using find -maxdepth 0 -type d."""
    out, _, rc = _run([
        "sudo", "-u", FRAPPE_USER,
        "find", str(path), "-maxdepth", "0", "-type", "d",
    ])
    return rc == 0 and out.strip() != ""


def _read_json_sudo(path: str | Path) -> dict:
    """Read and parse a JSON file as the frappe user."""
    content = _sudo_cat(path)
    if not content:
        return {}
    try:
        return json.loads(content)
    except Exception:
        return {}


def _site_names() -> list[str]:
    """Return list of site names by finding site_config.json files as frappe user."""
    out, _, rc = _run([
        "sudo", "-u", FRAPPE_USER,
        "find", str(SITES_DIR), "-maxdepth", "2", "-name", "site_config.json",
    ])
    if rc != 0:
        return []
    sites = []
    for line in out.splitlines():
        p = Path(line.strip())
        if p.parent != SITES_DIR:
            sites.append(p.parent.name)
    return sorted(sites)


def _installed_apps() -> list[str]:
    """Return list of installed app directories as frappe user.
    Uses a single find for <app>/<app>/__init__.py to identify real apps."""
    out, _, rc = _run([
        "sudo", "-u", FRAPPE_USER,
        "find", str(APPS_DIR), "-maxdepth", "3", "-mindepth", "2",
        "-name", "__init__.py", "-type", "f",
    ])
    if rc != 0:
        return []
    apps = set()
    for line in out.splitlines():
        p = Path(line.strip())
        # Accept <APPS_DIR>/<app_name>/<app_name>/__init__.py
        # or <APPS_DIR>/<app_name>/__init__.py
        rel = p.relative_to(APPS_DIR)
        parts = rel.parts
        if len(parts) >= 1 and not parts[0].startswith("."):
            apps.add(parts[0])
    return sorted(apps)


# ---------------------------------------------------------------------------
# Sites
# ---------------------------------------------------------------------------

class NewSiteRequest(BaseModel):
    site_name: str
    admin_password: str
    db_name: str = ""
    install_apps: list[str] = []


@router.post("/sites/create")
async def create_site(req: NewSiteRequest, _: str = Depends(require_super_admin)) -> dict:
    """Create a new Frappe site using bench new-site."""
    if not req.site_name or not req.admin_password:
        raise HTTPException(400, "site_name and admin_password are required")
    # Basic validation — site name should be a valid hostname
    import re
    if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9\.\-]{1,}$', req.site_name):
        raise HTTPException(400, "Invalid site name")

    args = ["new-site", req.site_name, "--admin-password", req.admin_password, "--no-mariadb-socket"]
    if req.db_name:
        args += ["--db-name", req.db_name]
    for app in req.install_apps:
        args += ["--install-app", app]

    out, err, rc = _bench(args, timeout=300)
    return {
        "site": req.site_name,
        "ok": rc == 0,
        "output": (out + err)[-3000:].strip(),
    }


@router.get("/sites")
async def list_sites(_: str = Depends(require_super_admin)) -> dict:
    """List all Frappe sites with their configuration."""
    sites = []
    for name in _site_names():
        site_dir = SITES_DIR / name
        cfg = _read_json_sudo(site_dir / "site_config.json")
        # Read installed apps list
        apps_txt_content = _sudo_cat(site_dir / ".apps")
        installed = [a for a in apps_txt_content.splitlines() if a.strip()] if apps_txt_content else []
        sites.append({
            "name": name,
            "db_name": cfg.get("db_name", ""),
            "db_host": cfg.get("db_host", "localhost"),
            "installed_apps": installed,
            "maintenance_mode": cfg.get("maintenance_mode", 0),
            "developer_mode": cfg.get("developer_mode", 0),
            "frappe_user": FRAPPE_USER,
        })
    return {"sites": sites, "count": len(sites), "bench_dir": str(BENCH_DIR)}


@router.get("/sites/{site}/config")
async def get_site_config(site: str, _: str = Depends(require_super_admin)) -> dict:
    """Get full site_config.json for a site."""
    cfg_path = SITES_DIR / site / "site_config.json"
    if not _sudo_exists(cfg_path):
        raise HTTPException(404, f"Site '{site}' not found")
    return {"site": site, "config": _read_json_sudo(cfg_path)}


@router.post("/sites/{site}/clear-cache")
async def clear_site_cache(site: str, _: str = Depends(require_super_admin)) -> dict:
    out, err, rc = _bench(["--site", site, "clear-cache"], timeout=30)
    return {"site": site, "ok": rc == 0, "output": (out + err).strip()}


@router.post("/sites/{site}/clear-website-cache")
async def clear_website_cache(site: str, _: str = Depends(require_super_admin)) -> dict:
    out, err, rc = _bench(["--site", site, "clear-website-cache"], timeout=30)
    return {"site": site, "ok": rc == 0, "output": (out + err).strip()}


@router.post("/sites/{site}/migrate")
async def migrate_site(site: str, _: str = Depends(require_super_admin)) -> dict:
    out, err, rc = _bench(["--site", site, "migrate"], timeout=180)
    return {"site": site, "ok": rc == 0, "output": (out + err)[-3000:]}


@router.post("/sites/{site}/backup")
async def backup_site(site: str, _: str = Depends(require_super_admin)) -> dict:
    out, err, rc = _bench(["--site", site, "backup", "--with-files"], timeout=300)
    return {"site": site, "ok": rc == 0, "output": (out + err).strip()}


@router.post("/sites/{site}/maintenance-mode")
async def toggle_maintenance(site: str, enable: bool = True, _: str = Depends(require_super_admin)) -> dict:
    cmd = ["--site", site, "set-maintenance-mode", "on" if enable else "off"]
    out, err, rc = _bench(cmd, timeout=30)
    return {"site": site, "maintenance_mode": enable, "ok": rc == 0, "output": (out + err).strip()}


@router.get("/sites/{site}/backups")
async def list_backups(site: str, _: str = Depends(require_super_admin)) -> dict:
    backup_dir = SITES_DIR / site / "private" / "backups"
    # Use find to list backup files with modification time and size
    out, _, rc = _run([
        "sudo", "-u", FRAPPE_USER,
        "find", str(backup_dir), "-maxdepth", "1", "-type", "f",
        "-printf", "%f|%s|%T@\n",
    ])
    backups = []
    if rc == 0:
        for line in out.splitlines():
            parts = line.strip().split("|")
            if len(parts) == 3:
                fname, size_str, mtime_str = parts
                try:
                    mtime = datetime.fromtimestamp(float(mtime_str), UTC).isoformat()
                    backups.append({
                        "name": fname,
                        "path": str(backup_dir / fname),
                        "size": int(size_str),
                        "modified": mtime,
                    })
                except (ValueError, OSError):
                    pass
    backups.sort(key=lambda x: x["modified"], reverse=True)
    return {"site": site, "backups": backups[:20], "count": len(backups)}


@router.get("/sites/{site}/scheduler-logs")
async def get_scheduler_logs(site: str, _: str = Depends(require_super_admin)) -> dict:
    log_path = SITES_DIR / site / "logs" / "scheduler.log"
    lines: list[str] = []
    if _sudo_exists(log_path):
        out, _, rc = _run(["sudo", "-u", FRAPPE_USER, "tail", "-n", "100", str(log_path)])
        if rc == 0:
            lines = out.splitlines()
    return {"site": site, "lines": lines, "log_path": str(log_path)}


# ---------------------------------------------------------------------------
# Apps
# ---------------------------------------------------------------------------

@router.get("/apps")
async def list_apps(_: str = Depends(require_super_admin)) -> dict:
    """List all installed apps in the bench."""
    apps = []
    for app_name in _installed_apps():
        app_dir = APPS_DIR / app_name

        # Read __init__.py for version (try <app>/<app>/__init__.py first)
        version = ""
        for init_candidate in [
            app_dir / app_name / "__init__.py",
            app_dir / "__init__.py",
        ]:
            if _sudo_exists(init_candidate):
                content = _sudo_cat(init_candidate)
                for line in content.splitlines():
                    if "__version__" in line and "=" in line:
                        version = line.split("=", 1)[1].strip().strip('"\'')
                        break
                if version:
                    break

        # Read hooks.py for app_title, app_publisher
        hooks_path = app_dir / app_name / "hooks.py"
        title = app_name
        publisher = ""
        if _sudo_exists(hooks_path):
            for line in _sudo_cat(hooks_path).splitlines():
                if line.startswith("app_title"):
                    title = line.split("=", 1)[1].strip().strip('"\'')
                elif line.startswith("app_publisher"):
                    publisher = line.split("=", 1)[1].strip().strip('"\'')

        # Git info — run as frappe user
        git_out, _, git_rc = _run(["sudo", "-u", FRAPPE_USER, "git", "-C", str(app_dir), "log", "--oneline", "-1"])
        last_commit = git_out.strip() if git_rc == 0 else ""

        branch_out, _, _ = _run(["sudo", "-u", FRAPPE_USER, "git", "-C", str(app_dir), "rev-parse", "--abbrev-ref", "HEAD"])
        branch = branch_out.strip()

        apps.append({
            "name": app_name,
            "title": title,
            "publisher": publisher,
            "version": version,
            "last_commit": last_commit,
            "branch": branch,
            "path": str(app_dir),
        })

    return {"apps": apps, "count": len(apps)}


@router.post("/apps/{app}/pull")
async def pull_app(app: str, _: str = Depends(require_super_admin)) -> dict:
    """Git pull for an app."""
    app_dir = APPS_DIR / app
    if not _sudo_is_dir(app_dir):
        raise HTTPException(404, f"App '{app}' not found")
    out, err, rc = _run(["sudo", "-u", FRAPPE_USER, "git", "-C", str(app_dir), "pull"], timeout=60)
    return {"app": app, "ok": rc == 0, "output": (out + err).strip()}


class GetAppRequest(BaseModel):
    url: str          # GitHub URL, PyPI name, or frappe app name
    branch: str = ""  # optional branch/tag


@router.post("/apps/get-app")
async def get_app(req: GetAppRequest, _: str = Depends(require_super_admin)) -> dict:
    """Fetch a new app into the bench using bench get-app."""
    if not req.url:
        raise HTTPException(400, "url is required")
    args = ["get-app", req.url]
    if req.branch:
        args += ["--branch", req.branch]
    out, err, rc = _bench(args, timeout=300)
    return {"ok": rc == 0, "output": (out + err)[-4000:].strip()}


class SiteInstallRequest(BaseModel):
    site: str


@router.post("/apps/{app}/install-on-site")
async def install_app_on_site(app: str, req: SiteInstallRequest, _: str = Depends(require_super_admin)) -> dict:
    """Install a bench app on a specific site."""
    if not req.site:
        raise HTTPException(400, "site is required")
    out, err, rc = _bench(["--site", req.site, "install-app", app], timeout=180)
    return {"app": app, "site": req.site, "ok": rc == 0, "output": (out + err)[-3000:].strip()}


@router.post("/apps/{app}/uninstall-from-site")
async def uninstall_app_from_site(app: str, req: SiteInstallRequest, _: str = Depends(require_super_admin)) -> dict:
    """Uninstall a bench app from a specific site."""
    if not req.site:
        raise HTTPException(400, "site is required")
    out, err, rc = _bench(["--site", req.site, "uninstall-app", app, "--yes"], timeout=180)
    return {"app": app, "site": req.site, "ok": rc == 0, "output": (out + err)[-3000:].strip()}


# ---------------------------------------------------------------------------
# Workers
# ---------------------------------------------------------------------------

@router.get("/workers")
async def list_workers(_: str = Depends(require_super_admin)) -> dict:
    """List all bench worker processes (supervisor status)."""
    out, err, rc = _run(["sudo", "supervisorctl", "status"], timeout=10)
    workers = []
    for line in (out + err).splitlines():
        parts = line.split()
        if len(parts) >= 2:
            name = parts[0]
            status = parts[1] if len(parts) > 1 else "UNKNOWN"
            pid_info = parts[3] if len(parts) > 3 else ""
            uptime = " ".join(parts[4:]) if len(parts) > 4 else ""
            workers.append({
                "name": name,
                "status": status,
                "pid": pid_info.rstrip(","),
                "uptime": uptime,
                "running": status == "RUNNING",
            })
    return {"workers": workers, "count": len(workers)}


class WorkerAction(BaseModel):
    action: str  # start, stop, restart


@router.post("/workers/{worker}/action")
async def worker_action(worker: str, req: WorkerAction, _: str = Depends(require_super_admin)) -> dict:
    if req.action not in ("start", "stop", "restart"):
        raise HTTPException(400, "action must be start, stop, or restart")
    out, err, rc = _run(["sudo", "supervisorctl", req.action, worker], timeout=30)
    return {"worker": worker, "action": req.action, "ok": rc == 0, "output": (out + err).strip()}


@router.post("/workers/restart-all")
async def restart_all_workers(_: str = Depends(require_super_admin)) -> dict:
    out, err, rc = _run(
        ["sudo", "supervisorctl", "restart", "frappe-bench-web:*", "frappe-bench-workers:*"],
        timeout=60,
    )
    return {"ok": rc == 0, "output": (out + err).strip()}


# ---------------------------------------------------------------------------
# Scheduler
# ---------------------------------------------------------------------------

def _scheduler_status_for_site(site: str, common: dict) -> dict:
    """Compute real scheduler status by merging common + per-site config.

    Priority: per-site site_config.json overrides common_site_config.json.
    Status values: 'enabled' | 'paused' | 'disabled'

    Logic:
      - enable_scheduler == 0  → disabled (scheduler fully off)
      - enable_scheduler != 0 AND pause_scheduler == 1 → paused
      - enable_scheduler != 0 AND pause_scheduler != 1 → enabled
      - maintenance_mode == 1 → also note maintenance (scheduler still runs but we flag it)
    """
    site_cfg = _read_json_sudo(SITES_DIR / site / "site_config.json")

    # Resolve each key: per-site wins over common
    def resolve(key: str, default: int) -> int:
        if key in site_cfg:
            v = site_cfg[key]
        elif key in common:
            v = common[key]
        else:
            return default
        return 1 if v else 0

    enable = resolve("enable_scheduler", 1)
    paused = resolve("pause_scheduler", 0)
    maintenance = resolve("maintenance_mode", 0)

    if enable == 0:
        status = "disabled"
    elif paused == 1:
        status = "paused"
    else:
        status = "enabled"

    return {
        "site": site,
        "status": status,
        "enable_scheduler": enable,
        "pause_scheduler": paused,
        "maintenance_mode": maintenance,
        # source of each value for transparency
        "enable_source": "site" if "enable_scheduler" in site_cfg else "common" if "enable_scheduler" in common else "default",
        "pause_source": "site" if "pause_scheduler" in site_cfg else "common" if "pause_scheduler" in common else "default",
    }


@router.get("/scheduler")
async def get_scheduler_status(_: str = Depends(require_super_admin)) -> dict:
    """Get scheduler status for all sites, resolved from config files directly."""
    common = _read_json_sudo(SITES_DIR / "common_site_config.json")
    statuses = [_scheduler_status_for_site(site, common) for site in _site_names()]
    return {"sites": statuses}


@router.post("/scheduler/{site}/{action}")
async def scheduler_action(site: str, action: str, _: str = Depends(require_super_admin)) -> dict:
    if action not in ("enable", "disable", "resume", "pause"):
        raise HTTPException(400, "Invalid scheduler action")
    out, err, rc = _bench(["--site", site, "scheduler", action], timeout=15)
    ok = rc == 0
    # Re-read real status after the action so the response includes the updated state
    if ok:
        common = _read_json_sudo(SITES_DIR / "common_site_config.json")
        updated = _scheduler_status_for_site(site, common)
    else:
        updated = {}
    return {
        "site": site, "action": action, "ok": ok,
        "output": (out + err).strip(),
        **updated,
    }


# ---------------------------------------------------------------------------
# Bench info and operations
# ---------------------------------------------------------------------------

@router.get("/info")
async def bench_info(_: str = Depends(require_super_admin)) -> dict:
    """Return bench version, Python version, and node version."""
    bench_v, _, _ = _bench(["version"], timeout=10)
    python_v, _, _ = _run(["python3", "--version"])
    node_v, _, _ = _run(["node", "--version"])
    pip_v, _, _ = _run(["pip3", "--version"])
    common_cfg = _read_json_sudo(SITES_DIR / "common_site_config.json")
    return {
        "bench_version": bench_v.strip(),
        "python_version": python_v.strip(),
        "node_version": node_v.strip(),
        "pip_version": pip_v.strip(),
        "bench_dir": str(BENCH_DIR),
        "sites_count": len(_site_names()),
        "apps_count": len(_installed_apps()),
        "common_config": common_cfg,
    }


@router.get("/logs")
async def get_bench_logs(_: str = Depends(require_super_admin)) -> dict:
    """Return recent bench log files."""
    logs_dir = BENCH_DIR / "logs"
    out, _, rc = _run([
        "sudo", "-u", FRAPPE_USER,
        "find", str(logs_dir), "-maxdepth", "1", "-type", "f",
        "-printf", "%f|%s|%T@\n",
    ])
    entries = []
    if rc == 0:
        for line in out.splitlines():
            parts = line.strip().split("|")
            if len(parts) == 3:
                fname, size_str, mtime_str = parts
                try:
                    entries.append({
                        "name": fname,
                        "path": str(logs_dir / fname),
                        "size": int(size_str),
                        "modified": datetime.fromtimestamp(float(mtime_str), UTC).isoformat(),
                    })
                except (ValueError, OSError):
                    pass
    entries.sort(key=lambda x: x["modified"], reverse=True)
    return {"logs": entries[:30]}


@router.get("/logs/{logfile}")
async def read_bench_log(logfile: str, lines: int = 100, _: str = Depends(require_super_admin)) -> dict:
    """Read tail of a bench log file."""
    # Sanitize — only allow plain filenames, no path traversal
    if "/" in logfile or ".." in logfile:
        raise HTTPException(400, "Invalid log file name")
    log_path = BENCH_DIR / "logs" / logfile
    if not _sudo_exists(log_path):
        raise HTTPException(404, f"Log file '{logfile}' not found")
    out, _, _ = _run(["sudo", "-u", FRAPPE_USER, "tail", "-n", str(min(lines, 500)), str(log_path)])
    return {"logfile": logfile, "lines": out.splitlines(), "path": str(log_path)}


@router.get("/common-config")
async def get_common_config(_: str = Depends(require_super_admin)) -> dict:
    cfg_path = SITES_DIR / "common_site_config.json"
    return {"config": _read_json_sudo(cfg_path), "path": str(cfg_path)}


class ConfigUpdate(BaseModel):
    config: dict


@router.put("/common-config")
async def update_common_config(req: ConfigUpdate, _: str = Depends(require_super_admin)) -> dict:
    cfg_path = SITES_DIR / "common_site_config.json"
    existing = _read_json_sudo(cfg_path)
    existing.update(req.config)
    new_content = json.dumps(existing, indent=2)
    # Write via sudo tee so it runs as frappe user
    out, err, rc = _run(
        ["sudo", "-u", FRAPPE_USER, "tee", str(cfg_path)],
        stdin_data=new_content,
    )
    if rc != 0:
        raise HTTPException(500, f"Write failed: {err.strip()}")
    return {"ok": True, "path": str(cfg_path)}


# ---------------------------------------------------------------------------
# Email
# ---------------------------------------------------------------------------

@router.post("/sites/{site}/send-test-email")
async def send_test_email(site: str, to: str, _: str = Depends(require_super_admin)) -> dict:
    out, err, rc = _bench(
        ["--site", site, "execute", "frappe.sendmail",
         "--kwargs", f'{{"recipients": ["{to}"], "subject": "FrothIQ Test Email", "message": "Test from FrothIQ Control Center", "delayed": false}}'],
        timeout=30,
    )
    return {"site": site, "to": to, "ok": rc == 0, "output": (out + err).strip()}


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

@router.get("/sites/{site}/db-info")
async def get_db_info(site: str, _: str = Depends(require_super_admin)) -> dict:
    cfg = _read_json_sudo(SITES_DIR / site / "site_config.json")
    db_name = cfg.get("db_name", "")
    if not db_name:
        raise HTTPException(404, "db_name not found in site config")

    query = f"SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='{db_name}'"
    out, _, _ = _run(["mysql", "-N", "-e", query], timeout=10)
    table_count = out.strip()

    size_query = (
        f"SELECT ROUND(SUM(data_length + index_length) / 1024 / 1024, 2) "
        f"FROM information_schema.tables WHERE table_schema='{db_name}'"
    )
    size_out, _, _ = _run(["mysql", "-N", "-e", size_query], timeout=10)

    return {
        "site": site,
        "db_name": db_name,
        "db_host": cfg.get("db_host", "localhost"),
        "table_count": table_count,
        "size_mb": size_out.strip(),
    }
