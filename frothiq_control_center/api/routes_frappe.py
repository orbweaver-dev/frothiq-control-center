"""
Frappe Bench management API — super_admin only.
Provides site, app, worker, scheduler, and bench operations.
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
# Helpers
# ---------------------------------------------------------------------------

def _run(cmd: list[str], timeout: int = 30, cwd: str | None = None) -> tuple[str, str, int]:
    try:
        r = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            cwd=cwd or str(BENCH_DIR),
            env={**os.environ, "HOME": f"/home/{FRAPPE_USER}"},
        )
        return r.stdout, r.stderr, r.returncode
    except subprocess.TimeoutExpired:
        return "", f"Command timed out after {timeout}s", 1
    except Exception as e:
        return "", str(e), 1


def _bench(args: list[str], timeout: int = 60) -> tuple[str, str, int]:
    """Run a bench command as the frappe user via sudo."""
    return _run(
        ["sudo", "-u", FRAPPE_USER, "bench"] + args,
        timeout=timeout,
        cwd=str(BENCH_DIR),
    )


def _read_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text())
    except Exception:
        return {}


def _site_names() -> list[str]:
    """Return list of site names (directories that have site_config.json)."""
    sites = []
    for p in SITES_DIR.iterdir():
        if p.is_dir() and (p / "site_config.json").exists():
            sites.append(p.name)
    return sorted(sites)


def _installed_apps() -> list[str]:
    """Return list of installed app directories."""
    apps = []
    for p in APPS_DIR.iterdir():
        if p.is_dir() and (p / "__init__.py").exists() and not p.name.startswith("."):
            apps.append(p.name)
    return sorted(apps)


# ---------------------------------------------------------------------------
# Sites
# ---------------------------------------------------------------------------

@router.get("/sites")
async def list_sites(_: str = Depends(require_super_admin)) -> dict:
    """List all Frappe sites with their configuration."""
    sites = []
    for name in _site_names():
        site_dir = SITES_DIR / name
        cfg = _read_json(site_dir / "site_config.json")
        # Read installed apps
        apps_txt = site_dir / ".apps"
        installed = apps_txt.read_text().splitlines() if apps_txt.exists() else []
        sites.append({
            "name": name,
            "db_name": cfg.get("db_name", ""),
            "db_host": cfg.get("db_host", "localhost"),
            "installed_apps": [a for a in installed if a.strip()],
            "maintenance_mode": cfg.get("maintenance_mode", 0),
            "developer_mode": cfg.get("developer_mode", 0),
            "frappe_user": FRAPPE_USER,
        })
    return {"sites": sites, "count": len(sites), "bench_dir": str(BENCH_DIR)}


@router.get("/sites/{site}/config")
async def get_site_config(site: str, _: str = Depends(require_super_admin)) -> dict:
    """Get full site_config.json for a site."""
    cfg_path = SITES_DIR / site / "site_config.json"
    if not cfg_path.exists():
        raise HTTPException(404, f"Site '{site}' not found")
    return {"site": site, "config": _read_json(cfg_path)}


@router.post("/sites/{site}/clear-cache")
async def clear_site_cache(site: str, _: str = Depends(require_super_admin)) -> dict:
    """Clear cache for a specific site."""
    out, err, rc = _bench(["--site", site, "clear-cache"], timeout=30)
    return {"site": site, "ok": rc == 0, "output": (out + err).strip()}


@router.post("/sites/{site}/clear-website-cache")
async def clear_website_cache(site: str, _: str = Depends(require_super_admin)) -> dict:
    out, err, rc = _bench(["--site", site, "clear-website-cache"], timeout=30)
    return {"site": site, "ok": rc == 0, "output": (out + err).strip()}


@router.post("/sites/{site}/migrate")
async def migrate_site(site: str, _: str = Depends(require_super_admin)) -> dict:
    """Run database migrations for a site."""
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
    backups = []
    if backup_dir.exists():
        for f in sorted(backup_dir.iterdir(), key=lambda x: x.stat().st_mtime, reverse=True):
            if f.is_file():
                st = f.stat()
                backups.append({
                    "name": f.name,
                    "path": str(f),
                    "size": st.st_size,
                    "modified": datetime.fromtimestamp(st.st_mtime, UTC).isoformat(),
                })
    return {"site": site, "backups": backups[:20], "count": len(backups)}


@router.get("/sites/{site}/scheduler-logs")
async def get_scheduler_logs(site: str, _: str = Depends(require_super_admin)) -> dict:
    log_path = SITES_DIR / site / "logs" / "scheduler.log"
    lines: list[str] = []
    if log_path.exists():
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
        # Read __init__.py for version
        version = ""
        init_py = app_dir / app_name / "__init__.py"
        if not init_py.exists():
            # Try package init
            init_py = app_dir / "__init__.py"
        if init_py.exists():
            for line in init_py.read_text(errors="replace").splitlines():
                if "__version__" in line and "=" in line:
                    version = line.split("=", 1)[1].strip().strip('"\'')
                    break

        # Try hooks.py for app_title, app_publisher
        hooks_path = app_dir / app_name / "hooks.py"
        title = app_name
        publisher = ""
        if hooks_path.exists():
            for line in hooks_path.read_text(errors="replace").splitlines():
                if line.startswith("app_title"):
                    title = line.split("=", 1)[1].strip().strip('"\'')
                elif line.startswith("app_publisher"):
                    publisher = line.split("=", 1)[1].strip().strip('"\'')

        # Git info
        git_out, _, git_rc = _run(["git", "-C", str(app_dir), "log", "--oneline", "-1"])
        last_commit = git_out.strip() if git_rc == 0 else ""

        branch_out, _, _ = _run(["git", "-C", str(app_dir), "rev-parse", "--abbrev-ref", "HEAD"])
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
    if not app_dir.is_dir():
        raise HTTPException(404, f"App '{app}' not found")
    out, err, rc = _run(["sudo", "-u", FRAPPE_USER, "git", "-C", str(app_dir), "pull"], timeout=60)
    return {"app": app, "ok": rc == 0, "output": (out + err).strip()}


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
    """Control a supervisor worker process."""
    if req.action not in ("start", "stop", "restart"):
        raise HTTPException(400, "action must be start, stop, or restart")
    out, err, rc = _run(["sudo", "supervisorctl", req.action, worker], timeout=30)
    return {"worker": worker, "action": req.action, "ok": rc == 0, "output": (out + err).strip()}


@router.post("/workers/restart-all")
async def restart_all_workers(_: str = Depends(require_super_admin)) -> dict:
    """Restart all bench workers and web server."""
    out, err, rc = _run(["sudo", "supervisorctl", "restart", "frappe-bench-web:*", "frappe-bench-workers:*"], timeout=60)
    return {"ok": rc == 0, "output": (out + err).strip()}


# ---------------------------------------------------------------------------
# Scheduler
# ---------------------------------------------------------------------------

@router.get("/scheduler")
async def get_scheduler_status(_: str = Depends(require_super_admin)) -> dict:
    """Get scheduler status for all sites."""
    statuses = []
    for site in _site_names():
        out, _, _ = _bench(["--site", site, "scheduler", "status"], timeout=15)
        statuses.append({"site": site, "output": out.strip()})
    return {"sites": statuses}


@router.post("/scheduler/{site}/{action}")
async def scheduler_action(site: str, action: str, _: str = Depends(require_super_admin)) -> dict:
    if action not in ("enable", "disable", "resume", "pause"):
        raise HTTPException(400, "Invalid scheduler action")
    out, err, rc = _bench(["--site", site, "scheduler", action], timeout=15)
    return {"site": site, "action": action, "ok": rc == 0, "output": (out + err).strip()}


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
    common_cfg = _read_json(SITES_DIR / "common_site_config.json")
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
    entries = []
    if logs_dir.exists():
        for f in sorted(logs_dir.iterdir(), key=lambda x: x.stat().st_mtime, reverse=True):
            if f.is_file():
                st = f.stat()
                entries.append({
                    "name": f.name,
                    "path": str(f),
                    "size": st.st_size,
                    "modified": datetime.fromtimestamp(st.st_mtime, UTC).isoformat(),
                })
    return {"logs": entries[:30]}


@router.get("/logs/{logfile}")
async def read_bench_log(logfile: str, lines: int = 100, _: str = Depends(require_super_admin)) -> dict:
    """Read tail of a bench log file."""
    log_path = BENCH_DIR / "logs" / logfile
    if not log_path.exists() or not log_path.is_file():
        raise HTTPException(404, f"Log file '{logfile}' not found")
    out, _, _ = _run(["sudo", "-u", FRAPPE_USER, "tail", "-n", str(min(lines, 500)), str(log_path)])
    return {"logfile": logfile, "lines": out.splitlines(), "path": str(log_path)}


@router.get("/common-config")
async def get_common_config(_: str = Depends(require_super_admin)) -> dict:
    cfg_path = SITES_DIR / "common_site_config.json"
    return {"config": _read_json(cfg_path), "path": str(cfg_path)}


class ConfigUpdate(BaseModel):
    config: dict


@router.put("/common-config")
async def update_common_config(req: ConfigUpdate, _: str = Depends(require_super_admin)) -> dict:
    cfg_path = SITES_DIR / "common_site_config.json"
    try:
        existing = _read_json(cfg_path)
        existing.update(req.config)
        cfg_path.write_text(json.dumps(existing, indent=2))
        return {"ok": True, "path": str(cfg_path)}
    except Exception as e:
        raise HTTPException(500, str(e))


# ---------------------------------------------------------------------------
# Email
# ---------------------------------------------------------------------------

@router.post("/sites/{site}/send-test-email")
async def send_test_email(site: str, to: str, _: str = Depends(require_super_admin)) -> dict:
    out, err, rc = _bench(
        ["--site", site, "execute", "frappe.utils.email_lib.sendmail",
         "--args", f'["{to}"]', "--kwargs", '{"subject": "FrothIQ Test Email", "message": "Test from FrothIQ Control Center"}'],
        timeout=30,
    )
    return {"site": site, "to": to, "ok": rc == 0, "output": (out + err).strip()}


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

@router.get("/sites/{site}/db-info")
async def get_db_info(site: str, _: str = Depends(require_super_admin)) -> dict:
    cfg = _read_json(SITES_DIR / site / "site_config.json")
    db_name = cfg.get("db_name", "")
    if not db_name:
        raise HTTPException(404, "db_name not found in site config")

    # Table count and size
    query = f"SELECT COUNT(*) as cnt FROM information_schema.tables WHERE table_schema='{db_name}'"
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
        "table_count": table_count.strip(),
        "size_mb": size_out.strip(),
    }
