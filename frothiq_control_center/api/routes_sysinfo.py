"""
ServOps — system information endpoints (super_admin only).
Host metrics, processes, cron, logs, packages, users/groups, filesystems.
"""

from __future__ import annotations

import grp
import platform
import pwd
import re
import subprocess
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, Query

import psutil

from .routes_auth import require_super_admin

router = APIRouter(prefix="/sysinfo", tags=["sysinfo"])


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _uptime_str(boot_ts: float) -> str:
    secs = int(time.time() - boot_ts)
    days, rem = divmod(secs, 86400)
    hours, rem = divmod(rem, 3600)
    mins = rem // 60
    parts = []
    if days:
        parts.append(f"{days}d")
    if hours or days:
        parts.append(f"{hours}h")
    parts.append(f"{mins}m")
    return " ".join(parts)


def _run(cmd: list[str], timeout: int = 10) -> str:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.stdout
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# Dashboard — overall system health
# ---------------------------------------------------------------------------

@router.get("")
async def get_sysinfo(_: str = Depends(require_super_admin)) -> dict:
    boot_ts = psutil.boot_time()
    cpu_pct = psutil.cpu_percent(interval=0.2)
    load_avg = list(psutil.getloadavg())
    mem = psutil.virtual_memory()
    swap = psutil.swap_memory()

    disks = []
    for part in psutil.disk_partitions(all=False):
        try:
            usage = psutil.disk_usage(part.mountpoint)
        except PermissionError:
            continue
        disks.append({
            "mountpoint": part.mountpoint,
            "device": part.device,
            "fstype": part.fstype,
            "total_gb": round(usage.total / 1e9, 2),
            "used_gb": round(usage.used / 1e9, 2),
            "free_gb": round(usage.free / 1e9, 2),
            "percent": usage.percent,
        })

    net = psutil.net_io_counters()
    uname = platform.uname()

    return {
        "hostname": uname.node,
        "os": f"{uname.system} {uname.release}",
        "kernel": uname.version,
        "arch": uname.machine,
        "python": platform.python_version(),
        "uptime": _uptime_str(boot_ts),
        "boot_time": datetime.fromtimestamp(boot_ts, tz=UTC).isoformat(),
        "cpu": {
            "percent": cpu_pct,
            "logical_cores": psutil.cpu_count(logical=True),
            "physical_cores": psutil.cpu_count(logical=False),
            "load_avg_1m": round(load_avg[0], 2),
            "load_avg_5m": round(load_avg[1], 2),
            "load_avg_15m": round(load_avg[2], 2),
        },
        "memory": {
            "total_gb": round(mem.total / 1e9, 2),
            "used_gb": round(mem.used / 1e9, 2),
            "available_gb": round(mem.available / 1e9, 2),
            "percent": mem.percent,
            "swap_total_gb": round(swap.total / 1e9, 2),
            "swap_used_gb": round(swap.used / 1e9, 2),
            "swap_percent": swap.percent,
        },
        "disks": disks,
        "network": {
            "bytes_sent_mb": round(net.bytes_sent / 1e6, 2),
            "bytes_recv_mb": round(net.bytes_recv / 1e6, 2),
            "packets_sent": net.packets_sent,
            "packets_recv": net.packets_recv,
            "interfaces": list(psutil.net_if_addrs().keys()),
        },
        "processes": len(psutil.pids()),
        "checked_at": datetime.now(UTC).isoformat(),
    }


# ---------------------------------------------------------------------------
# Running Processes
# ---------------------------------------------------------------------------

@router.get("/processes")
async def get_processes(
    _: str = Depends(require_super_admin),
    limit: int = Query(100, ge=1, le=500),
    sort: str = Query("cpu", pattern="^(cpu|mem|pid|name)$"),
) -> dict:
    procs = []
    for p in psutil.process_iter(["pid", "name", "username", "status", "cpu_percent", "memory_percent", "create_time", "cmdline"]):
        try:
            info = p.info
            procs.append({
                "pid": info["pid"],
                "name": info["name"] or "",
                "user": info["username"] or "",
                "status": info["status"] or "",
                "cpu_pct": round(info["cpu_percent"] or 0, 1),
                "mem_pct": round(info["memory_percent"] or 0, 2),
                "started": datetime.fromtimestamp(info["create_time"], tz=UTC).isoformat() if info["create_time"] else None,
                "cmd": " ".join(info["cmdline"] or [])[:120],
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    key_map = {"cpu": "cpu_pct", "mem": "mem_pct", "pid": "pid", "name": "name"}
    procs.sort(key=lambda x: x[key_map[sort]], reverse=(sort in ("cpu", "mem")))

    return {
        "total": len(procs),
        "processes": procs[:limit],
        "checked_at": datetime.now(UTC).isoformat(),
    }


# ---------------------------------------------------------------------------
# Scheduled Cron Jobs
# ---------------------------------------------------------------------------

@router.get("/cron")
async def get_cron(_: str = Depends(require_super_admin)) -> dict:
    jobs: list[dict[str, Any]] = []

    # System crontab
    system_crontab = Path("/etc/crontab")
    if system_crontab.exists():
        _parse_crontab_file(system_crontab, "system", jobs)

    # /etc/cron.d/
    cron_d = Path("/etc/cron.d")
    if cron_d.is_dir():
        for f in sorted(cron_d.iterdir()):
            if f.is_file() and not f.name.startswith("."):
                _parse_crontab_file(f, f"cron.d/{f.name}", jobs)

    # User crontabs via crontab -l for known users
    for user in _system_users(shell_only=True):
        out = _run(["crontab", "-l", "-u", user], timeout=5)
        for line in out.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(None, 5)
            if len(parts) >= 6:
                jobs.append({
                    "source": f"user:{user}",
                    "schedule": " ".join(parts[:5]),
                    "user": user,
                    "command": parts[5],
                })

    return {"total": len(jobs), "jobs": jobs, "checked_at": datetime.now(UTC).isoformat()}


def _parse_crontab_file(path: Path, source: str, jobs: list) -> None:
    try:
        for line in path.read_text(errors="replace").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("@"):
                parts = line.split(None, 2)
                if len(parts) >= 2:
                    jobs.append({"source": source, "schedule": parts[0], "user": parts[1] if len(parts) > 2 else "", "command": parts[-1]})
                continue
            parts = line.split(None, 6)
            if len(parts) >= 6:
                jobs.append({
                    "source": source,
                    "schedule": " ".join(parts[:5]),
                    "user": parts[5] if len(parts) > 6 else "",
                    "command": parts[-1],
                })
    except Exception:
        pass


# ---------------------------------------------------------------------------
# System Logs
# ---------------------------------------------------------------------------

LOG_FILES = [
    "/var/log/syslog",
    "/var/log/auth.log",
    "/var/log/kern.log",
    "/var/log/dpkg.log",
    "/var/log/apt/history.log",
    "/var/log/nginx/access.log",
    "/var/log/nginx/error.log",
    "/var/log/apache2/access.log",
    "/var/log/apache2/error.log",
    "/var/log/mysql/error.log",
    "/var/log/fail2ban.log",
]


@router.get("/logs")
async def get_log_files(_: str = Depends(require_super_admin)) -> dict:
    files = []
    for path_str in LOG_FILES:
        p = Path(path_str)
        if p.exists():
            stat = p.stat()
            files.append({
                "path": path_str,
                "size_kb": round(stat.st_size / 1024, 1),
                "modified": datetime.fromtimestamp(stat.st_mtime, tz=UTC).isoformat(),
            })
    return {"files": files}


@router.get("/logs/tail")
async def tail_log(
    _: str = Depends(require_super_admin),
    path: str = Query(...),
    lines: int = Query(100, ge=10, le=1000),
) -> dict:
    allowed = {p for p in LOG_FILES}
    # Allow any file under /var/log/
    if not path.startswith("/var/log/"):
        return {"error": "Path not allowed", "lines": []}
    try:
        out = _run(["tail", f"-n{lines}", path])
        return {"path": path, "lines": out.splitlines(), "checked_at": datetime.now(UTC).isoformat()}
    except Exception as e:
        return {"error": str(e), "lines": []}


# ---------------------------------------------------------------------------
# Software Packages
# ---------------------------------------------------------------------------

@router.get("/packages")
async def get_packages(
    _: str = Depends(require_super_admin),
    search: str = Query("", max_length=100),
) -> dict:
    out = _run(["dpkg-query", "-W", "-f=${Package}\t${Version}\t${Status}\t${Architecture}\n"], timeout=15)
    pkgs = []
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) < 4:
            continue
        name, version, status, arch = parts[0], parts[1], parts[2], parts[3]
        if "installed" not in status:
            continue
        if search and search.lower() not in name.lower():
            continue
        pkgs.append({"name": name, "version": version, "arch": arch})
    pkgs.sort(key=lambda x: x["name"])
    return {"total": len(pkgs), "packages": pkgs[:500], "checked_at": datetime.now(UTC).isoformat()}


@router.get("/packages/updates")
async def get_package_updates(_: str = Depends(require_super_admin)) -> dict:
    # apt list --upgradable (non-interactive)
    out = _run(["apt", "list", "--upgradable", "-q"], timeout=30)
    updates = []
    for line in out.splitlines():
        if "/" not in line or "Listing" in line:
            continue
        m = re.match(r"^(\S+)/\S+\s+(\S+)\s+(\S+)\s+\[upgradable from: (\S+)\]", line)
        if m:
            updates.append({"name": m.group(1), "new_version": m.group(2), "arch": m.group(3), "old_version": m.group(4)})
    return {"total": len(updates), "updates": updates, "checked_at": datetime.now(UTC).isoformat()}


# ---------------------------------------------------------------------------
# Users and Groups
# ---------------------------------------------------------------------------

def _system_users(shell_only: bool = False) -> list[str]:
    users = []
    for p in pwd.getpwall():
        if shell_only and p.pw_shell in ("/bin/false", "/usr/sbin/nologin", "/sbin/nologin"):
            continue
        users.append(p.pw_name)
    return users


@router.get("/users")
async def get_users(_: str = Depends(require_super_admin)) -> dict:
    users = []
    for p in sorted(pwd.getpwall(), key=lambda x: x.pw_uid):
        users.append({
            "username": p.pw_name,
            "uid": p.pw_uid,
            "gid": p.pw_gid,
            "gecos": p.pw_gecos,
            "home": p.pw_dir,
            "shell": p.pw_shell,
            "login_shell": p.pw_shell not in ("/bin/false", "/usr/sbin/nologin", "/sbin/nologin", ""),
        })
    groups = []
    for g in sorted(grp.getgrall(), key=lambda x: x.gr_gid):
        groups.append({
            "name": g.gr_name,
            "gid": g.gr_gid,
            "members": list(g.gr_mem),
        })
    return {
        "users": users,
        "groups": groups,
        "user_count": len(users),
        "group_count": len(groups),
        "checked_at": datetime.now(UTC).isoformat(),
    }


# ---------------------------------------------------------------------------
# Disk and Network Filesystems
# ---------------------------------------------------------------------------

@router.get("/filesystems")
async def get_filesystems(_: str = Depends(require_super_admin)) -> dict:
    mounts = []
    for part in psutil.disk_partitions(all=True):
        try:
            usage = psutil.disk_usage(part.mountpoint)
            used_gb = round(usage.used / 1e9, 2)
            total_gb = round(usage.total / 1e9, 2)
            free_gb = round(usage.free / 1e9, 2)
            percent = usage.percent
        except (PermissionError, OSError):
            used_gb = total_gb = free_gb = percent = None
        mounts.append({
            "device": part.device,
            "mountpoint": part.mountpoint,
            "fstype": part.fstype,
            "opts": part.opts,
            "total_gb": total_gb,
            "used_gb": used_gb,
            "free_gb": free_gb,
            "percent": percent,
        })
    return {"mounts": mounts, "count": len(mounts), "checked_at": datetime.now(UTC).isoformat()}


# ---------------------------------------------------------------------------
# Bootup and Shutdown — systemd service list
# ---------------------------------------------------------------------------

@router.get("/bootup")
async def get_bootup(_: str = Depends(require_super_admin)) -> dict:
    out = _run([
        "systemctl", "list-units", "--type=service",
        "--all", "--no-pager", "--no-legend",
        "--output=json",
    ], timeout=10)
    services = []
    if out:
        import json
        try:
            raw = json.loads(out)
            for s in raw:
                services.append({
                    "unit": s.get("unit", ""),
                    "load": s.get("load", ""),
                    "active": s.get("active", ""),
                    "sub": s.get("sub", ""),
                    "description": s.get("description", ""),
                })
        except Exception:
            pass
    return {"services": services, "count": len(services), "checked_at": datetime.now(UTC).isoformat()}
