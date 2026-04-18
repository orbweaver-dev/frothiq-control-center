"""
ServOps — system information + management endpoints (super_admin only).
"""

from __future__ import annotations

import grp
import os
import platform
import pwd
import re
import shutil
import subprocess
import threading
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

import psutil

from .routes_auth import require_super_admin

router = APIRouter(prefix="/sysinfo", tags=["sysinfo"])

# ---------------------------------------------------------------------------
# Constants / validation
# ---------------------------------------------------------------------------

SERVICE_NAME_RE = re.compile(r"^[a-zA-Z0-9._@:-]+$")
ALLOWED_SERVICE_ACTIONS = {"start", "stop", "restart", "enable", "disable", "reload"}
ALLOWED_KILL_SIGNALS = {1, 9, 15}  # SIGHUP, SIGKILL, SIGTERM

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
    "/var/log/mail.log",
]

KNOWN_SERVERS: dict[str, dict] = {
    "nginx": {
        "label": "Nginx",
        "service": "nginx",
        "binaries": ["nginx"],
        "config_paths": ["/etc/nginx/nginx.conf", "/etc/nginx/sites-enabled"],
        "log_paths": ["/var/log/nginx/error.log", "/var/log/nginx/access.log"],
        "category": "web",
    },
    "apache2": {
        "label": "Apache2",
        "service": "apache2",
        "binaries": ["apache2", "httpd"],
        "config_paths": ["/etc/apache2/apache2.conf"],
        "log_paths": ["/var/log/apache2/error.log", "/var/log/apache2/access.log"],
        "category": "web",
    },
    "mysql": {
        "label": "MySQL",
        "service": "mysql",
        "binaries": ["mysql", "mysqld"],
        "config_paths": ["/etc/mysql/my.cnf", "/etc/mysql/mysql.conf.d/mysqld.cnf"],
        "log_paths": ["/var/log/mysql/error.log"],
        "category": "database",
    },
    "mariadb": {
        "label": "MariaDB",
        "service": "mariadb",
        "binaries": ["mariadbd", "mysqld"],
        "config_paths": ["/etc/mysql/mariadb.conf.d/50-server.cnf"],
        "log_paths": ["/var/log/mysql/error.log"],
        "category": "database",
    },
    "postgresql": {
        "label": "PostgreSQL",
        "service": "postgresql",
        "binaries": ["psql", "postgres"],
        "config_paths": ["/etc/postgresql"],
        "log_paths": ["/var/log/postgresql"],
        "category": "database",
    },
    "redis": {
        "label": "Redis",
        "service": "redis-server",
        "binaries": ["redis-server", "redis-cli"],
        "config_paths": ["/etc/redis/redis.conf"],
        "log_paths": ["/var/log/redis/redis-server.log"],
        "category": "database",
    },
    "mongodb": {
        "label": "MongoDB",
        "service": "mongod",
        "binaries": ["mongod", "mongosh"],
        "config_paths": ["/etc/mongod.conf"],
        "log_paths": ["/var/log/mongodb/mongod.log"],
        "category": "database",
    },
    "postfix": {
        "label": "Postfix",
        "service": "postfix",
        "binaries": ["postfix", "postconf"],
        "config_paths": ["/etc/postfix/main.cf"],
        "log_paths": ["/var/log/mail.log"],
        "category": "mail",
    },
    "dovecot": {
        "label": "Dovecot",
        "service": "dovecot",
        "binaries": ["dovecot"],
        "config_paths": ["/etc/dovecot/dovecot.conf"],
        "log_paths": ["/var/log/mail.log"],
        "category": "mail",
    },
    "openssh": {
        "label": "OpenSSH",
        "service": "ssh",
        "binaries": ["sshd"],
        "config_paths": ["/etc/ssh/sshd_config"],
        "log_paths": ["/var/log/auth.log"],
        "category": "access",
    },
    "bind9": {
        "label": "BIND DNS",
        "service": "bind9",
        "binaries": ["named"],
        "config_paths": ["/etc/bind/named.conf"],
        "log_paths": ["/var/log/syslog"],
        "category": "dns",
    },
    "haproxy": {
        "label": "HAProxy",
        "service": "haproxy",
        "binaries": ["haproxy"],
        "config_paths": ["/etc/haproxy/haproxy.cfg"],
        "log_paths": ["/var/log/haproxy.log"],
        "category": "proxy",
    },
    "vsftpd": {
        "label": "FTP (vsftpd)",
        "service": "vsftpd",
        "binaries": ["vsftpd"],
        "config_paths": ["/etc/vsftpd.conf"],
        "log_paths": ["/var/log/vsftpd.log"],
        "category": "ftp",
    },
    "fail2ban": {
        "label": "Fail2ban",
        "service": "fail2ban",
        "binaries": ["fail2ban-client"],
        "config_paths": ["/etc/fail2ban/jail.conf", "/etc/fail2ban/jail.local"],
        "log_paths": ["/var/log/fail2ban.log"],
        "category": "security",
    },
}

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


def _run(cmd: list[str], timeout: int = 10) -> tuple[str, str, int]:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return "", "Timed out", 1
    except Exception as e:
        return "", str(e), 1


def _run_out(cmd: list[str], timeout: int = 10) -> str:
    stdout, _, _ = _run(cmd, timeout)
    return stdout


def _service_active(service: str) -> str:
    out, _, _ = _run(["systemctl", "is-active", service], timeout=5)
    return out.strip()


def _service_enabled(service: str) -> str:
    out, _, _ = _run(["systemctl", "is-enabled", service], timeout=5)
    return out.strip()


def _system_users(shell_only: bool = False) -> list[str]:
    users = []
    for p in pwd.getpwall():
        if shell_only and p.pw_shell in ("/bin/false", "/usr/sbin/nologin", "/sbin/nologin"):
            continue
        users.append(p.pw_name)
    return users


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
# Dashboard
# ---------------------------------------------------------------------------

@router.get("")
async def get_sysinfo(_: str = Depends(require_super_admin)) -> dict:
    boot_ts = psutil.boot_time()
    cpu_pct = psutil.cpu_percent(interval=0.2)
    cpu_per_core = psutil.cpu_percent(interval=0, percpu=True)
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
    net_per_nic = psutil.net_io_counters(pernic=True)
    uname = platform.uname()

    # Read the real OS distribution from /etc/os-release (freedesktop standard).
    # platform.uname().release is the kernel version, not the distro name.
    try:
        os_release = platform.freedesktop_os_release()
        os_name      = os_release.get("PRETTY_NAME", f"{uname.system} {uname.release}")
        os_id        = os_release.get("ID", "linux").lower()
        os_version   = os_release.get("VERSION_ID", "")
        os_codename  = os_release.get("VERSION_CODENAME", "")
    except (OSError, AttributeError):
        os_name     = f"{uname.system} {uname.release}"
        os_id       = "linux"
        os_version  = ""
        os_codename = ""

    return {
        "hostname": uname.node,
        "os": os_name,           # "Ubuntu 24.04.4 LTS" — human-readable distro name
        "os_id": os_id,          # "ubuntu" — machine-readable ID for logo matching
        "os_version": os_version,    # "24.04"
        "os_codename": os_codename,  # "noble"
        "kernel": uname.release,     # "6.8.0-107-generic" — kernel version
        "kernel_build": uname.version,  # "#107-Ubuntu SMP PREEMPT_DYNAMIC …" — build string
        "arch": uname.machine,
        "python": platform.python_version(),
        "uptime": _uptime_str(boot_ts),
        "boot_time": datetime.fromtimestamp(boot_ts, tz=UTC).isoformat(),
        "cpu": {
            "percent": cpu_pct,
            "per_core": cpu_per_core,
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
            "bytes_sent_mb": round(net.bytes_sent / 1e6, 4),
            "bytes_recv_mb": round(net.bytes_recv / 1e6, 4),
            "packets_sent": net.packets_sent,
            "packets_recv": net.packets_recv,
            "interfaces": list(psutil.net_if_addrs().keys()),
            "per_interface": {
                iface: {
                    "bytes_sent_mb": round(counters.bytes_sent / 1e6, 4),
                    "bytes_recv_mb": round(counters.bytes_recv / 1e6, 4),
                }
                for iface, counters in net_per_nic.items()
            },
        },
        "processes": len(psutil.pids()),
        "checked_at": datetime.now(UTC).isoformat(),
    }


# ---------------------------------------------------------------------------
# Processes
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
    return {"total": len(procs), "processes": procs[:limit], "checked_at": datetime.now(UTC).isoformat()}


class KillRequest(BaseModel):
    signal: int = 15


@router.post("/processes/{pid}/kill")
async def kill_process(pid: int, body: KillRequest, _: str = Depends(require_super_admin)) -> dict:
    if body.signal not in ALLOWED_KILL_SIGNALS:
        raise HTTPException(400, f"Signal must be one of {ALLOWED_KILL_SIGNALS}")
    try:
        proc = psutil.Process(pid)
        proc.send_signal(body.signal)
        return {"ok": True, "pid": pid, "signal": body.signal}
    except psutil.NoSuchProcess:
        raise HTTPException(404, "Process not found")
    except psutil.AccessDenied:
        raise HTTPException(403, "Access denied")


# ---------------------------------------------------------------------------
# Bootup / Systemd services
# ---------------------------------------------------------------------------

@router.get("/bootup")
async def get_bootup(_: str = Depends(require_super_admin)) -> dict:
    import json
    out, _, _ = _run([
        "systemctl", "list-units", "--type=service",
        "--all", "--no-pager", "--no-legend", "--output=json",
    ], timeout=10)
    services = []
    if out:
        try:
            for s in json.loads(out):
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


class ServiceActionRequest(BaseModel):
    service: str
    action: str


@router.post("/bootup/action")
async def service_action(body: ServiceActionRequest, _: str = Depends(require_super_admin)) -> dict:
    if not SERVICE_NAME_RE.match(body.service):
        raise HTTPException(400, "Invalid service name")
    if body.action not in ALLOWED_SERVICE_ACTIONS:
        raise HTTPException(400, f"Action must be one of {ALLOWED_SERVICE_ACTIONS}")
    _, stderr, rc = _run(["sudo", "systemctl", body.action, body.service], timeout=30)
    if rc != 0:
        raise HTTPException(500, stderr.strip() or f"systemctl {body.action} failed")
    return {"ok": True, "service": body.service, "action": body.action}


# ---------------------------------------------------------------------------
# Cron Jobs
# ---------------------------------------------------------------------------

@router.get("/cron")
async def get_cron(_: str = Depends(require_super_admin)) -> dict:
    jobs: list[dict[str, Any]] = []
    system_crontab = Path("/etc/crontab")
    if system_crontab.exists():
        _parse_crontab_file(system_crontab, "system", jobs)
    cron_d = Path("/etc/cron.d")
    if cron_d.is_dir():
        for f in sorted(cron_d.iterdir()):
            if f.is_file() and not f.name.startswith("."):
                _parse_crontab_file(f, f"cron.d/{f.name}", jobs)
    for user in _system_users(shell_only=True):
        out = _run_out(["crontab", "-l", "-u", user], timeout=5)
        for line in out.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(None, 5)
            if len(parts) >= 6:
                jobs.append({"source": f"user:{user}", "schedule": " ".join(parts[:5]), "user": user, "command": parts[5]})
    return {"total": len(jobs), "jobs": jobs, "checked_at": datetime.now(UTC).isoformat()}


class CronAddRequest(BaseModel):
    user: str
    schedule: str
    command: str


@router.post("/cron/entry")
async def add_cron_entry(body: CronAddRequest, _: str = Depends(require_super_admin)) -> dict:
    if not re.match(r"^[a-z_][a-z0-9_-]{0,31}$", body.user):
        raise HTTPException(400, "Invalid username")
    if len(body.schedule) > 100 or len(body.command) > 500:
        raise HTTPException(400, "Schedule or command too long")
    # Read existing crontab
    existing, _, _ = _run(["crontab", "-l", "-u", body.user], timeout=5)
    new_entry = f"{body.schedule} {body.command}\n"
    new_crontab = existing.rstrip("\n") + ("\n" if existing.strip() else "") + new_entry
    proc = subprocess.run(
        ["crontab", "-u", body.user, "-"],
        input=new_crontab, capture_output=True, text=True, timeout=10,
    )
    if proc.returncode != 0:
        raise HTTPException(500, proc.stderr.strip() or "crontab write failed")
    return {"ok": True}


class CronDeleteRequest(BaseModel):
    user: str
    schedule: str
    command: str


@router.delete("/cron/entry")
async def delete_cron_entry(body: CronDeleteRequest, _: str = Depends(require_super_admin)) -> dict:
    if not re.match(r"^[a-z_][a-z0-9_-]{0,31}$", body.user):
        raise HTTPException(400, "Invalid username")
    existing, _, _ = _run(["crontab", "-l", "-u", body.user], timeout=5)
    target = f"{body.schedule} {body.command}"
    new_lines = [l for l in existing.splitlines() if l.strip() != target]
    new_crontab = "\n".join(new_lines) + "\n"
    proc = subprocess.run(
        ["crontab", "-u", body.user, "-"],
        input=new_crontab, capture_output=True, text=True, timeout=10,
    )
    if proc.returncode != 0:
        raise HTTPException(500, proc.stderr.strip() or "crontab write failed")
    return {"ok": True}


# ---------------------------------------------------------------------------
# System Logs
# ---------------------------------------------------------------------------

@router.get("/logs")
async def get_log_files(_: str = Depends(require_super_admin)) -> dict:
    files = []
    for path_str in LOG_FILES:
        p = Path(path_str)
        if p.exists() and p.is_file():
            stat = p.stat()
            files.append({"path": path_str, "size_kb": round(stat.st_size / 1024, 1), "modified": datetime.fromtimestamp(stat.st_mtime, tz=UTC).isoformat()})
    return {"files": files}


@router.get("/logs/tail")
async def tail_log(
    _: str = Depends(require_super_admin),
    path: str = Query(...),
    lines: int = Query(100, ge=10, le=1000),
) -> dict:
    if not path.startswith("/var/log/"):
        return {"error": "Path not allowed", "lines": []}
    try:
        out = _run_out(["tail", f"-n{lines}", path])
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
    out = _run_out(["dpkg-query", "-W", "-f=${Package}\t${Version}\t${Status}\t${Architecture}\n"], timeout=15)
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
    out = _run_out(["apt", "list", "--upgradable", "-q"], timeout=30)
    updates = []
    for line in out.splitlines():
        if "/" not in line or "Listing" in line:
            continue
        m = re.match(r"^(\S+)/\S+\s+(\S+)\s+(\S+)\s+\[upgradable from: (\S+)\]", line)
        if m:
            updates.append({"name": m.group(1), "new_version": m.group(2), "arch": m.group(3), "old_version": m.group(4)})
    return {"total": len(updates), "updates": updates, "checked_at": datetime.now(UTC).isoformat()}


# ---------------------------------------------------------------------------
# OS upgrade — background job tracker
# ---------------------------------------------------------------------------

_UPGRADE_JOB: dict = {
    "id": None,
    "status": "idle",      # idle | running | done | error
    "lines": [],
    "packages_upgraded": 0,
    "started_at": None,
    "finished_at": None,
    "error": "",
}
_UPGRADE_LOCK = threading.Lock()


def _run_upgrade() -> None:
    """Run apt-get update + apt-get upgrade in a background thread."""
    _UPGRADE_JOB["lines"] = []
    _UPGRADE_JOB["packages_upgraded"] = 0
    _UPGRADE_JOB["error"] = ""

    def _emit(line: str) -> None:
        _UPGRADE_JOB["lines"].append(line)
        if len(_UPGRADE_JOB["lines"]) > 500:
            _UPGRADE_JOB["lines"] = _UPGRADE_JOB["lines"][-500:]

    # env_keep in sudoers preserves these through sudo privilege escalation.
    # NEEDRESTART_MODE=a: auto-restart services without prompting.
    # DEBIAN_FRONTEND=noninteractive: suppresses debconf/whiptail TUI dialogs.
    apt_env = {
        **os.environ,
        "DEBIAN_FRONTEND": "noninteractive",
        "APT_LISTCHANGES_FRONTEND": "none",
        "NEEDRESTART_MODE": "a",
    }

    try:
        # Step 1: refresh package lists
        _emit("[apt] Refreshing package lists…")
        proc = subprocess.run(
            ["sudo", "apt-get", "update", "-q"],
            capture_output=True, text=True, env=apt_env, timeout=120,
        )
        for line in (proc.stdout + proc.stderr).splitlines():
            line = line.strip()
            # skip raw terminal escape sequences from whiptail
            if line and not line.startswith("\x1b[") and not line.startswith("[?"):
                _emit(line)

        if proc.returncode != 0:
            _UPGRADE_JOB["status"] = "error"
            _UPGRADE_JOB["error"] = "apt-get update failed (rc={})".format(proc.returncode)
            _UPGRADE_JOB["finished_at"] = datetime.now(UTC).isoformat()
            return

        # Step 2: upgrade all packages.
        # -o Dpkg::Options force-confdef/confold: handle config file conflicts without prompting.
        _emit("[apt] Starting package upgrade…")
        proc2 = subprocess.run(
            [
                "sudo", "apt-get", "upgrade", "-y", "-q",
                "--no-install-recommends",
                "-o", "Dpkg::Options::=--force-confdef",
                "-o", "Dpkg::Options::=--force-confold",
            ],
            capture_output=True, text=True, env=apt_env, timeout=600,
        )
        for line in (proc2.stdout + proc2.stderr).splitlines():
            line = line.strip()
            if line and not line.startswith("\x1b[") and not line.startswith("[?"):
                _emit(line)
            m = re.search(r"(\d+) upgraded", line)
            if m:
                _UPGRADE_JOB["packages_upgraded"] = int(m.group(1))

        _emit(f"[apt] Exit code: {proc2.returncode}")
        if proc2.returncode != 0:
            _UPGRADE_JOB["status"] = "error"
            err = "\n".join(
                l for l in (proc2.stderr or "").splitlines()
                if l.strip() and not l.startswith("\x1b[") and not l.startswith("[?")
            )
            _UPGRADE_JOB["error"] = (err or "apt-get upgrade failed")[-300:]
        else:
            _UPGRADE_JOB["status"] = "done"
            _emit("[apt] Upgrade complete.")

    except Exception as exc:
        _UPGRADE_JOB["status"] = "error"
        _UPGRADE_JOB["error"] = str(exc)[:300]
        _emit(f"[apt] Exception: {exc}")

    _UPGRADE_JOB["finished_at"] = datetime.now(UTC).isoformat()


@router.post("/os/upgrade")
async def start_os_upgrade(_: str = Depends(require_super_admin)) -> dict:
    with _UPGRADE_LOCK:
        if _UPGRADE_JOB["status"] == "running":
            return {"ok": False, "message": "Upgrade already in progress", "job_id": _UPGRADE_JOB["id"]}
        job_id = str(uuid.uuid4())
        _UPGRADE_JOB.update({
            "id": job_id,
            "status": "running",
            "lines": [],
            "packages_upgraded": 0,
            "started_at": datetime.now(UTC).isoformat(),
            "finished_at": None,
            "error": "",
        })
    thread = threading.Thread(target=_run_upgrade, daemon=True)
    thread.start()
    return {"ok": True, "job_id": job_id}


@router.get("/os/upgrade/status")
async def get_upgrade_status(_: str = Depends(require_super_admin)) -> dict:
    return {
        "job_id": _UPGRADE_JOB["id"],
        "status": _UPGRADE_JOB["status"],
        "lines": _UPGRADE_JOB["lines"][-60:],   # last 60 lines
        "packages_upgraded": _UPGRADE_JOB["packages_upgraded"],
        "started_at": _UPGRADE_JOB["started_at"],
        "finished_at": _UPGRADE_JOB["finished_at"],
        "error": _UPGRADE_JOB["error"],
    }


class PackageActionRequest(BaseModel):
    name: str
    action: str  # remove | purge


@router.post("/packages/action")
async def package_action(body: PackageActionRequest, _: str = Depends(require_super_admin)) -> dict:
    if not re.match(r"^[a-z0-9][a-z0-9+\-.]{0,100}$", body.name):
        raise HTTPException(400, "Invalid package name")
    if body.action not in {"remove", "purge"}:
        raise HTTPException(400, "Action must be remove or purge")
    env = {"DEBIAN_FRONTEND": "noninteractive"}
    import os
    full_env = {**os.environ, **env}
    _, stderr, rc = _run(["apt-get", body.action, "-y", "--", body.name], timeout=120)
    if rc != 0:
        raise HTTPException(500, stderr.strip() or "apt-get failed")
    return {"ok": True, "package": body.name, "action": body.action}


# ---------------------------------------------------------------------------
# Users and Groups
# ---------------------------------------------------------------------------

@router.get("/users")
async def get_users(_: str = Depends(require_super_admin)) -> dict:
    users = [
        {
            "username": p.pw_name, "uid": p.pw_uid, "gid": p.pw_gid,
            "gecos": p.pw_gecos, "home": p.pw_dir, "shell": p.pw_shell,
            "login_shell": p.pw_shell not in ("/bin/false", "/usr/sbin/nologin", "/sbin/nologin", ""),
        }
        for p in sorted(pwd.getpwall(), key=lambda x: x.pw_uid)
    ]
    groups = [
        {"name": g.gr_name, "gid": g.gr_gid, "members": list(g.gr_mem)}
        for g in sorted(grp.getgrall(), key=lambda x: x.gr_gid)
    ]
    return {"users": users, "groups": groups, "user_count": len(users), "group_count": len(groups), "checked_at": datetime.now(UTC).isoformat()}


class CreateUserRequest(BaseModel):
    username: str
    password: str
    shell: str = "/bin/bash"
    groups: list[str] = []
    comment: str = ""


@router.post("/users")
async def create_user(body: CreateUserRequest, _: str = Depends(require_super_admin)) -> dict:
    if not re.match(r"^[a-z_][a-z0-9_-]{0,31}$", body.username):
        raise HTTPException(400, "Invalid username")
    if body.shell not in ("/bin/bash", "/bin/sh", "/bin/zsh", "/usr/bin/fish", "/bin/false", "/usr/sbin/nologin"):
        raise HTTPException(400, "Shell not allowed")
    cmd = ["useradd", "-m", "-s", body.shell]
    if body.comment:
        cmd += ["-c", body.comment[:64]]
    if body.groups:
        safe_groups = [g for g in body.groups if re.match(r"^[a-z_][a-z0-9_-]{0,31}$", g)]
        cmd += ["-G", ",".join(safe_groups)]
    cmd.append(body.username)
    _, stderr, rc = _run(cmd, timeout=10)
    if rc != 0:
        raise HTTPException(500, stderr.strip() or "useradd failed")
    # Set password via chpasswd
    proc = subprocess.run(
        ["chpasswd"],
        input=f"{body.username}:{body.password}",
        capture_output=True, text=True, timeout=10,
    )
    if proc.returncode != 0:
        raise HTTPException(500, proc.stderr.strip() or "chpasswd failed")
    return {"ok": True, "username": body.username}


@router.delete("/users/{username}")
async def delete_user(username: str, _: str = Depends(require_super_admin)) -> dict:
    if not re.match(r"^[a-z_][a-z0-9_-]{0,31}$", username):
        raise HTTPException(400, "Invalid username")
    _, stderr, rc = _run(["userdel", "-r", username], timeout=15)
    if rc != 0:
        raise HTTPException(500, stderr.strip() or "userdel failed")
    return {"ok": True, "username": username}


class CreateGroupRequest(BaseModel):
    name: str


@router.post("/groups")
async def create_group(body: CreateGroupRequest, _: str = Depends(require_super_admin)) -> dict:
    if not re.match(r"^[a-z_][a-z0-9_-]{0,31}$", body.name):
        raise HTTPException(400, "Invalid group name")
    _, stderr, rc = _run(["groupadd", body.name], timeout=10)
    if rc != 0:
        raise HTTPException(500, stderr.strip() or "groupadd failed")
    return {"ok": True, "name": body.name}


@router.delete("/groups/{name}")
async def delete_group(name: str, _: str = Depends(require_super_admin)) -> dict:
    if not re.match(r"^[a-z_][a-z0-9_-]{0,31}$", name):
        raise HTTPException(400, "Invalid group name")
    _, stderr, rc = _run(["groupdel", name], timeout=10)
    if rc != 0:
        raise HTTPException(500, stderr.strip() or "groupdel failed")
    return {"ok": True, "name": name}


# ---------------------------------------------------------------------------
# Filesystems
# ---------------------------------------------------------------------------

@router.get("/filesystems")
async def get_filesystems(_: str = Depends(require_super_admin)) -> dict:
    mounts = []
    for part in psutil.disk_partitions(all=True):
        try:
            usage = psutil.disk_usage(part.mountpoint)
            used_gb, total_gb, free_gb, percent = round(usage.used / 1e9, 2), round(usage.total / 1e9, 2), round(usage.free / 1e9, 2), usage.percent
        except (PermissionError, OSError):
            used_gb = total_gb = free_gb = percent = None
        mounts.append({"device": part.device, "mountpoint": part.mountpoint, "fstype": part.fstype, "opts": part.opts, "total_gb": total_gb, "used_gb": used_gb, "free_gb": free_gb, "percent": percent})
    return {"mounts": mounts, "count": len(mounts), "checked_at": datetime.now(UTC).isoformat()}


# ---------------------------------------------------------------------------
# Servers — auto-detection
# ---------------------------------------------------------------------------

def _detect_server(key: str, meta: dict) -> dict | None:
    found = any(shutil.which(b) for b in meta["binaries"])
    if not found:
        # Also check if config path exists
        found = any(Path(p).exists() for p in meta["config_paths"])
    if not found:
        return None
    active = _service_active(meta["service"])
    enabled = _service_enabled(meta["service"])
    return {
        "key": key,
        "label": meta["label"],
        "service": meta["service"],
        "category": meta["category"],
        "active": active,
        "enabled": enabled,
        "running": active == "active",
    }


@router.get("/servers")
async def list_servers(_: str = Depends(require_super_admin)) -> dict:
    detected_keys: set[str] = set()
    servers = []
    for key, meta in KNOWN_SERVERS.items():
        srv = _detect_server(key, meta)
        if not srv:
            continue
        # If MariaDB is present, skip the MySQL entry (MariaDB ships a mysql compat binary)
        if key == "mysql" and "mariadb" in detected_keys:
            continue
        if key == "mariadb" and "mysql" in detected_keys:
            # Replace the mysql entry with mariadb
            servers = [s for s in servers if s["key"] != "mysql"]
        detected_keys.add(key)
        servers.append(srv)
    return {"servers": servers, "count": len(servers), "checked_at": datetime.now(UTC).isoformat()}


@router.get("/servers/{key}")
async def get_server(key: str, _: str = Depends(require_super_admin)) -> dict:
    if key not in KNOWN_SERVERS:
        raise HTTPException(404, "Unknown server")
    meta = KNOWN_SERVERS[key]
    detected = _detect_server(key, meta)
    if not detected:
        raise HTTPException(404, "Server not installed")

    # Read first existing config file (first 200 lines)
    config_content = None
    config_path = None
    for cp in meta["config_paths"]:
        p = Path(cp)
        if p.is_file():
            try:
                lines = p.read_text(errors="replace").splitlines()[:200]
                config_content = "\n".join(lines)
                config_path = cp
            except Exception:
                pass
            break

    # Tail first existing log file — use sudo to handle root-owned log dirs
    log_lines = []
    log_path = None
    for lp in meta["log_paths"]:
        out = _run_out(["sudo", "tail", "-n50", lp])
        if out.strip():
            log_lines = out.splitlines()
            log_path = lp
            break

    return {
        **detected,
        "config_path": config_path,
        "config_content": config_content,
        "log_path": log_path,
        "log_lines": log_lines,
        "checked_at": datetime.now(UTC).isoformat(),
    }


# ---------------------------------------------------------------------------
# Network speed test
# ---------------------------------------------------------------------------

@router.post("/speedtest")
async def run_speedtest(_: str = Depends(require_super_admin)) -> dict:
    """Run a network speed test using the first available CLI tool."""
    import asyncio, json as _json

    async def _run(cmd: list[str]) -> dict | None:
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=90)
            if proc.returncode != 0:
                return None
            data = _json.loads(stdout.decode())
            return data
        except Exception:
            return None

    # --- Ookla official speedtest CLI (bytes/sec bandwidth) ---
    data = await _run(["speedtest", "--accept-gdpr", "--accept-license", "-f", "json"])
    if data and "download" in data and isinstance(data["download"], dict):
        bw_dl = data["download"].get("bandwidth", 0)   # bytes/sec
        bw_ul = data["upload"].get("bandwidth", 0)
        ping  = data.get("ping", {}).get("latency", 0)
        srv   = data.get("server", {})
        return {
            "download_mbps": round(bw_dl * 8 / 1_000_000, 2),
            "upload_mbps":   round(bw_ul * 8 / 1_000_000, 2),
            "ping_ms":       round(ping, 1),
            "server":        f"{srv.get('name', '')}, {srv.get('location', '')}".strip(", "),
            "isp":           data.get("isp", ""),
            "tested_at":     datetime.now(UTC).isoformat(),
        }

    # --- speedtest-cli Python package (bits/sec) ---
    for cmd in [["speedtest-cli", "--json"], ["python3", "-m", "speedtest", "--json"]]:
        data = await _run(cmd)
        if data and "download" in data and isinstance(data["download"], (int, float)):
            srv = data.get("server", {})
            loc = ", ".join(filter(None, [srv.get("name"), srv.get("country")]))
            return {
                "download_mbps": round(data["download"] / 1_000_000, 2),
                "upload_mbps":   round(data["upload"]   / 1_000_000, 2),
                "ping_ms":       round(data.get("ping", 0), 1),
                "server":        loc,
                "isp":           data.get("client", {}).get("isp", ""),
                "tested_at":     datetime.now(UTC).isoformat(),
            }

    raise HTTPException(status_code=503, detail="No speedtest tool found. Install: apt install speedtest-cli")
