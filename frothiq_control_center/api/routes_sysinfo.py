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
    "rails": {
        "label": "Ruby on Rails",
        "service": "puma",
        "binaries": ["ruby"],
        "config_paths": ["/usr/lib/ruby", "/usr/bin/ruby"],
        "log_paths": [],
        "category": "web",
    },
}

# ---------------------------------------------------------------------------
# Per-IP nftables accounting (IPv4 + IPv6)
# ---------------------------------------------------------------------------

_ipacct_ips: set[str]  = set()
_ipacct6_ips: set[str] = set()
_ipacct_lock  = threading.Lock()
_ipacct6_lock = threading.Lock()

# Cache ipacct reads — dashboard polls every 2 s; cap nft reads at 1/10 s to avoid
# generating dozens of kernel netlink calls per minute.
_IPACCT_TTL = 10.0
_ipacct_cache:  dict = {"data": {}, "ts": 0.0}
_ipacct6_cache: dict = {"data": {}, "ts": 0.0}

def _nft(*args: str) -> subprocess.CompletedProcess:
    # Run nft directly — the service unit grants CAP_NET_ADMIN via AmbientCapabilities,
    # so no sudo is needed for nftables operations.
    return subprocess.run(["/usr/sbin/nft"] + list(args), capture_output=True, text=True)

def _parse_nft_counters(table: str, family: str, proto_fields: tuple[str, ...]) -> dict[str, dict[str, int]]:
    """Generic parser for nftables counter rules. Works for both ip and ip6 families."""
    import json as _json
    result = _nft("-j", "list", "table", family, table)
    if result.returncode != 0:
        return {}
    try:
        data = _json.loads(result.stdout)
    except Exception:
        return {}
    totals: dict[str, dict[str, int]] = {}
    for item in data.get("nftables", []):
        rule = item.get("rule")
        if not rule:
            continue
        chain  = rule.get("chain")
        exprs  = rule.get("expr", [])
        ip_val: str | None = None
        bytes_v: int = 0
        for expr in exprs:
            match   = expr.get("match", {})
            payload = match.get("left", {}).get("payload", {})
            if payload.get("protocol") in proto_fields and payload.get("field") in ("daddr", "saddr"):
                ip_val = match.get("right")
            counter = expr.get("counter", {})
            if "bytes" in counter:
                bytes_v = counter["bytes"]
        if ip_val:
            if ip_val not in totals:
                totals[ip_val] = {"bytes_in": 0, "bytes_out": 0}
            if chain == "in":
                totals[ip_val]["bytes_in"] = bytes_v
            elif chain == "out":
                totals[ip_val]["bytes_out"] = bytes_v
    return totals

# --- IPv4 ---

def _setup_ipacct(ips: set[str]) -> None:
    _nft("delete", "table", "ip", "cc_ipacct")
    _nft("add", "table", "ip", "cc_ipacct")
    _nft("add", "chain", "ip", "cc_ipacct", "in",
         "{ type filter hook input priority -10 ; policy accept ; }")
    _nft("add", "chain", "ip", "cc_ipacct", "out",
         "{ type filter hook output priority -10 ; policy accept ; }")
    for ip in sorted(ips):
        _nft("add", "rule", "ip", "cc_ipacct", "in",  "ip", "daddr", ip, "counter")
        _nft("add", "rule", "ip", "cc_ipacct", "out", "ip", "saddr", ip, "counter")

def _get_ipacct(current_ips: set[str]) -> dict[str, dict[str, int]]:
    global _ipacct_ips
    with _ipacct_lock:
        if current_ips != _ipacct_ips:
            _setup_ipacct(current_ips)
            _ipacct_ips = current_ips.copy()
        now = time.monotonic()
        if now - _ipacct_cache["ts"] < _IPACCT_TTL:
            return dict(_ipacct_cache["data"])
        result = _parse_nft_counters("cc_ipacct", "ip", ("ip",))
        _ipacct_cache["data"] = result
        _ipacct_cache["ts"] = now
    return result

# --- IPv6 ---

def _setup_ipacct6(ips: set[str]) -> None:
    _nft("delete", "table", "ip6", "cc_ipacct6")
    _nft("add", "table", "ip6", "cc_ipacct6")
    _nft("add", "chain", "ip6", "cc_ipacct6", "in",
         "{ type filter hook input priority -10 ; policy accept ; }")
    _nft("add", "chain", "ip6", "cc_ipacct6", "out",
         "{ type filter hook output priority -10 ; policy accept ; }")
    for ip in sorted(ips):
        _nft("add", "rule", "ip6", "cc_ipacct6", "in",  "ip6", "daddr", ip, "counter")
        _nft("add", "rule", "ip6", "cc_ipacct6", "out", "ip6", "saddr", ip, "counter")

def _get_ipacct6(current_ips: set[str]) -> dict[str, dict[str, int]]:
    global _ipacct6_ips
    with _ipacct6_lock:
        if current_ips != _ipacct6_ips:
            _setup_ipacct6(current_ips)
            _ipacct6_ips = current_ips.copy()
        now = time.monotonic()
        if now - _ipacct6_cache["ts"] < _IPACCT_TTL:
            return dict(_ipacct6_cache["data"])
        result = _parse_nft_counters("cc_ipacct6", "ip6", ("ip6",))
        _ipacct6_cache["data"] = result
        _ipacct6_cache["ts"] = now
    return result

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
    net_if_addrs = psutil.net_if_addrs()
    # Collect non-loopback IPv4 + global-scope IPv6 addresses for per-IP accounting
    _all_ips: set[str]  = set()
    _all_ip6s: set[str] = set()
    for iface, addrs in net_if_addrs.items():
        if iface == "lo":
            continue
        for a in addrs:
            if a.family == 2:    # AF_INET — IPv4
                _all_ips.add(a.address)
            elif a.family == 10: # AF_INET6 — IPv6, skip link-local (fe80::)
                addr = a.address.split("%")[0]  # strip interface suffix e.g. "fe80::1%eth0"
                if not addr.lower().startswith("fe80"):
                    _all_ip6s.add(addr)
    ip_acct  = _get_ipacct(_all_ips)
    ip6_acct = _get_ipacct6(_all_ip6s)
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
            "interfaces": list(net_if_addrs.keys()),
            "per_interface": {
                iface: {
                    "bytes_sent": counters.bytes_sent,
                    "bytes_recv": counters.bytes_recv,
                    "ip": next(
                        (a.address for a in net_if_addrs.get(iface, []) if a.family == 2),  # AF_INET = 2
                        None,
                    ),
                    "all_ips": [
                        a.address for a in net_if_addrs.get(iface, []) if a.family == 2
                    ],
                    "all_ipv6s": [
                        a.address.split("%")[0] for a in net_if_addrs.get(iface, [])
                        if a.family == 10 and not a.address.lower().startswith("fe80")
                    ],
                }
                for iface, counters in net_per_nic.items()
            },
            "per_ip_bytes":  ip_acct,
            "per_ip6_bytes": ip6_acct,
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


# Classification labels
_CLS_GHOST       = "ghost_record"
_CLS_SUPERSEDED  = "superseded"
_CLS_CRASHED     = "crashed"
_CLS_MISSING_DEP = "missing_dependency"
_CLS_UNKNOWN     = "unknown"


def _classify_failed_unit(unit: str, load_state: str) -> dict:
    """Inspect a failed systemd unit and return classification + recommended fix."""

    # ── Ghost record: unit file no longer exists ───────────────────────────
    if load_state == "not-found":
        return {
            "classification": _CLS_GHOST,
            "reason": "Unit file has been deleted but systemd still holds a failure record for it.",
            "recommended_action": "reset-failed",
            "recommended_label": "Clear record",
            "safe_to_autofix": True,
        }

    # ── Load the unit file for pattern inspection ──────────────────────────
    unit_path_out, _, _ = _run(["systemctl", "show", unit, "--property=FragmentPath"], timeout=5)
    unit_path = ""
    for line in unit_path_out.splitlines():
        if line.startswith("FragmentPath="):
            unit_path = line.split("=", 1)[1].strip()

    unit_content = ""
    if unit_path:
        try:
            unit_content = open(unit_path).read()
        except OSError:
            pass

    # ── fcgiwrap superseded by PHP-FPM ─────────────────────────────────────
    if unit.startswith("fcgiwrap-"):
        # Extract the socket ID from ExecStart to find matching PHP-FPM pool
        import re as _re
        sock_match = _re.search(r"/var/fcgiwrap/(\d+)\.sock", unit_content)
        fpm_running = False
        if sock_match:
            pool_id = sock_match.group(1)
            fpm_out, _, _ = _run(
                ["systemctl", "is-active", f"php8.3-fpm@{pool_id}.service"],
                timeout=5,
            )
            # Also check generic pool activity via ps
            ps_out, _, _ = _run(["pgrep", "-f", f"pool {pool_id}"], timeout=5)
            fpm_running = fpm_out.strip() == "active" or bool(ps_out.strip())

        if fpm_running:
            return {
                "classification": _CLS_SUPERSEDED,
                "reason": "fcgiwrap was replaced by PHP-FPM for this virtual host. "
                          "The PHP-FPM pool is active and serving PHP requests normally.",
                "recommended_action": "disable-and-reset",
                "recommended_label": "Disable & clear",
                "safe_to_autofix": True,
            }
        # fcgiwrap for a non-PHP site (no fpm pool found)
        return {
            "classification": _CLS_SUPERSEDED,
            "reason": "fcgiwrap is not needed — this virtual host does not serve PHP. "
                      "No PHP-FPM pool was found either.",
            "recommended_action": "disable-and-reset",
            "recommended_label": "Disable & clear",
            "safe_to_autofix": True,
        }

    # ── Check journal for dependency / exec errors ─────────────────────────
    journal_out, _, _ = _run(
        ["journalctl", "-u", unit, "-n", "20", "--no-pager", "--output=short"],
        timeout=8,
    )

    if "Dependency failed" in journal_out or "dependency" in journal_out.lower():
        dep_hint = ""
        for line in journal_out.splitlines():
            if "Dependency" in line or "Required" in line:
                dep_hint = line.strip()
                break
        return {
            "classification": _CLS_MISSING_DEP,
            "reason": f"Service failed due to an unmet dependency. Last log: {dep_hint or 'see journal'}",
            "recommended_action": "investigate",
            "recommended_label": "View logs",
            "safe_to_autofix": False,
        }

    # ── Legitimate crashed service ─────────────────────────────────────────
    last_error = ""
    for line in reversed(journal_out.splitlines()):
        if "error" in line.lower() or "failed" in line.lower() or "killed" in line.lower():
            last_error = line.strip()
            break

    return {
        "classification": _CLS_CRASHED,
        "reason": f"Service exited unexpectedly. {('Last error: ' + last_error) if last_error else 'Check journal for details.'}",
        "recommended_action": "restart",
        "recommended_label": "Restart",
        "safe_to_autofix": False,
    }


@router.get("/bootup/failed-analysis")
async def failed_service_analysis(_: str = Depends(require_super_admin)) -> dict:
    """Classify all failed systemd units and return per-service fix recommendations."""
    import json
    out, _, _ = _run([
        "systemctl", "list-units", "--state=failed",
        "--all", "--no-pager", "--no-legend", "--output=json",
    ], timeout=10)

    results = []
    if out:
        try:
            units = json.loads(out)
        except Exception:
            units = []
        for u in units:
            name = u.get("unit", "")
            load = u.get("load", "")
            if not name:
                continue
            classification = _classify_failed_unit(name, load)
            results.append({
                "unit": name,
                "load": load,
                "active": u.get("active", ""),
                "sub": u.get("sub", ""),
                "description": u.get("description", ""),
                **classification,
            })

    return {
        "failed": results,
        "count": len(results),
        "analyzed_at": datetime.now(UTC).isoformat(),
    }


class FailedFixRequest(BaseModel):
    service: str
    action: str  # "reset-failed" | "disable-and-reset"


@router.post("/bootup/failed-analysis/fix")
async def fix_failed_service(body: FailedFixRequest, _: str = Depends(require_super_admin)) -> dict:
    """Apply the recommended fix for a classified failed service."""
    if not SERVICE_NAME_RE.match(body.service):
        raise HTTPException(400, "Invalid service name")
    if body.action not in {"reset-failed", "disable-and-reset"}:
        raise HTTPException(400, "action must be reset-failed or disable-and-reset")

    if body.action == "disable-and-reset":
        _, err, rc = _run(["sudo", "systemctl", "disable", body.service], timeout=15)
        if rc != 0:
            # disable may fail if unit is not-found — proceed to reset anyway
            pass
        _, err2, rc2 = _run(["sudo", "systemctl", "reset-failed", body.service], timeout=10)
        if rc2 != 0:
            raise HTTPException(500, err2.strip() or "reset-failed failed")
    else:
        _, err, rc = _run(["sudo", "systemctl", "reset-failed", body.service], timeout=10)
        if rc != 0:
            raise HTTPException(500, err.strip() or "reset-failed failed")

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


# ---------------------------------------------------------------------------
# Critical services — watchdog + post-upgrade recovery
# ---------------------------------------------------------------------------

# Services that must always be running; the watchdog will restart them if stopped.
CRITICAL_SERVICES = [
    "ssh",
    "apache2",
    "frothiq-nft",
    "frothiq-lfd",
    "frothiq-core",
    "frothiq-control-center",
    "frothiq-ui",
    "frothiq-gateway",
]

_WATCHDOG_LOG: list[dict] = []
_WATCHDOG_LOCK = threading.Lock()


def _service_is_active(name: str) -> bool:
    r = subprocess.run(
        ["sudo", "systemctl", "is-active", name],
        capture_output=True, text=True, timeout=5,
    )
    return r.stdout.strip() == "active"


def _restart_service(name: str) -> tuple[bool, str]:
    r = subprocess.run(
        ["sudo", "systemctl", "start", name],
        capture_output=True, text=True, timeout=30,
    )
    ok = r.returncode == 0
    msg = (r.stdout + r.stderr).strip()
    return ok, msg


def _watchdog_tick() -> None:
    recovered = []
    failed = []
    for svc in CRITICAL_SERVICES:
        try:
            if not _service_is_active(svc):
                ok, msg = _restart_service(svc)
                entry = {
                    "service": svc,
                    "action": "start",
                    "success": ok,
                    "message": msg,
                    "ts": datetime.now(UTC).isoformat(),
                }
                if ok:
                    recovered.append(entry)
                else:
                    entry["message"] = msg or "start command failed"
                    failed.append(entry)
        except Exception as exc:
            failed.append({"service": svc, "action": "start", "success": False,
                           "message": str(exc), "ts": datetime.now(UTC).isoformat()})

    if recovered or failed:
        with _WATCHDOG_LOCK:
            _WATCHDOG_LOG.extend(recovered + failed)
            if len(_WATCHDOG_LOG) > 200:
                del _WATCHDOG_LOG[:-200]


def _watchdog_loop() -> None:
    while True:
        time.sleep(60)
        try:
            _watchdog_tick()
        except Exception:
            pass


# Start the watchdog background thread once at import time.
threading.Thread(target=_watchdog_loop, daemon=True, name="service-watchdog").start()


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
        # Step 1: finish any previously interrupted dpkg operations.
        _emit("[apt] Checking for interrupted package operations…")
        proc0 = subprocess.run(
            ["sudo", "dpkg", "--configure", "-a"],
            capture_output=True, text=True, env=apt_env, timeout=120,
        )
        for line in (proc0.stdout + proc0.stderr).splitlines():
            line = line.strip()
            if line and not line.startswith("\x1b[") and not line.startswith("[?"):
                _emit(line)

        # Step 2: fix any broken dependency state before upgrading.
        _emit("[apt] Fixing broken dependencies…")
        proc_fix = subprocess.run(
            ["sudo", "apt-get", "install", "-f", "-y", "-q",
             "-o", "Dpkg::Options::=--force-confdef",
             "-o", "Dpkg::Options::=--force-confold"],
            capture_output=True, text=True, env=apt_env, timeout=180,
        )
        for line in (proc_fix.stdout + proc_fix.stderr).splitlines():
            line = line.strip()
            if line and not line.startswith("\x1b[") and not line.startswith("[?"):
                _emit(line)
        if proc_fix.returncode != 0:
            _UPGRADE_JOB["status"] = "error"
            _UPGRADE_JOB["error"] = "apt-get -f install failed (rc={})".format(proc_fix.returncode)
            _UPGRADE_JOB["finished_at"] = datetime.now(UTC).isoformat()
            return

        # Step 3: refresh package lists.
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

        # Step 4: upgrade all packages.
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

    finally:
        # Always run watchdog after an upgrade — packages being stopped mid-install
        # is the most common cause of critical services going down.
        _emit("[apt] Checking critical services after upgrade…")
        try:
            _watchdog_tick()
            with _WATCHDOG_LOCK:
                recent = [e for e in _WATCHDOG_LOG if e.get("action") == "start"][-10:]
            for entry in recent:
                status = "restarted" if entry["success"] else "FAILED to restart"
                _emit(f"[watchdog] {entry['service']}: {status}")
        except Exception as exc:
            _emit(f"[watchdog] Error during post-upgrade check: {exc}")

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


@router.get("/watchdog")
async def get_watchdog_status(_: str = Depends(require_super_admin)) -> dict:
    """Return current health of all critical services + recent recovery events."""
    statuses = {}
    for svc in CRITICAL_SERVICES:
        try:
            statuses[svc] = _service_is_active(svc)
        except Exception:
            statuses[svc] = False
    with _WATCHDOG_LOCK:
        log = list(_WATCHDOG_LOG[-50:])
    return {
        "services": statuses,
        "all_healthy": all(statuses.values()),
        "recovery_log": log,
        "checked_at": datetime.now(UTC).isoformat(),
    }


@router.post("/watchdog/run")
async def run_watchdog_now(_: str = Depends(require_super_admin)) -> dict:
    """Trigger an immediate watchdog check and return results."""
    before = {svc: _service_is_active(svc) for svc in CRITICAL_SERVICES}
    _watchdog_tick()
    after = {svc: _service_is_active(svc) for svc in CRITICAL_SERVICES}
    with _WATCHDOG_LOCK:
        log = list(_WATCHDOG_LOG[-20:])
    return {
        "before": before,
        "after": after,
        "recovery_log": log,
        "checked_at": datetime.now(UTC).isoformat(),
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
    import asyncio, json as _json, shutil

    async def _run(cmd: list[str], timeout: int = 60) -> dict | None:
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            if proc.returncode != 0:
                return None
            return _json.loads(stdout.decode())
        except Exception:
            return None

    def _is_valid(dl: float, ul: float, ping: float) -> bool:
        # speedtest-cli returns ping=1800000 and speeds=0 when test servers are unreachable
        return ping < 10_000 and (dl > 0 or ul > 0)

    # --- Ookla official speedtest CLI (bytes/sec bandwidth) ---
    # Only attempt if it's actually the Ookla binary (not Python speedtest-cli)
    ookla_path = shutil.which("speedtest")
    if ookla_path:
        ver_proc = await _run([ookla_path, "--version"], timeout=5)
        # Ookla binary returns structured JSON for --version; Python speedtest-cli returns None (non-JSON stdout)
        ookla_available = ver_proc is not None
    else:
        ookla_available = False

    if ookla_available:
        data = await _run([ookla_path, "--accept-gdpr", "--accept-license", "-f", "json"])
        if data and "download" in data and isinstance(data["download"], dict):
            bw_dl = data["download"].get("bandwidth", 0)   # bytes/sec
            bw_ul = data["upload"].get("bandwidth", 0)
            ping  = data.get("ping", {}).get("latency", 0)
            dl_mbps = round(bw_dl * 8 / 1_000_000, 2)
            ul_mbps = round(bw_ul * 8 / 1_000_000, 2)
            if _is_valid(dl_mbps, ul_mbps, ping):
                srv = data.get("server", {})
                return {
                    "download_mbps": dl_mbps,
                    "upload_mbps":   ul_mbps,
                    "ping_ms":       round(ping, 1),
                    "server":        f"{srv.get('name', '')}, {srv.get('location', '')}".strip(", "),
                    "isp":           data.get("isp", ""),
                    "tested_at":     datetime.now(UTC).isoformat(),
                }

    # --- speedtest-cli Python package (bits/sec) ---
    # speedtest-cli exits 0 even on HTTP errors (403, network failures), returning
    # error text to stdout instead of JSON. We must distinguish:
    #   - tool not found (shutil.which returns None)
    #   - speedtest.net blocked/rate-limited (HTTP 4xx in stdout)
    #   - server unresponsive (ping=1800000, speeds=0)
    #   - success

    _BLOCK_PATTERNS = ("403", "Forbidden", "Cannot retrieve", "Unable to connect", "ERROR")

    async def _run_raw(cmd: list[str], timeout: int = 60) -> tuple[int, str, str]:
        """Run command and return (returncode, stdout, stderr)."""
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            return proc.returncode, stdout.decode(), stderr.decode()
        except Exception as exc:
            return -1, "", str(exc)

    async def _get_nearest_server_id(binary: str) -> tuple[str | None, str | None]:
        """Return (server_id, error_detail). error_detail is set when blocked."""
        import re as _re
        rc, stdout, _ = await _run_raw([binary, "--list"], timeout=20)
        combined = stdout
        for pat in _BLOCK_PATTERNS:
            if pat in combined:
                return None, f"speedtest.net refused the connection ({combined.strip().splitlines()[-1]}). This is usually temporary rate-limiting — try again in a few minutes."
        for line in combined.splitlines():
            m = _re.match(r"^\s*(\d+)\)", line)
            if m:
                return m.group(1), None
        return None, None   # no servers found but no explicit error

    # Check tool is installed before attempting
    cli_binary = shutil.which("speedtest-cli")
    if not cli_binary:
        raise HTTPException(status_code=503, detail="speedtest-cli is not installed. Run: apt install speedtest-cli")

    server_id, block_error = await _get_nearest_server_id(cli_binary)
    if block_error:
        raise HTTPException(status_code=503, detail=block_error)

    cmd = [cli_binary, "--json"]
    if server_id:
        cmd += ["--server", server_id]
    rc, stdout, stderr = await _run_raw(cmd, timeout=90)

    # Check for blocking errors in the test output too
    for pat in _BLOCK_PATTERNS:
        if pat in stdout or pat in stderr:
            raise HTTPException(
                status_code=503,
                detail=f"speedtest.net blocked the test. This is usually temporary — try again in a few minutes.",
            )

    try:
        data = _json.loads(stdout)
    except Exception:
        raw = (stdout + stderr).strip().splitlines()
        last = raw[-1] if raw else "no output"
        raise HTTPException(status_code=503, detail=f"Speed test returned unexpected output: {last}")

    if "download" in data and isinstance(data["download"], (int, float)):
        dl_mbps = round(data["download"] / 1_000_000, 2)
        ul_mbps = round(data["upload"]   / 1_000_000, 2)
        ping    = data.get("ping", 0)
        if not _is_valid(dl_mbps, ul_mbps, ping):
            raise HTTPException(
                status_code=503,
                detail="Speed test completed but returned invalid measurements (ping>10s or zero speeds). Try again.",
            )
        srv = data.get("server", {})
        loc = ", ".join(filter(None, [srv.get("name"), srv.get("country")]))
        return {
            "download_mbps": dl_mbps,
            "upload_mbps":   ul_mbps,
            "ping_ms":       round(ping, 1),
            "server":        loc,
            "isp":           data.get("client", {}).get("isp", ""),
            "tested_at":     datetime.now(UTC).isoformat(),
        }


# ---------------------------------------------------------------------------
# Network Configuration
# ---------------------------------------------------------------------------

@router.get("/network-config")
async def get_network_config(_: str = Depends(require_super_admin)) -> dict:
    import socket
    import struct

    af_inet  = 2   # AF_INET  (IPv4)
    af_inet6 = 10  # AF_INET6 (IPv6)
    af_link  = 17  # AF_PACKET (MAC address on Linux)

    net_if_addrs  = psutil.net_if_addrs()
    net_if_stats  = psutil.net_if_stats()
    net_io        = psutil.net_io_counters(pernic=True)

    interfaces = []
    for iface, addrs in net_if_addrs.items():
        stats   = net_if_stats.get(iface)
        io      = net_io.get(iface)
        ipv4    = [a for a in addrs if a.family == af_inet]
        ipv6    = [a for a in addrs if a.family == af_inet6]
        mac_rec = next((a for a in addrs if a.family == af_link), None)

        def _cidr(netmask: str | None) -> str | None:
            if not netmask:
                return None
            try:
                return str(sum(bin(int(o)).count("1") for o in netmask.split(".")))
            except Exception:
                return None

        interfaces.append({
            "name":       iface,
            "is_up":      stats.isup if stats else False,
            "speed_mbps": stats.speed if stats else 0,
            "mtu":        stats.mtu if stats else 0,
            "mac":        mac_rec.address if mac_rec else None,
            "ipv4": [
                {
                    "address": a.address,
                    "netmask": a.netmask,
                    "cidr":    _cidr(a.netmask),
                    "broadcast": a.broadcast,
                }
                for a in ipv4
            ],
            "ipv6": [
                {
                    "address": a.address.split("%")[0],
                    "netmask": a.netmask,
                }
                for a in ipv6
                if not a.address.lower().startswith("fe80")
            ],
            "io": {
                "bytes_sent": io.bytes_sent if io else 0,
                "bytes_recv": io.bytes_recv if io else 0,
                "packets_sent": io.packets_sent if io else 0,
                "packets_recv": io.packets_recv if io else 0,
                "errin": io.errin if io else 0,
                "errout": io.errout if io else 0,
                "dropin": io.dropin if io else 0,
                "dropout": io.dropout if io else 0,
            } if io else None,
        })

    # DNS servers from /etc/resolv.conf
    dns_servers: list[str] = []
    dns_search: list[str] = []
    try:
        with open("/etc/resolv.conf") as f:
            for line in f:
                line = line.strip()
                if line.startswith("nameserver"):
                    parts = line.split()
                    if len(parts) >= 2:
                        dns_servers.append(parts[1])
                elif line.startswith("search") or line.startswith("domain"):
                    dns_search.extend(line.split()[1:])
    except OSError:
        pass

    # Routing table via `ip route show`
    routes: list[dict] = []
    try:
        out = _run_out(["ip", "route", "show"])
        for line in out.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split()
            route: dict[str, str | None] = {
                "destination": parts[0] if parts else None,
                "gateway": None,
                "interface": None,
                "metric": None,
                "proto": None,
                "scope": None,
            }
            i = 1
            while i < len(parts):
                if parts[i] == "via" and i + 1 < len(parts):
                    route["gateway"] = parts[i + 1]; i += 2
                elif parts[i] == "dev" and i + 1 < len(parts):
                    route["interface"] = parts[i + 1]; i += 2
                elif parts[i] == "metric" and i + 1 < len(parts):
                    route["metric"] = parts[i + 1]; i += 2
                elif parts[i] == "proto" and i + 1 < len(parts):
                    route["proto"] = parts[i + 1]; i += 2
                elif parts[i] == "scope" and i + 1 < len(parts):
                    route["scope"] = parts[i + 1]; i += 2
                else:
                    i += 1
            routes.append(route)
    except Exception:
        pass

    # Default gateway
    default_gateway: str | None = next(
        (r["gateway"] for r in routes if r.get("destination") in ("default", "0.0.0.0/0") and r.get("gateway")),
        None,
    )

    # Firewall state — FrothIQ-nft preferred; fall back to ufw then nftables
    # CSF/LFD is intentionally excluded: it was decommissioned when FrothIQ took over.
    firewall: dict = {"tool": "unknown", "state": "unknown", "rules": []}

    frothiq_nft_out, _, frothiq_nft_rc = _run(["systemctl", "is-active", "frothiq-nft"])
    frothiq_nft_state = frothiq_nft_out.strip() if frothiq_nft_rc == 0 else "inactive"

    if frothiq_nft_state in ("active", "activating") or frothiq_nft_rc == 0:
        # --- FrothIQ nft firewall detected ---
        frothiq_lfd_out, _, frothiq_lfd_rc = _run(["systemctl", "is-active", "frothiq-lfd"])
        frothiq_lfd_state = frothiq_lfd_out.strip() if frothiq_lfd_rc == 0 else "inactive"

        # Count blacklisted IPs from the live nft set
        def _count_nft_set(set_name: str) -> int:
            try:
                import re as _re
                out, _, rc = _run(["nft", "list", "set", "inet", "frothiq", set_name])
                if rc != 0:
                    return 0
                m = _re.search(r"elements\s*=\s*\{([^}]+)\}", out, _re.DOTALL)
                if not m:
                    return 0
                return sum(1 for t in _re.split(r",", m.group(1)) if t.strip().split()[0:1] and _re.match(r"^[\d./a-fA-F:]+$", t.strip().split()[0]))
            except Exception:
                return 0

        blacklist_count = _count_nft_set("blacklist")
        temp_ban_count  = _count_nft_set("temp_ban")

        overall_state = "active" if frothiq_nft_state == "active" else "inactive"

        firewall = {
            "tool":               "frothiq",
            "state":              overall_state,
            "frothiq_nft_state":  frothiq_nft_state,
            "frothiq_lfd_state":  frothiq_lfd_state,
            "blacklist_count":    blacklist_count,
            "temp_ban_count":     temp_ban_count,
            "rules":              [],
        }
    else:
        ufw_out, _, ufw_rc = _run(["ufw", "status", "verbose"])
        if ufw_rc == 0:
            lines = ufw_out.splitlines()
            state_line = next((l for l in lines if l.lower().startswith("status:")), "")
            firewall = {
                "tool": "ufw",
                "state": state_line.replace("Status:", "").strip() if state_line else "unknown",
                "rules": [l for l in lines if l and not l.startswith("Status") and not l.startswith("Logging") and not l.startswith("Default") and not l.startswith("New profiles") and l.strip()],
            }
        else:
            nft_out, _, nft_rc = _run(["nft", "list", "ruleset"])
            if nft_rc == 0:
                firewall = {
                    "tool": "nftables",
                    "state": "active",
                    "rules": nft_out.splitlines()[:40],
                }

    # Open listening ports via ss
    ports: list[dict] = []
    try:
        ss_out = _run_out(["ss", "-tlnp"])
        for line in ss_out.splitlines()[1:]:
            parts = line.split()
            if len(parts) < 5:
                continue
            local = parts[3]
            process = parts[6] if len(parts) > 6 else ""
            addr, _, port = local.rpartition(":")
            ports.append({"local_address": addr or "*", "port": port, "process": process})
    except Exception:
        pass

    # DNS resolution check
    dns_ok = False
    try:
        socket.getaddrinfo("google.com", 80, proto=socket.IPPROTO_TCP)
        dns_ok = True
    except Exception:
        pass

    # Connectivity checks: ping 8.8.8.8 (external) and default gateway (internal)
    def _ping(host: str) -> dict:
        out, _, rc = _run(["ping", "-c", "3", "-W", "2", host])
        if rc == 0:
            rtt = None
            for l in out.splitlines():
                if "rtt" in l or "round-trip" in l:
                    parts = l.split("=")
                    if len(parts) > 1:
                        rtt = parts[1].strip().split("/")[1] + " ms" if "/" in parts[1] else parts[1].strip()
            return {"host": host, "reachable": True, "rtt_avg": rtt}
        return {"host": host, "reachable": False, "rtt_avg": None}

    ping_external = _ping("8.8.8.8")
    ping_gateway  = _ping(default_gateway) if default_gateway else {"host": default_gateway, "reachable": None, "rtt_avg": None}

    return {
        "interfaces":       interfaces,
        "dns_servers":      dns_servers,
        "dns_search":       dns_search,
        "dns_resolves":     dns_ok,
        "routes":           routes,
        "default_gateway":  default_gateway,
        "firewall":         firewall,
        "open_ports":       ports,
        "connectivity": {
            "external": ping_external,
            "gateway":  ping_gateway,
        },
        "checked_at": datetime.now(UTC).isoformat(),
    }


# ---------------------------------------------------------------------------
# Hardware Info
# ---------------------------------------------------------------------------

@router.get("/hardware")
async def get_hardware(_: str = Depends(require_super_admin)) -> dict:
    uname = platform.uname()

    # CPU
    cpu_freq = psutil.cpu_freq()
    cpu_info: dict = {
        "logical_cores":  psutil.cpu_count(logical=True),
        "physical_cores": psutil.cpu_count(logical=False),
        "percent":        psutil.cpu_percent(interval=0.3),
        "per_core":       psutil.cpu_percent(interval=0, percpu=True),
        "freq_mhz":       round(cpu_freq.current, 1) if cpu_freq else None,
        "freq_max_mhz":   round(cpu_freq.max, 1) if cpu_freq else None,
        "model":          None,
        "arch":           uname.machine,
        "load_avg_1m":    round(psutil.getloadavg()[0], 2),
        "load_avg_5m":    round(psutil.getloadavg()[1], 2),
        "load_avg_15m":   round(psutil.getloadavg()[2], 2),
    }
    try:
        with open("/proc/cpuinfo") as f:
            for line in f:
                if line.startswith("model name"):
                    cpu_info["model"] = line.split(":", 1)[1].strip()
                    break
    except OSError:
        pass

    # Memory
    mem  = psutil.virtual_memory()
    swap = psutil.swap_memory()
    memory = {
        "total_gb":     round(mem.total / 1e9, 2),
        "used_gb":      round(mem.used / 1e9, 2),
        "available_gb": round(mem.available / 1e9, 2),
        "cached_gb":    round(getattr(mem, "cached", 0) / 1e9, 2),
        "buffers_gb":   round(getattr(mem, "buffers", 0) / 1e9, 2),
        "percent":      mem.percent,
        "swap_total_gb": round(swap.total / 1e9, 2),
        "swap_used_gb":  round(swap.used / 1e9, 2),
        "swap_percent":  swap.percent,
    }

    # Disks
    disks = []
    for part in psutil.disk_partitions(all=False):
        try:
            usage = psutil.disk_usage(part.mountpoint)
        except PermissionError:
            continue
        disks.append({
            "device":     part.device,
            "mountpoint": part.mountpoint,
            "fstype":     part.fstype,
            "opts":       part.opts,
            "total_gb":   round(usage.total / 1e9, 2),
            "used_gb":    round(usage.used / 1e9, 2),
            "free_gb":    round(usage.free / 1e9, 2),
            "percent":    usage.percent,
        })

    # Block devices (lsblk)
    block_devices: list[dict] = []
    try:
        out = _run_out(["lsblk", "-J", "-o", "NAME,SIZE,TYPE,MODEL,ROTA,TRAN"])
        import json as _json
        lsblk = _json.loads(out)
        block_devices = lsblk.get("blockdevices", [])
    except Exception:
        pass

    # Temperature sensors
    temps: dict = {}
    try:
        raw = psutil.sensors_temperatures()
        for name, entries in raw.items():
            temps[name] = [
                {"label": e.label or name, "current": e.current, "high": e.high, "critical": e.critical}
                for e in entries
            ]
    except (AttributeError, Exception):
        pass

    # GPU (nvidia-smi if available)
    gpu: list[dict] = []
    try:
        out = _run_out(["nvidia-smi", "--query-gpu=name,memory.total,memory.used,utilization.gpu,temperature.gpu",
                        "--format=csv,noheader,nounits"])
        for line in out.strip().splitlines():
            parts = [p.strip() for p in line.split(",")]
            if len(parts) >= 5:
                gpu.append({
                    "name":         parts[0],
                    "memory_total": parts[1] + " MiB",
                    "memory_used":  parts[2] + " MiB",
                    "utilization":  parts[3] + "%",
                    "temperature":  parts[4] + "°C",
                })
    except Exception:
        pass

    # System / OS info
    try:
        os_release = platform.freedesktop_os_release()
        os_pretty = os_release.get("PRETTY_NAME", f"{uname.system} {uname.release}")
    except (OSError, AttributeError):
        os_pretty = f"{uname.system} {uname.release}"

    # DMI / hardware info (dmidecode — requires root; graceful fallback)
    dmi: dict = {}
    try:
        for dmi_type, key in [("system", "system"), ("baseboard", "baseboard"), ("bios", "bios")]:
            out, _, rc = _run(["dmidecode", "-t", dmi_type])
            if rc == 0:
                entry: dict = {}
                for line in out.splitlines():
                    if ":" in line:
                        k, _, v = line.partition(":")
                        k = k.strip(); v = v.strip()
                        if k and v and v not in ("Not Specified", "Not Present", "To Be Filled By O.E.M."):
                            entry[k] = v
                dmi[key] = entry
    except Exception:
        pass

    boot_ts = psutil.boot_time()

    return {
        "cpu":     cpu_info,
        "memory":  memory,
        "disks":   disks,
        "block_devices": block_devices,
        "temperatures": temps,
        "gpu":     gpu,
        "dmi":     dmi,
        "system": {
            "hostname": uname.node,
            "os":       os_pretty,
            "kernel":   uname.release,
            "arch":     uname.machine,
            "uptime":   _uptime_str(boot_ts),
            "boot_time": datetime.fromtimestamp(boot_ts, tz=UTC).isoformat(),
            "processes": len(psutil.pids()),
            "python":   platform.python_version(),
        },
        "checked_at": datetime.now(UTC).isoformat(),
    }


# ---------------------------------------------------------------------------
# Audit logger
# ---------------------------------------------------------------------------

import logging as _logging

_audit_log = _logging.getLogger("mc3.audit")
if not _audit_log.handlers:
    try:
        _h = _logging.FileHandler("/var/log/mc3-audit.log", delay=True)
        _h.setFormatter(_logging.Formatter("%(asctime)s  %(message)s"))
        _audit_log.addHandler(_h)
    except OSError:
        pass
    _audit_log.addHandler(_logging.StreamHandler())
    _audit_log.setLevel(_logging.INFO)


def _audit(user: str, action: str, detail: str, result: str) -> None:
    _audit_log.info("user=%s action=%s detail=%r result=%s", user, action, detail, result)


# ---------------------------------------------------------------------------
# Allowed network interfaces (validated against psutil at call time)
# ---------------------------------------------------------------------------

def _validate_iface(name: str) -> None:
    allowed = set(psutil.net_if_addrs().keys())
    if name not in allowed:
        raise HTTPException(status_code=400, detail=f"Unknown interface: {name!r}")


def _validate_ip(addr: str) -> None:
    import ipaddress
    try:
        ipaddress.ip_address(addr)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid IP address: {addr!r}")


def _validate_prefix(prefix: int) -> None:
    if not (0 <= prefix <= 128):
        raise HTTPException(status_code=400, detail=f"Invalid prefix length: {prefix}")


# ---------------------------------------------------------------------------
# Network: Interface link up/down
# ---------------------------------------------------------------------------

class IfaceLinkRequest(BaseModel):
    action: str  # "up" | "down"


@router.post("/network/interface/{name}/link")
async def iface_link(name: str, body: IfaceLinkRequest, user: str = Depends(require_super_admin)) -> dict:
    if body.action not in ("up", "down"):
        raise HTTPException(status_code=400, detail="action must be 'up' or 'down'")
    _validate_iface(name)
    out, err, rc = _run(["ip", "link", "set", name, body.action])
    result = "ok" if rc == 0 else "error"
    _audit(user, f"iface_link_{body.action}", name, result)
    if rc != 0:
        raise HTTPException(status_code=500, detail=err.strip() or f"ip link set {name} {body.action} failed")
    # Verify new state
    stats = psutil.net_if_stats().get(name)
    return {
        "ok": True,
        "interface": name,
        "action": body.action,
        "is_up": stats.isup if stats else None,
        "executed_at": datetime.now(UTC).isoformat(),
    }


# ---------------------------------------------------------------------------
# Network: IP configuration (static or DHCP)
# ---------------------------------------------------------------------------

class IfaceIPRequest(BaseModel):
    mode: str           # "static" | "dhcp"
    address: str = ""   # required for static
    prefix: int = 24    # CIDR prefix length
    gateway: str = ""   # optional for static


@router.post("/network/interface/{name}/ip")
async def iface_ip(name: str, body: IfaceIPRequest, user: str = Depends(require_super_admin)) -> dict:
    if body.mode not in ("static", "dhcp"):
        raise HTTPException(status_code=400, detail="mode must be 'static' or 'dhcp'")
    _validate_iface(name)

    if body.mode == "static":
        if not body.address:
            raise HTTPException(status_code=400, detail="address is required for static mode")
        _validate_ip(body.address)
        _validate_prefix(body.prefix)
        if body.gateway:
            _validate_ip(body.gateway)

        # Flush existing IPv4 addresses, assign new one
        _run(["ip", "addr", "flush", "dev", name])
        out, err, rc = _run(["ip", "addr", "add", f"{body.address}/{body.prefix}", "dev", name])
        if rc != 0:
            _audit(user, "iface_ip_static", f"{name} {body.address}/{body.prefix}", "error")
            raise HTTPException(status_code=500, detail=err.strip() or "ip addr add failed")

        if body.gateway:
            _run(["ip", "route", "replace", "default", "via", body.gateway, "dev", name])

        detail = f"{name} {body.address}/{body.prefix} gw={body.gateway or 'unchanged'}"
        _audit(user, "iface_ip_static", detail, "ok")
        return {"ok": True, "interface": name, "mode": "static", "address": body.address,
                "prefix": body.prefix, "gateway": body.gateway or None,
                "executed_at": datetime.now(UTC).isoformat()}

    else:  # dhcp
        # Release existing static config and request DHCP lease via dhclient
        _run(["ip", "addr", "flush", "dev", name])
        out, err, rc = _run(["dhclient", "-v", name], timeout=20)
        if rc != 0:
            # Try dhcpcd as fallback
            out2, err2, rc2 = _run(["dhcpcd", name], timeout=20)
            if rc2 != 0:
                _audit(user, "iface_ip_dhcp", name, "error")
                raise HTTPException(status_code=500, detail="dhclient and dhcpcd both failed — no DHCP client available")
        _audit(user, "iface_ip_dhcp", name, "ok")
        return {"ok": True, "interface": name, "mode": "dhcp",
                "executed_at": datetime.now(UTC).isoformat()}


# ---------------------------------------------------------------------------
# Network: DNS configuration
# ---------------------------------------------------------------------------

class DNSRequest(BaseModel):
    servers: list[str]  # list of IP address strings


@router.put("/network/dns")
async def update_dns(body: DNSRequest, user: str = Depends(require_super_admin)) -> dict:
    if not body.servers:
        raise HTTPException(status_code=400, detail="At least one DNS server required")
    if len(body.servers) > 4:
        raise HTTPException(status_code=400, detail="Maximum 4 DNS servers allowed")
    for s in body.servers:
        _validate_ip(s)

    resolv = Path("/etc/resolv.conf")

    # Backup original
    backup_path = Path(f"/etc/resolv.conf.mc3bak.{int(time.time())}")
    try:
        if resolv.exists():
            import shutil as _shutil
            _shutil.copy2(str(resolv), str(backup_path))
    except OSError as e:
        raise HTTPException(status_code=500, detail=f"Could not create backup: {e}")

    # Preserve existing search/domain lines, replace nameserver lines
    existing_lines: list[str] = []
    try:
        with open(resolv) as f:
            existing_lines = f.readlines()
    except OSError:
        pass

    non_ns_lines = [l for l in existing_lines if not l.startswith("nameserver")]
    new_lines = non_ns_lines + [f"nameserver {s}\n" for s in body.servers]

    try:
        with open(resolv, "w") as f:
            f.writelines(new_lines)
    except OSError as e:
        _audit(user, "update_dns", str(body.servers), "error")
        raise HTTPException(status_code=500, detail=f"Could not write /etc/resolv.conf: {e}")

    _audit(user, "update_dns", f"servers={body.servers}", "ok")
    return {
        "ok": True,
        "servers": body.servers,
        "backup": str(backup_path),
        "executed_at": datetime.now(UTC).isoformat(),
    }


# ---------------------------------------------------------------------------
# Network: Restart networking
# ---------------------------------------------------------------------------

@router.post("/network/restart")
async def restart_networking(user: str = Depends(require_super_admin)) -> dict:
    # Try systemd-networkd first, then networking, then NetworkManager
    for service in ("systemd-networkd", "networking", "NetworkManager"):
        _, _, rc = _run(["systemctl", "is-active", service])
        if rc == 0:
            out, err, rc2 = _run(["systemctl", "restart", service], timeout=30)
            result = "ok" if rc2 == 0 else "error"
            _audit(user, "restart_networking", service, result)
            if rc2 != 0:
                raise HTTPException(status_code=500, detail=err.strip() or f"systemctl restart {service} failed")
            return {"ok": True, "service": service, "executed_at": datetime.now(UTC).isoformat()}

    _audit(user, "restart_networking", "none_found", "error")
    raise HTTPException(status_code=404, detail="No active network service found (systemd-networkd / networking / NetworkManager)")


# ---------------------------------------------------------------------------
# Disk: Mount / Unmount
# ---------------------------------------------------------------------------

# Allowed filesystem types for mounting
_ALLOWED_FSTYPES = {
    "ext2", "ext3", "ext4", "xfs", "btrfs", "vfat", "exfat",
    "ntfs", "tmpfs", "iso9660", "udf",
}

# Block device path must start with /dev/
_DEV_RE = re.compile(r"^/dev/[a-zA-Z0-9/_-]+$")
# Mountpoint must be an absolute path
_MP_RE  = re.compile(r"^/[a-zA-Z0-9_/.-]*$")


class MountRequest(BaseModel):
    device: str
    mountpoint: str
    fstype: str = "ext4"
    options: str = "defaults"


@router.post("/disk/mount")
async def disk_mount(body: MountRequest, user: str = Depends(require_super_admin)) -> dict:
    if not _DEV_RE.match(body.device):
        raise HTTPException(status_code=400, detail="Invalid device path")
    if not _MP_RE.match(body.mountpoint):
        raise HTTPException(status_code=400, detail="Invalid mountpoint path")
    if body.fstype not in _ALLOWED_FSTYPES:
        raise HTTPException(status_code=400, detail=f"Filesystem type not allowed: {body.fstype!r}")
    # options: allow only safe alphanumeric/comma/= chars
    if not re.match(r"^[a-zA-Z0-9,=_-]+$", body.options):
        raise HTTPException(status_code=400, detail="Invalid mount options")

    # Ensure mountpoint exists
    Path(body.mountpoint).mkdir(parents=True, exist_ok=True)

    cmd = ["mount", "-t", body.fstype, "-o", body.options, body.device, body.mountpoint]
    out, err, rc = _run(cmd, timeout=15)
    result = "ok" if rc == 0 else "error"
    _audit(user, "disk_mount", f"{body.device} → {body.mountpoint} ({body.fstype})", result)
    if rc != 0:
        raise HTTPException(status_code=500, detail=err.strip() or "mount failed")
    return {"ok": True, "device": body.device, "mountpoint": body.mountpoint,
            "fstype": body.fstype, "executed_at": datetime.now(UTC).isoformat()}


class UnmountRequest(BaseModel):
    mountpoint: str
    lazy: bool = False   # -l flag — unmount when no longer busy


@router.post("/disk/unmount")
async def disk_unmount(body: UnmountRequest, user: str = Depends(require_super_admin)) -> dict:
    if not _MP_RE.match(body.mountpoint):
        raise HTTPException(status_code=400, detail="Invalid mountpoint path")

    # Refuse to unmount critical system paths
    protected = {"/", "/boot", "/boot/efi", "/proc", "/sys", "/dev", "/run", "/tmp"}
    if body.mountpoint.rstrip("/") in protected:
        raise HTTPException(status_code=403, detail=f"Cannot unmount protected path: {body.mountpoint}")

    cmd = ["umount"]
    if body.lazy:
        cmd.append("-l")
    cmd.append(body.mountpoint)
    out, err, rc = _run(cmd, timeout=15)
    result = "ok" if rc == 0 else "error"
    _audit(user, "disk_unmount", body.mountpoint, result)
    if rc != 0:
        raise HTTPException(status_code=500, detail=err.strip() or "umount failed")
    return {"ok": True, "mountpoint": body.mountpoint, "executed_at": datetime.now(UTC).isoformat()}


# ---------------------------------------------------------------------------
# System: Reboot / Shutdown
# ---------------------------------------------------------------------------

class SystemPowerRequest(BaseModel):
    confirm: bool = False  # must be True to execute


@router.post("/system/reboot")
async def system_reboot(body: SystemPowerRequest, user: str = Depends(require_super_admin)) -> dict:
    if not body.confirm:
        raise HTTPException(status_code=400, detail="confirm must be true")
    _audit(user, "system_reboot", "requested", "executing")
    out, err, rc = _run(["shutdown", "-r", "+0"], timeout=10)
    result = "ok" if rc == 0 else "error"
    _audit(user, "system_reboot", "shutdown -r +0", result)
    if rc != 0:
        raise HTTPException(status_code=500, detail=err.strip() or "reboot failed")
    return {"ok": True, "action": "reboot", "executed_at": datetime.now(UTC).isoformat()}


@router.post("/system/shutdown")
async def system_shutdown(body: SystemPowerRequest, user: str = Depends(require_super_admin)) -> dict:
    if not body.confirm:
        raise HTTPException(status_code=400, detail="confirm must be true")
    _audit(user, "system_shutdown", "requested", "executing")
    out, err, rc = _run(["shutdown", "-h", "+0"], timeout=10)
    result = "ok" if rc == 0 else "error"
    _audit(user, "system_shutdown", "shutdown -h +0", result)
    if rc != 0:
        raise HTTPException(status_code=500, detail=err.strip() or "shutdown failed")
    return {"ok": True, "action": "shutdown", "executed_at": datetime.now(UTC).isoformat()}


# ---------------------------------------------------------------------------
# SSE — live upgrade log streaming
# ---------------------------------------------------------------------------

import asyncio as _asyncio
from fastapi.responses import StreamingResponse as _StreamingResponse


@router.get("/os/upgrade/stream")
async def stream_upgrade_log(_: str = Depends(require_super_admin)):
    """Server-Sent Events stream of the running upgrade log.

    The client receives one event per new log line. The stream closes when the
    upgrade finishes (status != 'running') or after 10 minutes of silence.
    """
    async def _generator():
        sent = 0
        idle = 0
        yield "retry: 2000\n\n"
        while True:
            lines = _UPGRADE_JOB.get("lines", [])
            new = lines[sent:]
            if new:
                idle = 0
                for line in new:
                    data = line.replace("\n", " ").strip()
                    if data:
                        yield f"data: {data}\n\n"
                sent += len(new)
            status = _UPGRADE_JOB.get("status", "idle")
            if status != "running" and sent >= len(_UPGRADE_JOB.get("lines", [])):
                yield f"event: done\ndata: {status}\n\n"
                break
            await _asyncio.sleep(0.5)
            idle += 1
            if idle > 1200:  # 10 minutes
                yield "event: timeout\ndata: stream timeout\n\n"
                break

    return _StreamingResponse(
        _generator(),
        media_type="text/event-stream",
        headers={"X-Accel-Buffering": "no", "Cache-Control": "no-cache"},
    )


# ---------------------------------------------------------------------------
# SMART disk health
# ---------------------------------------------------------------------------

@router.get("/disk/smart")
async def get_smart_health(_: str = Depends(require_super_admin)) -> dict:
    """Return SMART health data for all physical block devices using smartctl."""
    import json as _json

    # Enumerate physical block devices (exclude loop, sr, dm)
    devices: list[str] = []
    try:
        lsblk_out, _, _ = _run(["lsblk", "-d", "-n", "-o", "NAME,TYPE"], timeout=5)
        for line in lsblk_out.splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[1] == "disk":
                devices.append(f"/dev/{parts[0]}")
    except Exception:
        pass

    results: list[dict] = []
    for dev in devices:
        out, err, rc = _run(["sudo", "smartctl", "-a", "-j", dev], timeout=15)
        try:
            data = _json.loads(out)
        except Exception:
            results.append({"device": dev, "error": err.strip() or "smartctl parse error"})
            continue

        smart_status = data.get("smart_status", {})
        ata_attrs = data.get("ata_smart_attributes", {}).get("table", [])
        nvme = data.get("nvme_smart_health_information_log", {})
        model_info = data.get("model_name") or data.get("model_family") or ""
        temp = (
            data.get("temperature", {}).get("current")
            or nvme.get("temperature", {}).get("current")
        )
        results.append({
            "device": dev,
            "model": model_info,
            "serial": data.get("serial_number", ""),
            "firmware": data.get("firmware_version", ""),
            "capacity_bytes": data.get("user_capacity", {}).get("bytes"),
            "rotation_rate": data.get("rotation_rate"),
            "passed": smart_status.get("passed"),
            "temperature_c": temp,
            "power_on_hours": next(
                (a["raw"]["value"] for a in ata_attrs if a.get("id") == 9),
                nvme.get("power_on_hours"),
            ),
            "reallocated_sectors": next(
                (a["raw"]["value"] for a in ata_attrs if a.get("id") == 5), None
            ),
            "pending_sectors": next(
                (a["raw"]["value"] for a in ata_attrs if a.get("id") == 197), None
            ),
            "uncorrectable_errors": next(
                (a["raw"]["value"] for a in ata_attrs if a.get("id") == 198),
                nvme.get("media_errors"),
            ),
            "attributes": [
                {
                    "id": a.get("id"),
                    "name": a.get("name"),
                    "value": a.get("value"),
                    "worst": a.get("worst"),
                    "thresh": a.get("thresh"),
                    "raw": a.get("raw", {}).get("value"),
                    "failed": a.get("when_failed") not in (None, "", "never", "-"),
                }
                for a in ata_attrs
            ],
        })

    return {"devices": results, "count": len(results), "checked_at": datetime.now(UTC).isoformat()}


# ---------------------------------------------------------------------------
# Package hold / pin management
# ---------------------------------------------------------------------------

@router.get("/packages/holds")
async def list_package_holds(_: str = Depends(require_super_admin)) -> dict:
    """Return all packages currently held (apt-mark showhold)."""
    out, _, _ = _run(["sudo", "apt-mark", "showhold"], timeout=10)
    held = [p.strip() for p in out.splitlines() if p.strip()]
    return {"held": held, "count": len(held), "checked_at": datetime.now(UTC).isoformat()}


class PackageHoldRequest(BaseModel):
    package: str
    action: str  # "hold" | "unhold"


@router.post("/packages/hold")
async def set_package_hold(body: PackageHoldRequest, user: str = Depends(require_super_admin)) -> dict:
    if body.action not in ("hold", "unhold"):
        raise HTTPException(400, "action must be 'hold' or 'unhold'")
    if not re.match(r"^[a-zA-Z0-9_.+-]+$", body.package):
        raise HTTPException(400, "Invalid package name")
    out, err, rc = _run(["sudo", "apt-mark", body.action, body.package], timeout=10)
    result = "ok" if rc == 0 else "error"
    _audit(user, f"package_{body.action}", body.package, result)
    if rc != 0:
        raise HTTPException(500, err.strip() or f"apt-mark {body.action} failed")
    return {"ok": True, "package": body.package, "action": body.action, "executed_at": datetime.now(UTC).isoformat()}


# ---------------------------------------------------------------------------
# Audit log viewer
# ---------------------------------------------------------------------------

@router.get("/audit-log")
async def get_audit_log(
    _: str = Depends(require_super_admin),
    lines: int = Query(200, ge=1, le=1000),
    search: str = Query("", max_length=100),
) -> dict:
    """Read the last N lines of the MC3 audit log."""
    log_path = Path("/var/log/mc3-audit.log")
    entries: list[dict] = []
    try:
        out, _, _ = _run(["sudo", "tail", f"-{lines * 3}", str(log_path)], timeout=5)
        for line in out.splitlines():
            line = line.strip()
            if not line:
                continue
            if search and search.lower() not in line.lower():
                continue
            # Parse: "2025-01-01 12:00:00,000  user=X action=Y detail='Z' result=W"
            entry: dict[str, str] = {"raw": line}
            ts_match = re.match(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})", line)
            if ts_match:
                entry["timestamp"] = ts_match.group(1)
            for field in ("user", "action", "detail", "result"):
                m = re.search(rf"{field}=(\S+)", line)
                if m:
                    entry[field] = m.group(1).strip("'\"")
            entries.append(entry)
    except Exception as exc:
        return {"entries": [], "total": 0, "error": str(exc)}

    entries = entries[-lines:]
    return {"entries": list(reversed(entries)), "total": len(entries), "checked_at": datetime.now(UTC).isoformat()}


# ---------------------------------------------------------------------------
# Historical metrics (SQLite time-series, 30-day)
# ---------------------------------------------------------------------------

import sqlite3 as _sqlite3
import logging as _metrics_logging

_METRICS_DB = Path("/var/lib/mc3/metrics.db")
_METRICS_DB.parent.mkdir(parents=True, exist_ok=True)
_metrics_log = _metrics_logging.getLogger("mc3.metrics")


def _metrics_db() -> _sqlite3.Connection:
    conn = _sqlite3.connect(str(_METRICS_DB), check_same_thread=False)
    conn.row_factory = _sqlite3.Row
    conn.execute("""
        CREATE TABLE IF NOT EXISTS metrics (
            ts INTEGER PRIMARY KEY,
            cpu_pct REAL,
            mem_pct REAL,
            swap_pct REAL,
            disk_root_pct REAL,
            net_sent_mb REAL,
            net_recv_mb REAL,
            load_1m REAL
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_ts ON metrics(ts)")
    conn.commit()
    return conn


def _metrics_sample() -> None:
    try:
        cpu = psutil.cpu_percent(interval=1)
        mem = psutil.virtual_memory()
        swap = psutil.swap_memory()
        net = psutil.net_io_counters()
        try:
            disk_root = psutil.disk_usage("/").percent
        except Exception:
            disk_root = 0.0
        load1 = psutil.getloadavg()[0]
        ts = int(time.time())
        conn = _metrics_db()
        conn.execute(
            "INSERT OR REPLACE INTO metrics VALUES (?,?,?,?,?,?,?,?)",
            (ts, cpu, mem.percent, swap.percent, disk_root,
             round(net.bytes_sent / 1e6, 4), round(net.bytes_recv / 1e6, 4), round(load1, 2))
        )
        # Prune records older than 30 days
        conn.execute("DELETE FROM metrics WHERE ts < ?", (ts - 30 * 86400,))
        conn.commit()
        conn.close()
    except Exception as exc:
        _metrics_log.warning("metrics sample error: %s", exc)


def _metrics_loop() -> None:
    while True:
        try:
            _metrics_sample()
        except Exception:
            pass
        time.sleep(60)


threading.Thread(target=_metrics_loop, daemon=True, name="metrics-sampler").start()


@router.get("/metrics/history")
async def get_metrics_history(
    _: str = Depends(require_super_admin),
    hours: int = Query(24, ge=1, le=720),
    resolution: int = Query(60, ge=5, le=3600, description="Bucket size in seconds"),
) -> dict:
    """Return time-bucketed CPU/mem/disk/net metrics for the last N hours."""
    since = int(time.time()) - hours * 3600
    try:
        conn = _metrics_db()
        rows = conn.execute(
            "SELECT ts, cpu_pct, mem_pct, swap_pct, disk_root_pct, net_sent_mb, net_recv_mb, load_1m "
            "FROM metrics WHERE ts >= ? ORDER BY ts",
            (since,),
        ).fetchall()
        conn.close()
    except Exception as exc:
        return {"error": str(exc), "rows": []}

    # Bucket by resolution
    buckets: dict[int, list] = {}
    for row in rows:
        bucket = (row["ts"] // resolution) * resolution
        buckets.setdefault(bucket, []).append(dict(row))

    averaged = []
    for bucket_ts in sorted(buckets):
        group = buckets[bucket_ts]
        n = len(group)
        averaged.append({
            "ts": bucket_ts,
            "cpu_pct": round(sum(r["cpu_pct"] for r in group) / n, 1),
            "mem_pct": round(sum(r["mem_pct"] for r in group) / n, 1),
            "swap_pct": round(sum(r["swap_pct"] for r in group) / n, 1),
            "disk_root_pct": round(sum(r["disk_root_pct"] for r in group) / n, 1),
            "net_sent_mb": round(sum(r["net_sent_mb"] for r in group) / n, 4),
            "net_recv_mb": round(sum(r["net_recv_mb"] for r in group) / n, 4),
            "load_1m": round(sum(r["load_1m"] for r in group) / n, 2),
        })

    return {
        "rows": averaged,
        "count": len(averaged),
        "hours": hours,
        "resolution": resolution,
        "since": since,
        "checked_at": datetime.now(UTC).isoformat(),
    }


# ---------------------------------------------------------------------------
# Resource alert thresholds
# ---------------------------------------------------------------------------

_ALERT_CONFIG_PATH = Path("/var/lib/mc3/alert_thresholds.json")
_ALERT_DEFAULTS: dict = {
    "cpu_pct": 90.0,
    "mem_pct": 90.0,
    "disk_root_pct": 85.0,
    "load_1m": 8.0,
    "enabled": True,
}


def _load_alert_config() -> dict:
    try:
        import json as _j
        return {**_ALERT_DEFAULTS, **_j.loads(_ALERT_CONFIG_PATH.read_text())}
    except Exception:
        return dict(_ALERT_DEFAULTS)


def _save_alert_config(cfg: dict) -> None:
    import json as _j
    _ALERT_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    _ALERT_CONFIG_PATH.write_text(_j.dumps(cfg, indent=2))


@router.get("/alerts/thresholds")
async def get_alert_thresholds(_: str = Depends(require_super_admin)) -> dict:
    cfg = _load_alert_config()
    # Evaluate current state against thresholds
    cpu = psutil.cpu_percent(interval=0.2)
    mem = psutil.virtual_memory().percent
    load1 = psutil.getloadavg()[0]
    try:
        disk = psutil.disk_usage("/").percent
    except Exception:
        disk = 0.0
    alerts = []
    if cfg["enabled"]:
        if cpu >= cfg["cpu_pct"]:
            alerts.append({"metric": "cpu_pct", "value": cpu, "threshold": cfg["cpu_pct"]})
        if mem >= cfg["mem_pct"]:
            alerts.append({"metric": "mem_pct", "value": mem, "threshold": cfg["mem_pct"]})
        if disk >= cfg["disk_root_pct"]:
            alerts.append({"metric": "disk_root_pct", "value": disk, "threshold": cfg["disk_root_pct"]})
        if load1 >= cfg["load_1m"]:
            alerts.append({"metric": "load_1m", "value": round(load1, 2), "threshold": cfg["load_1m"]})
    return {
        "thresholds": cfg,
        "current": {"cpu_pct": cpu, "mem_pct": mem, "disk_root_pct": disk, "load_1m": round(load1, 2)},
        "active_alerts": alerts,
        "checked_at": datetime.now(UTC).isoformat(),
    }


class AlertThresholdsRequest(BaseModel):
    cpu_pct: float | None = None
    mem_pct: float | None = None
    disk_root_pct: float | None = None
    load_1m: float | None = None
    enabled: bool | None = None


@router.post("/alerts/thresholds")
async def update_alert_thresholds(body: AlertThresholdsRequest, user: str = Depends(require_super_admin)) -> dict:
    cfg = _load_alert_config()
    if body.cpu_pct is not None:
        cfg["cpu_pct"] = max(10.0, min(100.0, body.cpu_pct))
    if body.mem_pct is not None:
        cfg["mem_pct"] = max(10.0, min(100.0, body.mem_pct))
    if body.disk_root_pct is not None:
        cfg["disk_root_pct"] = max(10.0, min(100.0, body.disk_root_pct))
    if body.load_1m is not None:
        cfg["load_1m"] = max(0.1, min(128.0, body.load_1m))
    if body.enabled is not None:
        cfg["enabled"] = body.enabled
    _save_alert_config(cfg)
    _audit(user, "alert_thresholds_update", str(cfg), "ok")
    return {"ok": True, "thresholds": cfg}


# ---------------------------------------------------------------------------
# Log rotation management
# ---------------------------------------------------------------------------

@router.get("/log-rotation/configs")
async def list_logrotate_configs(_: str = Depends(require_super_admin)) -> dict:
    """List logrotate config files and their current state."""
    configs: list[dict] = []
    for conf_dir in ["/etc/logrotate.d", "/etc/logrotate.conf"]:
        p = Path(conf_dir)
        if p.is_file():
            configs.append({"path": str(p), "name": p.name, "is_dir": False})
        elif p.is_dir():
            for f in sorted(p.iterdir()):
                if f.is_file():
                    try:
                        content = f.read_text(errors="replace")
                        configs.append({"path": str(f), "name": f.name, "is_dir": False, "size": f.stat().st_size, "preview": content[:300]})
                    except Exception:
                        configs.append({"path": str(f), "name": f.name, "error": "unreadable"})

    # Get logrotate status (last run times)
    status_path = Path("/var/lib/logrotate/status")
    last_runs: dict[str, str] = {}
    try:
        for line in status_path.read_text(errors="replace").splitlines():
            m = re.match(r'^"(.+)" (.+)$', line.strip())
            if m:
                last_runs[m.group(1)] = m.group(2)
    except Exception:
        pass

    return {"configs": configs, "last_runs": last_runs, "checked_at": datetime.now(UTC).isoformat()}


@router.post("/log-rotation/run")
async def run_logrotate(user: str = Depends(require_super_admin)) -> dict:
    """Force-run logrotate on all configs."""
    out, err, rc = _run(["sudo", "logrotate", "--force", "/etc/logrotate.conf"], timeout=60)
    result = "ok" if rc == 0 else "error"
    _audit(user, "logrotate_run", "--force", result)
    return {
        "ok": rc == 0,
        "stdout": out[:1000],
        "stderr": err[:500],
        "returncode": rc,
        "executed_at": datetime.now(UTC).isoformat(),
    }


# ---------------------------------------------------------------------------
# Filesystem backup jobs
# ---------------------------------------------------------------------------

import json as _json

_BACKUP_JOBS_PATH = Path("/var/lib/mc3/backup_jobs.json")
_BACKUP_RUNNING: dict[str, dict] = {}
_BACKUP_LOCK = threading.Lock()


def _load_backup_jobs() -> list[dict]:
    try:
        return _json.loads(_BACKUP_JOBS_PATH.read_text())
    except Exception:
        return []


def _save_backup_jobs(jobs: list[dict]) -> None:
    _BACKUP_JOBS_PATH.parent.mkdir(parents=True, exist_ok=True)
    _BACKUP_JOBS_PATH.write_text(_json.dumps(jobs, indent=2))


@router.get("/backup/jobs")
async def list_backup_jobs(_: str = Depends(require_super_admin)) -> dict:
    jobs = _load_backup_jobs()
    with _BACKUP_LOCK:
        for job in jobs:
            if job["id"] in _BACKUP_RUNNING:
                job["status"] = _BACKUP_RUNNING[job["id"]]["status"]
                job["last_log"] = _BACKUP_RUNNING[job["id"]].get("log", [])[-20:]
    return {"jobs": jobs, "count": len(jobs), "checked_at": datetime.now(UTC).isoformat()}


class BackupJobRequest(BaseModel):
    name: str
    source: str        # absolute path to backup
    destination: str   # absolute path for backup output
    method: str = "rsync"   # "rsync" | "tar"
    exclude: list[str] = []


@router.post("/backup/jobs")
async def create_backup_job(body: BackupJobRequest, user: str = Depends(require_super_admin)) -> dict:
    if not body.source.startswith("/") or not body.destination.startswith("/"):
        raise HTTPException(400, "Source and destination must be absolute paths")
    if body.method not in ("rsync", "tar"):
        raise HTTPException(400, "method must be 'rsync' or 'tar'")
    jobs = _load_backup_jobs()
    job_id = str(uuid.uuid4())[:8]
    job = {
        "id": job_id,
        "name": body.name[:80],
        "source": body.source,
        "destination": body.destination,
        "method": body.method,
        "exclude": body.exclude[:20],
        "created_at": datetime.now(UTC).isoformat(),
        "last_run": None,
        "last_result": None,
    }
    jobs.append(job)
    _save_backup_jobs(jobs)
    _audit(user, "backup_job_create", f"{body.source}→{body.destination}", "ok")
    return {"ok": True, "job": job}


@router.delete("/backup/jobs/{job_id}")
async def delete_backup_job(job_id: str, user: str = Depends(require_super_admin)) -> dict:
    jobs = _load_backup_jobs()
    original = len(jobs)
    jobs = [j for j in jobs if j["id"] != job_id]
    if len(jobs) == original:
        raise HTTPException(404, "Job not found")
    _save_backup_jobs(jobs)
    _audit(user, "backup_job_delete", job_id, "ok")
    return {"ok": True}


def _run_backup_job(job: dict) -> None:
    job_id = job["id"]
    with _BACKUP_LOCK:
        _BACKUP_RUNNING[job_id] = {"status": "running", "log": []}

    def _log(msg: str) -> None:
        with _BACKUP_LOCK:
            _BACKUP_RUNNING[job_id]["log"].append(msg)

    try:
        src, dst, method = job["source"], job["destination"], job["method"]
        Path(dst).mkdir(parents=True, exist_ok=True)

        if method == "rsync":
            cmd = ["sudo", "rsync", "-av", "--delete"]
            for ex in job.get("exclude", []):
                cmd += ["--exclude", ex]
            cmd += [src.rstrip("/") + "/", dst.rstrip("/") + "/"]
        else:  # tar
            ts = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
            archive = str(Path(dst) / f"backup_{ts}.tar.gz")
            cmd = ["sudo", "tar", "-czf", archive]
            for ex in job.get("exclude", []):
                cmd += ["--exclude", ex]
            cmd.append(src)

        _log(f"Starting {method} backup: {src} → {dst}")
        out, err, rc = _run(cmd, timeout=3600)
        for line in (out + err).splitlines():
            _log(line.strip())
        result = "ok" if rc == 0 else f"error (rc={rc})"
        _log(f"Backup {result}")

        jobs = _load_backup_jobs()
        for j in jobs:
            if j["id"] == job_id:
                j["last_run"] = datetime.now(UTC).isoformat()
                j["last_result"] = result
        _save_backup_jobs(jobs)

        with _BACKUP_LOCK:
            _BACKUP_RUNNING[job_id]["status"] = result
    except Exception as exc:
        with _BACKUP_LOCK:
            _BACKUP_RUNNING[job_id]["status"] = f"error: {exc}"
        _log(f"Exception: {exc}")


@router.post("/backup/jobs/{job_id}/run")
async def run_backup_job(job_id: str, user: str = Depends(require_super_admin)) -> dict:
    jobs = _load_backup_jobs()
    job = next((j for j in jobs if j["id"] == job_id), None)
    if not job:
        raise HTTPException(404, "Job not found")
    with _BACKUP_LOCK:
        if _BACKUP_RUNNING.get(job_id, {}).get("status") == "running":
            return {"ok": False, "message": "Job already running"}
    _audit(user, "backup_job_run", job_id, "started")
    thread = threading.Thread(target=_run_backup_job, args=(job,), daemon=True)
    thread.start()
    return {"ok": True, "job_id": job_id}


@router.get("/backup/jobs/{job_id}/log")
async def get_backup_job_log(job_id: str, _: str = Depends(require_super_admin)) -> dict:
    with _BACKUP_LOCK:
        info = _BACKUP_RUNNING.get(job_id, {})
    return {
        "job_id": job_id,
        "status": info.get("status", "idle"),
        "log": info.get("log", []),
        "checked_at": datetime.now(UTC).isoformat(),
    }


# ---------------------------------------------------------------------------
# SSH key management
# ---------------------------------------------------------------------------

_ALLOWED_KEY_TYPES = {"ssh-rsa", "ssh-dss", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384",
                      "ecdsa-sha2-nistp521", "ssh-ed25519", "sk-ecdsa-sha2-nistp256@openssh.com",
                      "sk-ssh-ed25519@openssh.com"}


def _auth_keys_path(username: str) -> Path:
    try:
        pw = pwd.getpwnam(username)
        return Path(pw.pw_dir) / ".ssh" / "authorized_keys"
    except KeyError:
        raise HTTPException(404, f"User not found: {username}")


def _read_auth_keys(username: str) -> list[dict]:
    path = _auth_keys_path(username)
    out, _, _ = _run(["sudo", "cat", str(path)], timeout=5)
    keys = []
    for i, line in enumerate(out.splitlines()):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 2)
        if len(parts) < 2:
            continue
        keys.append({
            "index": i,
            "type": parts[0],
            "key": parts[1][:40] + "…" if len(parts[1]) > 40 else parts[1],
            "comment": parts[2] if len(parts) > 2 else "",
            "full": line,
        })
    return keys


@router.get("/ssh/keys/{username}")
async def get_ssh_keys(username: str, _: str = Depends(require_super_admin)) -> dict:
    if not re.match(r"^[a-zA-Z0-9_.-]+$", username):
        raise HTTPException(400, "Invalid username")
    keys = _read_auth_keys(username)
    return {"username": username, "keys": keys, "count": len(keys)}


class SSHKeyRequest(BaseModel):
    public_key: str


@router.post("/ssh/keys/{username}")
async def add_ssh_key(username: str, body: SSHKeyRequest, user: str = Depends(require_super_admin)) -> dict:
    if not re.match(r"^[a-zA-Z0-9_.-]+$", username):
        raise HTTPException(400, "Invalid username")
    key = body.public_key.strip()
    key_type = key.split()[0] if key.split() else ""
    if key_type not in _ALLOWED_KEY_TYPES:
        raise HTTPException(400, f"Unsupported key type: {key_type!r}")

    path = _auth_keys_path(username)
    # Ensure .ssh dir exists
    _run(["sudo", "mkdir", "-p", str(path.parent)], timeout=5)
    _run(["sudo", "chmod", "700", str(path.parent)], timeout=5)
    # Append key
    append_cmd = f"echo {_shlex_quote(key)} | sudo tee -a {_shlex_quote(str(path))}"
    out, err, rc = _run(["sudo", "bash", "-c", f"echo {_shlex_quote(key)} >> {_shlex_quote(str(path))}"], timeout=5)
    if rc != 0:
        raise HTTPException(500, err.strip() or "Failed to append key")
    _run(["sudo", "chmod", "600", str(path)], timeout=5)
    _audit(user, "ssh_key_add", f"{username}: {key[:40]}", "ok")
    return {"ok": True, "username": username}


class SSHKeyDeleteRequest(BaseModel):
    key_fragment: str   # unique substring of the key to delete (the full key or comment)


@router.delete("/ssh/keys/{username}")
async def delete_ssh_key(username: str, body: SSHKeyDeleteRequest, user: str = Depends(require_super_admin)) -> dict:
    if not re.match(r"^[a-zA-Z0-9_.-]+$", username):
        raise HTTPException(400, "Invalid username")
    path = _auth_keys_path(username)
    out, _, _ = _run(["sudo", "cat", str(path)], timeout=5)
    original_lines = out.splitlines()
    frag = body.key_fragment.strip()
    new_lines = [l for l in original_lines if frag not in l]
    if len(new_lines) == len(original_lines):
        raise HTTPException(404, "Key not found")
    new_content = "\n".join(new_lines) + "\n"
    write_cmd = ["sudo", "bash", "-c", f"printf %s {_shlex_quote(new_content)} > {_shlex_quote(str(path))}"]
    _, err, rc = _run(write_cmd, timeout=5)
    if rc != 0:
        raise HTTPException(500, err.strip() or "Failed to write authorized_keys")
    _audit(user, "ssh_key_delete", f"{username}: {frag[:40]}", "ok")
    return {"ok": True, "removed": len(original_lines) - len(new_lines)}


def _shlex_quote(s: str) -> str:
    import shlex
    return shlex.quote(s)


# ---------------------------------------------------------------------------
# Database admin (MariaDB / MySQL)
# Uses frothiq_dba credentials — ALL PRIVILEGES on all databases.
# ---------------------------------------------------------------------------

_DB_CNF = "--defaults-extra-file=/etc/mysql/frothiq_dba.cnf"
_DB_NAME_RE = re.compile(r"^[a-zA-Z0-9_\-]+$")


def _mysql(*args: str, timeout: int = 15) -> tuple[str, str, int]:
    """Run mariadb CLI with frothiq_dba credentials."""
    return _run(["mariadb", _DB_CNF, *args], timeout=timeout)


@router.get("/database/databases")
async def list_databases(_: str = Depends(require_super_admin)) -> dict:
    """List all MariaDB databases visible to frothiq_dba."""
    out, err, rc = _mysql("-e", "SHOW DATABASES;", "--skip-column-names", "-s")
    if rc != 0:
        return {"error": err.strip() or "mariadb unavailable", "databases": []}
    dbs = [line.strip() for line in out.splitlines() if line.strip()]
    return {"databases": dbs, "count": len(dbs), "checked_at": datetime.now(UTC).isoformat()}


@router.get("/database/databases/{db}/tables")
async def list_tables(db: str, _: str = Depends(require_super_admin)) -> dict:
    if not _DB_NAME_RE.match(db):
        raise HTTPException(400, "Invalid database name")
    out, err, rc = _mysql(db, "-e", "SHOW TABLES;", "--skip-column-names", "-s")
    if rc != 0:
        raise HTTPException(500, err.strip() or "mariadb error")
    tables = [line.strip() for line in out.splitlines() if line.strip()]
    return {"database": db, "tables": tables, "count": len(tables)}


class DBQueryRequest(BaseModel):
    database: str
    query: str


@router.post("/database/query")
async def run_db_query(body: DBQueryRequest, user: str = Depends(require_super_admin)) -> dict:
    """Execute a read-only SELECT/SHOW/DESCRIBE/EXPLAIN query against a MariaDB database."""
    if not _DB_NAME_RE.match(body.database):
        raise HTTPException(400, "Invalid database name")
    stripped = body.query.strip().upper()
    allowed_prefixes = ("SELECT", "SHOW", "DESCRIBE", "EXPLAIN", "DESC")
    if not any(stripped.startswith(p) for p in allowed_prefixes):
        raise HTTPException(400, "Only SELECT, SHOW, DESCRIBE, and EXPLAIN queries are allowed")
    if len(body.query) > 2000:
        raise HTTPException(400, "Query too long (max 2000 chars)")

    out, err, rc = _mysql(body.database, "-e", body.query, "--table", timeout=30)
    if rc != 0:
        raise HTTPException(500, err.strip() or "query error")
    _audit(user, "db_query", f"{body.database}: {body.query[:80]}", "ok")
    return {
        "database": body.database,
        "query": body.query,
        "result": out[:50000],
        "executed_at": datetime.now(UTC).isoformat(),
    }


class DBCreateRequest(BaseModel):
    name: str
    charset: str = "utf8mb4"
    collation: str = "utf8mb4_unicode_ci"


@router.post("/database/databases")
async def create_database(body: DBCreateRequest, user: str = Depends(require_super_admin)) -> dict:
    """Create a new MariaDB database."""
    if not _DB_NAME_RE.match(body.name):
        raise HTTPException(400, "Invalid database name")
    allowed_charsets = {"utf8mb4", "utf8", "latin1", "ascii"}
    if body.charset not in allowed_charsets:
        raise HTTPException(400, f"Unsupported charset. Allowed: {', '.join(allowed_charsets)}")
    sql = f"CREATE DATABASE `{body.name}` CHARACTER SET {body.charset} COLLATE {body.collation};"
    out, err, rc = _mysql("-e", sql)
    if rc != 0:
        raise HTTPException(500, err.strip() or "create database failed")
    _audit(user, "db_create", body.name, "ok")
    return {"created": body.name, "charset": body.charset, "collation": body.collation}


@router.delete("/database/databases/{db}")
async def drop_database(db: str, user: str = Depends(require_super_admin)) -> dict:
    """Drop a MariaDB database. Irreversible — caller must confirm."""
    if not _DB_NAME_RE.match(db):
        raise HTTPException(400, "Invalid database name")
    protected = {"mysql", "information_schema", "performance_schema", "sys", "frothiq_cc"}
    if db in protected:
        raise HTTPException(403, f"Database '{db}' is protected and cannot be dropped")
    out, err, rc = _mysql("-e", f"DROP DATABASE `{db}`;")
    if rc != 0:
        raise HTTPException(500, err.strip() or "drop database failed")
    _audit(user, "db_drop", db, "ok")
    return {"dropped": db}
