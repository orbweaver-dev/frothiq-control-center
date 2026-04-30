"""
WebOps — Virtual server inventory, connectivity monitoring, and controlled actions.

Server registry is stored in /etc/mc3/webops-servers.json.
Two server types:
  ssh      — remote server accessible via SSH (stop/restart only)
  libvirt  — local KVM/QEMU VM managed via virsh (start/stop/restart)

All actions are whitelisted. No arbitrary command execution.
Every action is audited to /var/log/mc3-audit.log.
"""

from __future__ import annotations

import json
import logging
import os
import re
import subprocess
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from .routes_auth import require_super_admin

router = APIRouter(prefix="/webops", tags=["webops"])

# ---------------------------------------------------------------------------
# Registry persistence
# ---------------------------------------------------------------------------

REGISTRY_FILE = Path("/var/lib/mc3/webops-servers.json")

_LOCAL_SERVER_ID = "wh1-local"


def _make_local_server() -> dict:
    return {
        "id": _LOCAL_SERVER_ID,
        "display_name": "wh1 (this server)",
        "hostname": "wh1.zonkhost.net",
        "ip": "127.0.0.1",
        "type": "local",
        "provider": "Zonkhost",
        "os": "Ubuntu 22.04",
        "ssh_user": "",
        "ssh_port": 22,
        "ssh_key": "",
        "libvirt_name": "",
        "tags": ["local", "wh1"],
        "notes": "Auto-registered local server",
        "added_at": datetime.now(UTC).isoformat(),
        "added_by": "system",
    }


def _load_registry() -> list[dict]:
    if not REGISTRY_FILE.exists():
        servers = [_make_local_server()]
        try:
            REGISTRY_FILE.parent.mkdir(parents=True, exist_ok=True)
            REGISTRY_FILE.write_text(json.dumps(servers, indent=2))
        except OSError:
            pass
        return servers
    try:
        return json.loads(REGISTRY_FILE.read_text())
    except PermissionError:
        raise HTTPException(503, f"Server registry is not readable — fix ownership: chown frothiq {REGISTRY_FILE}")
    except (json.JSONDecodeError, OSError):
        return []


def _save_registry(servers: list[dict]) -> None:
    REGISTRY_FILE.write_text(json.dumps(servers, indent=2))


def _find_server(server_id: str) -> dict:
    for s in _load_registry():
        if s.get("id") == server_id:
            return s
    raise HTTPException(status_code=404, detail=f"Server {server_id!r} not found in registry")


# ---------------------------------------------------------------------------
# Audit logger
# ---------------------------------------------------------------------------

_audit_log = logging.getLogger("mc3.webops.audit")
if not _audit_log.handlers:
    try:
        _h = logging.FileHandler("/var/log/mc3-audit.log", delay=True)
        _h.setFormatter(logging.Formatter("%(asctime)s  %(message)s"))
        _audit_log.addHandler(_h)
    except OSError:
        pass
    _audit_log.addHandler(logging.StreamHandler())
    _audit_log.setLevel(logging.INFO)


def _audit(user: str, action: str, server_id: str, detail: str, result: str) -> None:
    _audit_log.info(
        "domain=webops user=%s action=%s server=%s detail=%r result=%s",
        user, action, server_id, detail, result,
    )


# ---------------------------------------------------------------------------
# Low-level helpers — all subprocess with explicit arg lists, no shell=True
# ---------------------------------------------------------------------------

def _run(cmd: list[str], timeout: int = 10) -> tuple[str, str, int]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout, r.stderr, r.returncode
    except subprocess.TimeoutExpired:
        return "", "timeout", 124
    except FileNotFoundError:
        return "", f"{cmd[0]!r} not found", 127


def _run_out(cmd: list[str], timeout: int = 10) -> str:
    out, _, _ = _run(cmd, timeout)
    return out.strip()


# ---------------------------------------------------------------------------
# Ping connectivity
# ---------------------------------------------------------------------------

def _ping_check(host: str) -> dict:
    out, _, rc = _run(["ping", "-c", "3", "-W", "2", host], timeout=10)
    if rc != 0:
        return {"reachable": False, "latency_ms": None, "packet_loss": None}
    latency_ms: float | None = None
    loss: str | None = None
    for line in out.splitlines():
        if "rtt" in line or "round-trip" in line:
            parts = line.split("=")
            if len(parts) > 1:
                vals = parts[1].strip().split("/")
                if len(vals) >= 2:
                    try:
                        latency_ms = float(vals[1])
                    except ValueError:
                        pass
        if "packet loss" in line:
            m = re.search(r"(\d+)%\s+packet loss", line)
            if m:
                loss = m.group(1) + "%"
    return {"reachable": True, "latency_ms": latency_ms, "packet_loss": loss or "0%"}


# ---------------------------------------------------------------------------
# SSH helpers
# ---------------------------------------------------------------------------

def _ssh_base(server: dict) -> list[str]:
    """Build the base ssh command for a server entry (no remote command yet)."""
    cmd = [
        "ssh",
        "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=no",
        "-o", "ConnectTimeout=8",
        "-o", "ServerAliveInterval=5",
        "-o", "ServerAliveCountMax=1",
        "-p", str(server.get("ssh_port", 22)),
    ]
    key = server.get("ssh_key", "")
    if key and os.path.isfile(key):
        cmd += ["-i", key]
    cmd.append(f"{server.get('ssh_user', 'root')}@{server['ip']}")
    return cmd


def _ssh_check(server: dict) -> dict:
    """Test SSH reachability. Returns latency_ms or None on failure."""
    t0 = time.monotonic()
    out, err, rc = _run(_ssh_base(server) + ["echo ok"], timeout=12)
    elapsed = round((time.monotonic() - t0) * 1000, 1)
    if rc == 0 and "ok" in out:
        return {"reachable": True, "latency_ms": elapsed, "error": None}
    return {"reachable": False, "latency_ms": None, "error": err.strip() or "SSH failed"}


def _ssh_metrics(server: dict) -> dict:
    """Fetch resource metrics over SSH — single connection, hardcoded commands only."""
    out, _, rc = _run(_ssh_base(server) + [_METRICS_SCRIPT], timeout=20)
    if rc != 0:
        return {}
    return _parse_metrics_output(out)


def _ssh_vhosts(server: dict) -> list[dict]:
    """Read virtual host configs from Apache / Nginx over SSH. No user input embedded."""
    script = (
        # Apache (apache2ctl or apachectl or httpd)
        "if command -v apache2ctl >/dev/null 2>&1; then "
        "  echo 'WEB:apache'; apache2ctl -S 2>&1 | grep 'namevhost'; "
        "elif command -v apachectl >/dev/null 2>&1; then "
        "  echo 'WEB:apache'; apachectl -S 2>&1 | grep 'namevhost'; "
        "elif command -v httpd >/dev/null 2>&1; then "
        "  echo 'WEB:httpd'; httpd -S 2>&1 | grep 'namevhost'; "
        "fi; "
        # Nginx — iterate enabled site configs
        "if command -v nginx >/dev/null 2>&1; then "
        "  echo 'WEB:nginx'; "
        "  for f in /etc/nginx/sites-enabled/* /etc/nginx/conf.d/*.conf; do "
        "    [ -f \"$f\" ] || continue; "
        "    sn=$(grep -m1 'server_name' \"$f\" 2>/dev/null | sed 's/.*server_name[[:space:]]*//' | tr -d ';' | awk '{print $1}'); "
        "    lt=$(grep -m1 'listen' \"$f\" 2>/dev/null | sed 's/.*listen[[:space:]]*//' | tr -d ';' | awk '{print $1}'); "
        "    ssl=$(grep -c 'ssl_certificate' \"$f\" 2>/dev/null || echo 0); "
        "    dr=$(grep -m1 'root ' \"$f\" 2>/dev/null | sed 's/.*root[[:space:]]*//' | tr -d ';' | awk '{print $1}'); "
        "    [ -n \"$sn\" ] && echo \"NGINX_VH:${sn}|${lt}|${ssl}|${dr}\"; "
        "  done; "
        "fi"
    )
    out, _, rc = _run(_ssh_base(server) + [script], timeout=25)
    if rc != 0:
        return []

    vhosts: list[dict] = []
    current_web = "apache"
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("WEB:"):
            current_web = line[4:].strip()
        elif "namevhost" in line:
            # Apache: "         port 80 namevhost example.com (/path/conf:1)"
            m = re.search(r"port\s+(\d+)\s+namevhost\s+(\S+)\s+\((.+?):\d+\)", line)
            if m:
                port = int(m.group(1)); domain = m.group(2); cfg = m.group(3)
                vhosts.append({
                    "domain": domain, "port": port,
                    "ssl": port == 443,
                    "server": current_web,
                    "doc_root": None,
                    "config_file": cfg,
                })
        elif line.startswith("NGINX_VH:"):
            parts = line[9:].split("|")
            domain   = parts[0] if parts else "_"
            raw_port = parts[1] if len(parts) > 1 else "80"
            ssl_cnt  = _safe_int(parts, 2)
            doc_root = (parts[3].strip() or None) if len(parts) > 3 else None
            m2 = re.search(r"(\d+)", raw_port)
            port_num = int(m2.group(1)) if m2 else 80
            vhosts.append({
                "domain": domain, "port": port_num,
                "ssl": ssl_cnt > 0 or port_num == 443,
                "server": "nginx",
                "doc_root": doc_root,
                "config_file": None,
            })

    # Deduplicate domain+port pairs
    seen: set[tuple] = set()
    unique: list[dict] = []
    for v in vhosts:
        key_t = (v["domain"], v["port"])
        if key_t not in seen:
            seen.add(key_t)
            unique.append(v)
    return sorted(unique, key=lambda v: (v["domain"], v["port"]))


def _ssh_services(server: dict) -> list[dict]:
    """List active systemd services over SSH."""
    cmd = (
        "systemctl list-units --type=service --state=running "
        "--no-pager --plain 2>/dev/null | head -30 | awk '{print $1}'"
    )
    out, _, rc = _run(_ssh_base(server) + [cmd], timeout=15)
    if rc != 0:
        return []
    return [{"name": line.strip()} for line in out.splitlines() if line.strip() and line.endswith(".service")]


def _ssh_ports(server: dict) -> list[dict]:
    """List listening ports on the remote server via SSH."""
    cmd = "ss -tlnp 2>/dev/null | awk 'NR>1 {print $4}' | head -20"
    out, _, rc = _run(_ssh_base(server) + [cmd], timeout=12)
    if rc != 0:
        return []
    ports = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        _, _, port = line.rpartition(":")
        if port.isdigit():
            ports.append({"port": port, "address": line})
    return ports


# ---------------------------------------------------------------------------
# Local server helpers (no SSH — reads /proc and conf files directly)
# ---------------------------------------------------------------------------

_METRICS_SCRIPT = (
    "echo LOAD:$(cat /proc/loadavg 2>/dev/null | awk '{print $1\",\"$2\",\"$3}');"
    "echo MEM:$(free -b 2>/dev/null | awk 'NR==2{print $2\",\"$3\",\"$4}');"
    "echo SWAP:$(free -b 2>/dev/null | awk 'NR==3{print $2\",\"$3\",\"$4}');"
    "echo UPTIME:$(awk '{print $1}' /proc/uptime 2>/dev/null);"
    "echo HOST:$(hostname -s 2>/dev/null);"
    "echo OS:$(grep PRETTY_NAME /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '\"');"
    "echo PROCS:$(ps aux --no-headers 2>/dev/null | wc -l);"
    "echo CPU:$(grep -m1 'cpu ' /proc/stat | awk '{u=$2+$4; t=$2+$3+$4+$5; if(t>0) printf \"%.1f\", u*100/t; else print 0}');"
    "echo DISKS:$(df -P -B1 2>/dev/null | awk 'NR>1 && $6!=\"\" {gsub(/%/,\"\",$5); printf \"%s|%s|%s|%s|%s|%s;\", $6,$2,$3,$4,$5,$1}' | grep -v 'tmpfs\\|devtmpfs\\|squashfs\\|loop\\|udev\\|sysfs\\|proc' | head -c 2000);"
    "echo NETIO:$(awk 'NR>2 && $1!~/lo:/{gsub(/:/,\"\",$1); printf \"%s|%s|%s;\", $1,$2,$10}' /proc/net/dev 2>/dev/null | head -c 500)"
)


def _parse_metrics_output(out: str) -> dict:
    result: dict[str, Any] = {}
    for line in out.splitlines():
        if ":" not in line:
            continue
        key, _, val = line.partition(":")
        key = key.strip(); val = val.strip()
        if key == "LOAD":
            parts = val.split(",")
            result["load_avg"] = {"1m": _safe_float(parts, 0), "5m": _safe_float(parts, 1), "15m": _safe_float(parts, 2)}
        elif key == "MEM":
            parts = val.split(",")
            total = _safe_int(parts, 0); used = _safe_int(parts, 1); free = _safe_int(parts, 2)
            result["memory"] = {
                "total_gb": round(total / 1e9, 2),
                "used_gb":  round(used  / 1e9, 2),
                "free_gb":  round(free  / 1e9, 2),
                "percent":  round(used / total * 100, 1) if total else 0,
            }
        elif key == "SWAP":
            parts = val.split(",")
            total = _safe_int(parts, 0); used = _safe_int(parts, 1)
            if total > 0:
                result["swap"] = {
                    "total_gb": round(total / 1e9, 2),
                    "used_gb":  round(used  / 1e9, 2),
                    "percent":  round(used / total * 100, 1),
                }
        elif key == "DISKS":
            disks = []
            for entry in val.split(";"):
                entry = entry.strip()
                if not entry:
                    continue
                parts = entry.split("|")
                if len(parts) < 5:
                    continue
                mount = parts[0]; size_b = _safe_int(parts, 1)
                used_b = _safe_int(parts, 2); avail_b = _safe_int(parts, 3)
                pct = _safe_float(parts, 4); fstype = parts[5] if len(parts) > 5 else ""
                disks.append({
                    "mountpoint": mount,
                    "total_gb":   round(size_b  / 1e9, 2),
                    "used_gb":    round(used_b  / 1e9, 2),
                    "free_gb":    round(avail_b / 1e9, 2),
                    "percent":    pct,
                    "fstype":     fstype,
                })
            if disks:
                result["disks"] = disks
                root = next((d for d in disks if d["mountpoint"] == "/"), disks[0])
                result["disk"] = {k: root[k] for k in ("total_gb", "used_gb", "free_gb", "percent")}
        elif key == "NETIO":
            ifaces = []
            for entry in val.split(";"):
                entry = entry.strip()
                if not entry:
                    continue
                parts = entry.split("|")
                if len(parts) < 3:
                    continue
                ifaces.append({"iface": parts[0], "bytes_rx": _safe_int(parts, 1), "bytes_tx": _safe_int(parts, 2)})
            if ifaces:
                result["network_io"] = ifaces
        elif key == "UPTIME":
            secs = _safe_float([val], 0)
            result["uptime_secs"] = secs
            result["uptime"] = _fmt_uptime(secs)
        elif key == "HOST":
            result["hostname_live"] = val
        elif key == "OS":
            result["os_live"] = val
        elif key == "PROCS":
            result["process_count"] = _safe_int([val], 0)
        elif key == "CPU":
            result["cpu_percent"] = _safe_float([val], 0)
    return result


def _local_metrics() -> dict:
    out, _, rc = _run(["bash", "-c", _METRICS_SCRIPT], timeout=20)
    if rc != 0:
        return {}
    return _parse_metrics_output(out)


def _local_services() -> list[dict]:
    cmd = (
        "systemctl list-units --type=service --state=running "
        "--no-pager --plain 2>/dev/null | head -40 | awk '{print $1}'"
    )
    out, _, rc = _run(["bash", "-c", cmd], timeout=12)
    if rc != 0:
        return []
    return [{"name": ln.strip()} for ln in out.splitlines() if ln.strip().endswith(".service")]


def _local_ports() -> list[dict]:
    cmd = "ss -tlnp 2>/dev/null | awk 'NR>1 {print $4}' | head -30"
    out, _, rc = _run(["bash", "-c", cmd], timeout=10)
    if rc != 0:
        return []
    ports = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        _, _, port = line.rpartition(":")
        if port.isdigit():
            ports.append({"port": port, "address": line})
    return ports


def _nginx_server_blocks(text: str) -> list[str]:
    """Extract each top-level server { } block from an Nginx config via brace counting."""
    blocks: list[str] = []
    depth = 0
    in_server = False
    current: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not in_server:
            if re.match(r"^server\s*\{", stripped):
                in_server = True
                depth = stripped.count("{") - stripped.count("}")
                current = [line]
        else:
            current.append(line)
            depth += stripped.count("{") - stripped.count("}")
            if depth <= 0:
                blocks.append("\n".join(current))
                in_server = False
                current = []
    return blocks


def _local_vhosts() -> list[dict]:
    """Parse Apache and Nginx virtual host configs from system conf dirs directly."""
    vhosts: list[dict] = []

    # ── Apache: /etc/apache2/sites-enabled/*.conf ──────────────────────────────
    apache_dir = Path("/etc/apache2/sites-enabled")
    if apache_dir.exists():
        for conf_file in sorted(apache_dir.glob("*.conf")):
            try:
                text = conf_file.read_text(errors="replace")
            except OSError:
                continue
            for block_m in re.finditer(
                r"<VirtualHost\s+([^>]+)>(.*?)</VirtualHost>",
                text, re.DOTALL | re.IGNORECASE,
            ):
                vhost_addr = block_m.group(1).strip()
                block = block_m.group(2)
                port_m = re.search(r":(\d+)", vhost_addr.split()[0])
                port = int(port_m.group(1)) if port_m else 80
                sn_m = re.search(r"^\s*ServerName\s+(\S+)", block, re.MULTILINE | re.IGNORECASE)
                domain = sn_m.group(1).strip() if sn_m else None
                if not domain:
                    continue
                ssl = port == 443 or bool(re.search(r"SSLEngine\s+on", block, re.IGNORECASE))
                dr_m = re.search(r"^\s*DocumentRoot\s+(\S+)", block, re.MULTILINE | re.IGNORECASE)
                vhosts.append({
                    "domain": domain, "port": port, "ssl": ssl,
                    "server": "apache",
                    "doc_root": dr_m.group(1).strip() if dr_m else None,
                    "config_file": str(conf_file),
                })

    # ── Nginx: conf.d/*.conf and sites-enabled/*.conf ──────────────────────────
    for nginx_dir in (Path("/etc/nginx/conf.d"), Path("/etc/nginx/sites-enabled")):
        if not nginx_dir.exists():
            continue
        for conf_file in sorted(nginx_dir.glob("*.conf")):
            try:
                text = conf_file.read_text(errors="replace")
            except OSError:
                continue
            for block in _nginx_server_blocks(text):
                # server_name — handles both inline and multi-line (Frappe) format
                sn_m = re.search(r"server_name\s+(.*?)\s*;", block, re.DOTALL | re.IGNORECASE)
                if not sn_m:
                    continue
                names = sn_m.group(1).split()
                domain = next((n for n in names if n and not n.startswith("$") and n != "_"), None)
                if not domain:
                    continue
                port = 80
                ssl = False
                for lm in re.finditer(r"listen\s+([^;]+);", block, re.IGNORECASE):
                    lv = lm.group(1).strip()
                    if "ssl" in lv:
                        ssl = True
                    # port from IP:PORT / [IPv6]:PORT, or bare PORT
                    pm = re.search(r":(\d+)(?:\s|$)", lv) or re.search(r"^(\d+)(?:\s|$)", lv)
                    if pm:
                        port = int(pm.group(1))
                if port == 443:
                    ssl = True
                dr_m = re.search(r"^\s*root\s+(\S+)\s*;", block, re.MULTILINE | re.IGNORECASE)
                vhosts.append({
                    "domain": domain, "port": port, "ssl": ssl,
                    "server": "nginx",
                    "doc_root": dr_m.group(1).strip() if dr_m else None,
                    "config_file": str(conf_file),
                })

    # Deduplicate by domain+port
    seen: set[tuple] = set()
    unique: list[dict] = []
    for v in vhosts:
        key_t = (v["domain"], v["port"])
        if key_t not in seen:
            seen.add(key_t)
            unique.append(v)
    return sorted(unique, key=lambda v: (v["domain"], v["port"]))


# ---------------------------------------------------------------------------
# libvirt helpers
# ---------------------------------------------------------------------------

def _virsh_state(server: dict) -> str:
    """Get VM state from virsh: running, shut off, paused, etc."""
    name = server.get("libvirt_name", "")
    if not name:
        return "unknown"
    out = _run_out(["virsh", "domstate", name], timeout=8)
    return out.lower() or "unknown"


def _virsh_metrics(server: dict) -> dict:
    name = server.get("libvirt_name", "")
    if not name:
        return {}
    out = _run_out(["virsh", "dominfo", name], timeout=8)
    result: dict[str, Any] = {}
    for line in out.splitlines():
        if ":" in line:
            k, _, v = line.partition(":")
            k = k.strip(); v = v.strip()
            if k == "Max memory":
                result["memory_max_kb"] = _safe_int([v.split()[0]], 0)
            elif k == "Used memory":
                result["memory_used_kb"] = _safe_int([v.split()[0]], 0)
            elif k == "CPU(s)":
                result["vcpus"] = _safe_int([v], 0)
    mem_max = result.get("memory_max_kb", 0)
    mem_used = result.get("memory_used_kb", 0)
    if mem_max:
        result["memory"] = {
            "total_gb":  round(mem_max  / 1e6, 2),
            "used_gb":   round(mem_used / 1e6, 2),
            "percent":   round(mem_used / mem_max * 100, 1) if mem_max else 0,
        }
    return result


# ---------------------------------------------------------------------------
# Parsing utils
# ---------------------------------------------------------------------------

def _safe_float(parts: list[str], idx: int) -> float:
    try:
        return float(parts[idx])
    except (IndexError, ValueError):
        return 0.0


def _safe_int(parts: list[str], idx: int) -> int:
    try:
        return int(parts[idx])
    except (IndexError, ValueError):
        return 0


def _fmt_uptime(secs: float) -> str:
    s = int(secs)
    days, s = divmod(s, 86400)
    hours, s = divmod(s, 3600)
    mins, _  = divmod(s, 60)
    parts = []
    if days:  parts.append(f"{days}d")
    if hours: parts.append(f"{hours}h")
    parts.append(f"{mins}m")
    return " ".join(parts) or "0m"


# ---------------------------------------------------------------------------
# Server action execution (whitelisted)
# ---------------------------------------------------------------------------

_SSH_ACTIONS: dict[str, list[str]] = {
    "restart": ["sudo", "reboot"],
    "stop":    ["sudo", "poweroff"],
}

_VIRSH_ACTIONS: dict[str, str] = {
    "start":   "start",
    "stop":    "shutdown",
    "restart": "reboot",
}


def _execute_action(server: dict, action: str, user: str) -> dict:
    stype  = server.get("type", "ssh")
    sid    = server["id"]
    sname  = server.get("display_name", server.get("hostname", sid))

    if stype == "libvirt":
        virsh_cmd = _VIRSH_ACTIONS.get(action)
        if not virsh_cmd:
            raise HTTPException(status_code=400, detail=f"Action {action!r} not supported for libvirt servers")
        name = server.get("libvirt_name", "")
        if not name:
            raise HTTPException(status_code=400, detail="libvirt_name not configured for this server")
        out, err, rc = _run(["virsh", virsh_cmd, name], timeout=30)
        result = "ok" if rc == 0 else "error"
        _audit(user, f"virsh_{action}", sid, sname, result)
        if rc != 0:
            raise HTTPException(status_code=500, detail=err.strip() or f"virsh {virsh_cmd} {name} failed")
        return {"ok": True, "server": sname, "action": action, "output": out.strip(),
                "executed_at": datetime.now(UTC).isoformat()}

    else:  # ssh
        if action == "start":
            raise HTTPException(status_code=400, detail="Start is not available for SSH servers — server must be powered on externally")
        cmd_parts = _SSH_ACTIONS.get(action)
        if not cmd_parts:
            raise HTTPException(status_code=400, detail=f"Action {action!r} not supported for SSH servers")
        full_cmd = _ssh_base(server) + cmd_parts
        out, err, rc = _run(full_cmd, timeout=20)
        # SSH to a rebooting server may return non-zero; check if action was initiated
        result = "ok" if rc in (0, 255) else "error"
        _audit(user, f"ssh_{action}", sid, sname, result)
        if rc not in (0, 255):
            raise HTTPException(status_code=500, detail=err.strip() or f"SSH action {action} failed (rc={rc})")
        return {"ok": True, "server": sname, "action": action,
                "note": "Command sent — server may be unreachable briefly during restart" if action == "restart" else None,
                "executed_at": datetime.now(UTC).isoformat()}


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class AddServerRequest(BaseModel):
    display_name: str
    hostname: str
    ip: str
    type: str = "ssh"           # "ssh" | "libvirt"
    provider: str = ""
    os: str = ""
    ssh_user: str = "root"
    ssh_port: int = 22
    ssh_key: str = "/root/.ssh/id_rsa"
    libvirt_name: str = ""
    tags: list[str] = []
    notes: str = ""


class ServerActionRequest(BaseModel):
    action: str   # "start" | "stop" | "restart"


# ---------------------------------------------------------------------------
# Vhost management helpers (local server only)
# ---------------------------------------------------------------------------

BACKUP_DIR = Path("/var/lib/mc3/vhost-backups")
APACHE_SITES_AVAIL = Path("/etc/apache2/sites-available")
APACHE_SITES_ENABLED = Path("/etc/apache2/sites-enabled")
NGINX_SITES_AVAIL = Path("/etc/nginx/sites-available")
NGINX_SITES_ENABLED = Path("/etc/nginx/sites-enabled")


def _parse_cert_output(out: str, cert_path: str | None = None) -> dict:
    result: dict[str, Any] = {}
    if cert_path:
        result["cert_path"] = cert_path
    for line in out.splitlines():
        if line.startswith("notAfter="):
            result["expires"] = line.split("=", 1)[1].strip()
        elif line.startswith("issuer="):
            result["issuer"] = line.split("=", 1)[1].strip()
        elif line.startswith("subject="):
            result["subject"] = line.split("=", 1)[1].strip()
    return result


def _ssl_cert_info(domain: str) -> dict:
    """Return SSL cert expiry and issuer. Tries cert files first, falls back to live TLS probe."""
    cert_paths = [
        Path(f"/etc/letsencrypt/live/{domain}/cert.pem"),
        Path(f"/etc/ssl/certs/{domain}.pem"),
    ]
    for cert_path in cert_paths:
        try:
            exists = cert_path.exists()
        except OSError:
            # /etc/letsencrypt/live/ is root-only readable — skip silently
            continue
        if not exists:
            continue
        try:
            out = _run_out(
                ["openssl", "x509", "-in", str(cert_path), "-noout",
                 "-enddate", "-issuer", "-subject"],
                timeout=5,
            )
            result = _parse_cert_output(out, str(cert_path))
            if result.get("expires"):
                return result
        except Exception:
            pass

    # Fall back: probe the live TLS connection (no file permissions needed)
    try:
        proc = subprocess.run(
            ["bash", "-c",
             f"echo | openssl s_client -connect {domain}:443 -servername {domain} 2>/dev/null"
             " | openssl x509 -noout -enddate -issuer -subject 2>/dev/null"],
            capture_output=True, timeout=8,
        )
        if proc.returncode == 0 and proc.stdout:
            result = _parse_cert_output(proc.stdout.decode())
            if result.get("expires"):
                return result
    except Exception:
        pass

    return {}


def _vhost_is_enabled(domain: str, port: int, server_type: str) -> bool:
    """Return True if the vhost config is in the enabled symlinks/dir."""
    if server_type == "apache":
        enabled_dir = APACHE_SITES_ENABLED
        avail_dir = APACHE_SITES_AVAIL
        candidates = [
            f"{domain}.conf",
            f"{domain}-le-ssl.conf" if port == 443 else None,
            f"{domain}-ssl.conf" if port == 443 else None,
        ]
    else:
        enabled_dir = NGINX_SITES_ENABLED
        avail_dir = NGINX_SITES_AVAIL
        candidates = [f"{domain}.conf"]

    for name in filter(None, candidates):
        if (enabled_dir / name).exists() or (avail_dir / name).exists():
            return (enabled_dir / name).exists()
    # fall back: conf_file in sites-enabled means enabled
    return False


def _read_vhost_config(config_file: str) -> str:
    """Read the raw config file. Readable as frothiq (world-readable)."""
    try:
        return Path(config_file).read_text(errors="replace")
    except OSError as exc:
        raise HTTPException(status_code=404, detail=f"Config file not found: {exc}") from exc


def _toggle_apache_vhost(domain: str, port: int, enable: bool) -> dict:
    """Enable or disable an Apache vhost via a2ensite/a2dissite."""
    # Determine config stem
    candidates = [domain]
    if port == 443:
        candidates += [f"{domain}-le-ssl", f"{domain}-ssl"]
    for stem in candidates:
        conf = APACHE_SITES_AVAIL / f"{stem}.conf"
        if conf.exists():
            cmd = "a2ensite" if enable else "a2dissite"
            _, stderr, rc = _run(["sudo", f"/usr/sbin/{cmd}", f"{stem}.conf"], timeout=15)
            if rc != 0:
                raise HTTPException(status_code=500, detail=f"{cmd} failed: {stderr.strip()}")
            _run(["sudo", "/bin/systemctl", "reload", "apache2"], timeout=15)
            return {"toggled": True, "stem": stem, "enabled": enable}
    raise HTTPException(status_code=404, detail=f"No Apache config found for {domain}")


def _toggle_nginx_vhost(domain: str, enable: bool) -> dict:
    """Enable or disable an Nginx vhost via sudo ln/rm (sites-enabled is root-owned)."""
    avail = NGINX_SITES_AVAIL / f"{domain}.conf"
    enabled_link = NGINX_SITES_ENABLED / f"{domain}.conf"
    if not avail.exists():
        raise HTTPException(status_code=404, detail=f"No Nginx config found for {domain} in sites-available")
    if enable:
        _, stderr, rc = _run(
            ["sudo", "/bin/ln", "-sf", str(avail), str(enabled_link)], timeout=10
        )
        if rc != 0:
            raise HTTPException(status_code=500, detail=f"ln failed: {stderr.strip()}")
    else:
        _, stderr, rc = _run(
            ["sudo", "/bin/rm", "-f", str(enabled_link)], timeout=10
        )
        if rc != 0:
            raise HTTPException(status_code=500, detail=f"rm failed: {stderr.strip()}")
    _, stderr, rc = _run(["sudo", "/bin/systemctl", "reload", "nginx"], timeout=15)
    if rc != 0:
        raise HTTPException(status_code=500, detail=f"nginx reload failed: {stderr.strip()}")
    return {"toggled": True, "domain": domain, "enabled": enable}


def _write_vhost_config(config_file: str, content: str, server_type: str) -> None:
    """Write vhost config via sudo tee (frothiq can't write /etc/apache2 directly)."""
    path = Path(config_file)
    # Only allow writes to sites-available
    if server_type == "apache":
        allowed_dir = APACHE_SITES_AVAIL
    else:
        allowed_dir = NGINX_SITES_AVAIL
    if path.parent.resolve() != allowed_dir.resolve():
        raise HTTPException(status_code=400, detail="Config writes allowed only to sites-available")
    # Write via sudo tee
    proc = subprocess.run(
        ["sudo", "/usr/bin/tee", str(path)],
        input=content.encode(),
        capture_output=True,
        timeout=10,
    )
    if proc.returncode != 0:
        raise HTTPException(status_code=500, detail=f"tee failed: {proc.stderr.decode().strip()}")
    # Test config
    if server_type == "nginx":
        _, stderr, rc = _run(["sudo", "/usr/sbin/nginx", "-t"], timeout=10)
        if rc != 0:
            raise HTTPException(status_code=422, detail=f"Nginx config test failed: {stderr.strip()}")
    elif server_type == "apache":
        _, stderr, rc = _run(["apachectl", "configtest"], timeout=10)
        if rc != 0:
            raise HTTPException(status_code=422, detail=f"Apache config test failed: {stderr.strip()}")


def _backup_vhost(domain: str, port: int, server_type: str, config_file: str) -> dict:
    """Snapshot the config file (and optionally docroot) to the backup dir."""
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    stem = f"{domain}-{port}-{server_type}-{ts}"
    dest = BACKUP_DIR / f"{stem}.conf"
    try:
        import shutil
        shutil.copy2(config_file, dest)
    except OSError as exc:
        raise HTTPException(status_code=500, detail=f"Backup failed: {exc}") from exc
    return {
        "backup_file": str(dest),
        "timestamp": ts,
        "domain": domain,
        "port": port,
        "server_type": server_type,
        "source": config_file,
    }


def _list_backups(domain: str | None = None) -> list[dict]:
    """List vhost backups, optionally filtered by domain."""
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    results = []
    for f in sorted(BACKUP_DIR.glob("*.conf"), reverse=True):
        parts = f.stem.split("-")
        if len(parts) < 4:
            continue
        # stem format: domain-port-server_type-YYYYMMDD-HHMMSS
        # domain may contain hyphens, so parse from the right
        ts_time = parts[-1]
        ts_date = parts[-2]
        stype = parts[-3]
        port_str = parts[-4]
        d = "-".join(parts[:-4])
        if domain and d != domain:
            continue
        try:
            port = int(port_str)
        except ValueError:
            port = 0
        results.append({
            "backup_file": str(f),
            "domain": d,
            "port": port,
            "server_type": stype,
            "timestamp": f"{ts_date}-{ts_time}",
            "size_bytes": f.stat().st_size,
        })
    return results


def _restore_vhost(backup_file: str) -> dict:
    """Restore a vhost config from a backup file."""
    src = Path(backup_file)
    if not src.exists() or src.parent.resolve() != BACKUP_DIR.resolve():
        raise HTTPException(status_code=404, detail="Backup file not found")
    # Parse stem to determine target
    parts = src.stem.split("-")
    if len(parts) < 4:
        raise HTTPException(status_code=400, detail="Cannot parse backup filename")
    stype = parts[-3]
    port_str = parts[-4]
    domain = "-".join(parts[:-4])
    try:
        port = int(port_str)
    except ValueError:
        port = 0
    if stype == "apache":
        stem = domain if port != 443 else f"{domain}-le-ssl"
        target = APACHE_SITES_AVAIL / f"{stem}.conf"
    else:
        target = NGINX_SITES_AVAIL / f"{domain}.conf"
    # Write via sudo tee
    content = src.read_bytes()
    proc = subprocess.run(
        ["sudo", "/usr/bin/tee", str(target)],
        input=content,
        capture_output=True,
        timeout=10,
    )
    if proc.returncode != 0:
        raise HTTPException(status_code=500, detail=f"Restore failed: {proc.stderr.decode().strip()}")
    return {"restored": True, "target": str(target), "from_backup": str(src)}


# ---------------------------------------------------------------------------
_DOMAIN_RE = re.compile(r'^(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$')

_APACHE_VHOST_TEMPLATE = """\
<VirtualHost *:80>
    ServerName {domain}
    DocumentRoot {doc_root}
    ErrorLog ${{APACHE_LOG_DIR}}/{domain}-error.log
    CustomLog ${{APACHE_LOG_DIR}}/{domain}-access.log combined
    <Directory {doc_root}>
        Options Indexes FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>
</VirtualHost>
"""

_NGINX_VHOST_TEMPLATE = """\
server {{
    listen 80;
    listen [::]:80;
    server_name {domain};
    root {doc_root};
    index index.html index.htm;

    location / {{
        try_files $uri $uri/ =404;
    }}

    access_log /var/log/nginx/{domain}-access.log;
    error_log  /var/log/nginx/{domain}-error.log;
}}
"""


def _deploy_vhost(domain: str, server_type: str, doc_root: str) -> dict:
    """Create docroot, write config, enable vhost. Returns detail dict."""
    if not _DOMAIN_RE.match(domain):
        raise HTTPException(status_code=400, detail=f"Invalid domain name: {domain!r}")
    if server_type not in ("apache", "nginx"):
        raise HTTPException(status_code=400, detail="server_type must be 'apache' or 'nginx'")

    # Create document root
    _, stderr, rc = _run(["sudo", "/bin/mkdir", "-p", doc_root], timeout=10)
    if rc != 0:
        raise HTTPException(status_code=500, detail=f"mkdir failed: {stderr.strip()}")
    _run(["sudo", "/bin/chown", "-R", "www-data", doc_root], timeout=10)

    if server_type == "apache":
        config = _APACHE_VHOST_TEMPLATE.format(domain=domain, doc_root=doc_root)
        conf_path = APACHE_SITES_AVAIL / f"{domain}.conf"
        proc = subprocess.run(
            ["sudo", "/usr/bin/tee", str(conf_path)],
            input=config.encode(), capture_output=True, timeout=10,
        )
        if proc.returncode != 0:
            raise HTTPException(status_code=500, detail=f"Write failed: {proc.stderr.decode().strip()}")
        _, stderr, rc = _run(["sudo", "/usr/sbin/a2ensite", f"{domain}.conf"], timeout=15)
        if rc != 0:
            raise HTTPException(status_code=500, detail=f"a2ensite failed: {stderr.strip()}")
        _run(["sudo", "/bin/systemctl", "reload", "apache2"], timeout=15)
    else:
        config = _NGINX_VHOST_TEMPLATE.format(domain=domain, doc_root=doc_root)
        conf_path = NGINX_SITES_AVAIL / f"{domain}.conf"
        proc = subprocess.run(
            ["sudo", "/usr/bin/tee", str(conf_path)],
            input=config.encode(), capture_output=True, timeout=10,
        )
        if proc.returncode != 0:
            raise HTTPException(status_code=500, detail=f"Write failed: {proc.stderr.decode().strip()}")
        enabled_link = NGINX_SITES_ENABLED / f"{domain}.conf"
        _run(["sudo", "/bin/ln", "-sf", str(conf_path), str(enabled_link)], timeout=10)
        _, stderr, rc = _run(["sudo", "/bin/systemctl", "reload", "nginx"], timeout=15)
        if rc != 0:
            raise HTTPException(status_code=500, detail=f"nginx reload failed: {stderr.strip()}")

    return {
        "deployed": True,
        "domain": domain,
        "server_type": server_type,
        "doc_root": doc_root,
        "config_file": str(conf_path),
    }


# Vhost management Pydantic models
# ---------------------------------------------------------------------------

class VhostToggleRequest(BaseModel):
    domain: str
    port: int
    server_type: str
    enable: bool


class VhostConfigSaveRequest(BaseModel):
    config_file: str
    content: str
    server_type: str


class VhostBackupRequest(BaseModel):
    domain: str
    port: int
    server_type: str
    config_file: str


class VhostRestoreRequest(BaseModel):
    backup_file: str


class VhostDeployRequest(BaseModel):
    domain: str
    server_type: str = "apache"
    doc_root: str = ""


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/servers")
async def list_servers(_: str = Depends(require_super_admin)) -> dict:
    servers = _load_registry()
    return {"servers": servers, "count": len(servers), "checked_at": datetime.now(UTC).isoformat()}


@router.post("/servers")
async def add_server(body: AddServerRequest, user: str = Depends(require_super_admin)) -> dict:
    if body.type not in ("ssh", "libvirt"):
        raise HTTPException(status_code=400, detail="type must be 'ssh' or 'libvirt'")
    # Basic IP validation
    if not re.match(r"^[\w.\-:]+$", body.ip):
        raise HTTPException(status_code=400, detail="Invalid IP/hostname")
    if body.ssh_port < 1 or body.ssh_port > 65535:
        raise HTTPException(status_code=400, detail="Invalid SSH port")

    servers = _load_registry()
    # Prevent duplicate IPs
    for s in servers:
        if s.get("ip") == body.ip and s.get("type") == body.type:
            raise HTTPException(status_code=409, detail=f"Server with IP {body.ip!r} already exists")

    entry = {
        "id": str(uuid.uuid4()),
        "display_name": body.display_name,
        "hostname": body.hostname,
        "ip": body.ip,
        "type": body.type,
        "provider": body.provider,
        "os": body.os,
        "ssh_user": body.ssh_user,
        "ssh_port": body.ssh_port,
        "ssh_key": body.ssh_key,
        "libvirt_name": body.libvirt_name,
        "tags": body.tags,
        "notes": body.notes,
        "added_at": datetime.now(UTC).isoformat(),
        "added_by": user,
    }
    servers.append(entry)
    _save_registry(servers)
    _audit(user, "add_server", entry["id"], body.display_name, "ok")
    return {"ok": True, "server": entry}


@router.delete("/servers/{server_id}")
async def remove_server(server_id: str, user: str = Depends(require_super_admin)) -> dict:
    servers = _load_registry()
    orig_count = len(servers)
    servers = [s for s in servers if s.get("id") != server_id]
    if len(servers) == orig_count:
        raise HTTPException(status_code=404, detail="Server not found")
    _save_registry(servers)
    _audit(user, "remove_server", server_id, "", "ok")
    return {"ok": True, "removed": server_id}


@router.get("/servers/{server_id}/status")
async def server_status(server_id: str, _: str = Depends(require_super_admin)) -> dict:
    server = _find_server(server_id)
    stype  = server.get("type", "ssh")
    result: dict[str, Any] = {
        "id": server["id"],
        "display_name": server.get("display_name", ""),
        "ip": server["ip"],
        "type": stype,
        "checked_at": datetime.now(UTC).isoformat(),
    }

    if stype == "local":
        result["ping"]    = {"reachable": True, "latency_ms": 0, "packet_loss": "0%"}
        result["ssh"]     = {"reachable": None}
        result["is_up"]   = True
        result["state"]   = "running"
        result["metrics"] = _local_metrics()
        result["services"]= _local_services()
        result["ports"]   = _local_ports()
        return result

    # Ping check
    result["ping"] = _ping_check(server["ip"])

    if stype == "libvirt":
        state = _virsh_state(server)
        result["state"]   = state
        result["is_up"]   = state == "running"
        result["metrics"] = _virsh_metrics(server) if state == "running" else {}
        result["ssh"]     = {"reachable": None}   # ssh not primary for libvirt

    else:  # ssh
        ssh = _ssh_check(server)
        result["ssh"]   = ssh
        result["is_up"] = ssh["reachable"]
        result["state"] = "running" if ssh["reachable"] else "unreachable"
        if ssh["reachable"]:
            result["metrics"]  = _ssh_metrics(server)
            result["services"] = _ssh_services(server)
            result["ports"]    = _ssh_ports(server)
        else:
            result["metrics"]  = {}
            result["services"] = []
            result["ports"]    = []

    return result


@router.get("/servers/{server_id}/vhosts")
async def server_vhosts(server_id: str, _: str = Depends(require_super_admin)) -> dict:
    """Return virtual host configurations scraped from the server."""
    server = _find_server(server_id)
    stype = server.get("type")

    if stype == "local":
        vhosts = _local_vhosts()
        return {
            "vhosts": vhosts,
            "web_servers": list({v["server"] for v in vhosts}),
            "count": len(vhosts),
            "checked_at": datetime.now(UTC).isoformat(),
        }

    if stype != "ssh":
        return {"vhosts": [], "web_servers": [], "note": "vhost scraping only available for SSH and local servers",
                "checked_at": datetime.now(UTC).isoformat()}
    ssh = _ssh_check(server)
    if not ssh["reachable"]:
        raise HTTPException(status_code=503, detail="Server is not reachable via SSH")
    vhosts = _ssh_vhosts(server)
    web_servers = list({v["server"] for v in vhosts})
    return {
        "vhosts": vhosts,
        "web_servers": web_servers,
        "count": len(vhosts),
        "checked_at": datetime.now(UTC).isoformat(),
    }


@router.post("/servers/{server_id}/action")
async def server_action(
    server_id: str,
    body: ServerActionRequest,
    user: str = Depends(require_super_admin),
) -> dict:
    if body.action not in ("start", "stop", "restart"):
        raise HTTPException(status_code=400, detail="action must be 'start', 'stop', or 'restart'")
    server = _find_server(server_id)
    if server.get("type") == "local":
        raise HTTPException(status_code=400, detail="Power actions are not available for the local server")
    return _execute_action(server, body.action, user)


# ---------------------------------------------------------------------------
# Vhost management endpoints
# ---------------------------------------------------------------------------

@router.get("/vhosts/detail")
async def vhost_detail(
    domain: str,
    port: int,
    server_type: str,
    config_file: str,
    _: str = Depends(require_super_admin),
) -> dict:
    """Return full detail for a single vhost: config content, SSL info, enabled status."""
    config_content = _read_vhost_config(config_file)
    try:
        ssl_info = _ssl_cert_info(domain) if (port == 443 or "ssl" in config_content.lower()) else {}
    except Exception:
        ssl_info = {}
    try:
        enabled = _vhost_is_enabled(domain, port, server_type)
    except Exception:
        enabled = False
    try:
        backups = _list_backups(domain)
    except Exception:
        backups = []
    return {
        "domain": domain,
        "port": port,
        "server_type": server_type,
        "config_file": config_file,
        "config_content": config_content,
        "enabled": enabled,
        "ssl": ssl_info,
        "backups": backups,
        "checked_at": datetime.now(UTC).isoformat(),
    }


@router.post("/vhosts/toggle")
async def vhost_toggle(
    body: VhostToggleRequest,
    user: str = Depends(require_super_admin),
) -> dict:
    """Enable or disable a vhost."""
    _audit(user, "vhost_toggle", "local", f"{body.domain}:{body.port} enable={body.enable}", "started")
    if body.server_type == "apache":
        result = _toggle_apache_vhost(body.domain, body.port, body.enable)
    elif body.server_type == "nginx":
        result = _toggle_nginx_vhost(body.domain, body.enable)
    else:
        raise HTTPException(status_code=400, detail=f"Unknown server type: {body.server_type}")
    _audit(user, "vhost_toggle", "local", f"{body.domain}:{body.port}", "ok")
    return result


@router.post("/vhosts/save-config")
async def vhost_save_config(
    body: VhostConfigSaveRequest,
    user: str = Depends(require_super_admin),
) -> dict:
    """Write an updated config file and reload the web server."""
    _audit(user, "vhost_save_config", "local", body.config_file, "started")
    _write_vhost_config(body.config_file, body.content, body.server_type)
    # Reload the appropriate web server
    if body.server_type == "apache":
        _run(["sudo", "/bin/systemctl", "reload", "apache2"], timeout=15)
    else:
        _run(["sudo", "/bin/systemctl", "reload", "nginx"], timeout=15)
    _audit(user, "vhost_save_config", "local", body.config_file, "ok")
    return {"saved": True, "config_file": body.config_file}


@router.post("/vhosts/backup")
async def vhost_backup(
    body: VhostBackupRequest,
    user: str = Depends(require_super_admin),
) -> dict:
    """Create a timestamped backup of a vhost config."""
    _audit(user, "vhost_backup", "local", f"{body.domain}:{body.port}", "started")
    result = _backup_vhost(body.domain, body.port, body.server_type, body.config_file)
    _audit(user, "vhost_backup", "local", body.config_file, "ok")
    return result


@router.get("/vhosts/backups")
async def list_vhost_backups(
    domain: str | None = None,
    _: str = Depends(require_super_admin),
) -> dict:
    """List all vhost backups, optionally filtered by domain."""
    backups = _list_backups(domain)
    return {"backups": backups, "count": len(backups)}


@router.post("/vhosts/restore")
async def vhost_restore(
    body: VhostRestoreRequest,
    user: str = Depends(require_super_admin),
) -> dict:
    """Restore a vhost config from a backup file."""
    _audit(user, "vhost_restore", "local", body.backup_file, "started")
    result = _restore_vhost(body.backup_file)
    _audit(user, "vhost_restore", "local", body.backup_file, "ok")
    return result


@router.post("/vhosts/deploy")
async def vhost_deploy(
    body: VhostDeployRequest,
    user: str = Depends(require_super_admin),
) -> dict:
    """Deploy a new domain or subdomain vhost (create docroot + config + enable)."""
    domain = body.domain.strip().lower()
    doc_root = body.doc_root.strip() or f"/var/www/{domain}/public_html"
    _audit(user, "vhost_deploy", "local", f"{domain} ({body.server_type})", "started")
    result = _deploy_vhost(domain, body.server_type, doc_root)
    _audit(user, "vhost_deploy", "local", domain, "ok")
    return result


# ---------------------------------------------------------------------------
# Domain Manager — overview aggregation helpers
# ---------------------------------------------------------------------------

def _domain_emails(domain: str) -> list[dict]:
    """List mail/FTP users for a domain via virtualmin."""
    out = _run_out(["sudo", "/usr/sbin/virtualmin", "list-users", "--domain", domain], timeout=10)
    users = []
    for line in out.splitlines():
        parts = line.split()
        if not parts or parts[0] in ("User", "----"):
            continue
        username = parts[0]
        real_name = parts[1] if len(parts) > 1 else ""
        mail = parts[2].strip().lower() == "yes" if len(parts) > 2 else False
        ftp  = parts[3].strip().lower() != "no"  if len(parts) > 3 else False
        users.append({
            "username": username,
            "real_name": real_name,
            "email": f"{username}@{domain}",
            "mail": mail,
            "ftp": ftp,
        })
    return users


def _domain_databases(domain: str) -> list[dict]:
    """List databases for a domain via virtualmin."""
    out = _run_out(["sudo", "/usr/sbin/virtualmin", "list-databases", "--domain", domain], timeout=10)
    dbs = []
    for line in out.splitlines():
        parts = line.split()
        if not parts or parts[0] in ("Database", "----"):
            continue
        name = parts[0]
        db_type = parts[1] if len(parts) > 1 else "mysql"
        size = parts[2] if len(parts) > 2 else "?"
        dbs.append({"name": name, "type": db_type, "size": size})
    return dbs


def _domain_dns(domain: str) -> dict:
    """Return A, MX, NS, TXT records for a domain via dig."""
    records: dict[str, list[str]] = {}
    for rtype in ("A", "MX", "NS", "TXT"):
        out = _run_out(["dig", "+short", rtype, domain], timeout=5)
        values = [v.strip() for v in out.splitlines() if v.strip()]
        if values:
            records[rtype] = values
    return records


# ---------------------------------------------------------------------------
# Domain Manager endpoint
# ---------------------------------------------------------------------------

@router.get("/domains")
async def list_domains(_: str = Depends(require_super_admin)) -> dict:
    """Return a deduplicated list of apex domains derived from vhost configs."""
    vhosts = _local_vhosts()
    seen: set[str] = set()
    domains = []
    for v in vhosts:
        parts = v["domain"].split(".")
        apex = ".".join(parts[-2:]) if len(parts) >= 2 else v["domain"]
        if apex not in seen:
            seen.add(apex)
            domains.append(apex)
    return {"domains": sorted(domains), "count": len(domains)}


@router.get("/domains/{domain}/overview")
async def domain_overview(domain: str, _: str = Depends(require_super_admin)) -> dict:
    """Comprehensive domain view: vhosts, SSL, email, databases, DNS, subdomains."""
    all_vhosts = _local_vhosts()
    domain_vhosts = [
        v for v in all_vhosts
        if v["domain"] == domain or v["domain"].endswith(f".{domain}")
    ]

    # Deduplicate by (subdomain, port)
    subdomains = sorted({v["domain"] for v in domain_vhosts if v["domain"] != domain})

    try:
        ssl_info = _ssl_cert_info(domain)
    except Exception:
        ssl_info = {}

    try:
        emails = _domain_emails(domain)
    except Exception:
        emails = []

    try:
        databases = _domain_databases(domain)
    except Exception:
        databases = []

    try:
        dns = _domain_dns(domain)
    except Exception:
        dns = {}

    return {
        "domain": domain,
        "vhosts": domain_vhosts,
        "subdomains": subdomains,
        "ssl": ssl_info,
        "emails": emails,
        "databases": databases,
        "dns": dns,
        "checked_at": datetime.now(UTC).isoformat(),
    }


# ---------------------------------------------------------------------------
# DNS zone file management (direct BIND)
# ---------------------------------------------------------------------------

ZONE_DIR = Path("/var/lib/bind")
_DNS_TYPES = {"A", "AAAA", "MX", "NS", "TXT", "CNAME", "CAA", "SRV", "PTR"}
# Record types we display but never let the user add/remove via the editor
_DNS_READONLY_TYPES = {"SOA", "NS"}

# Regex: <name> [<ttl>] IN <type> <value>  (handles both absolute and relative names)
_ZONE_RECORD_RE = re.compile(
    r"^(\S+)\s+"          # name
    r"(?:(\d+)\s+)?"      # optional TTL
    r"IN\s+"              # class
    r"(\S+)\s+"           # type
    r"(.+?)\s*$",         # value
    re.IGNORECASE,
)
_SERIAL_RE = re.compile(r"(\d{10})\s*;?\s*[Ss]erial", re.MULTILINE)
_SERIAL_RE2 = re.compile(r"(\d{8,10})\s*\n\s*\d+\s*\n")  # SOA block style


def _zone_file(domain: str) -> Path:
    return ZONE_DIR / f"{domain}.hosts"


def _read_zone_raw(domain: str) -> str:
    out = _run_out(["sudo", "/bin/cat", str(_zone_file(domain))], timeout=5)
    if not out:
        raise HTTPException(status_code=404, detail=f"Zone file not found for {domain}")
    return out


def _parse_zone(content: str) -> list[dict]:
    """Parse BIND zone file lines into record dicts."""
    records = []
    for line in content.splitlines():
        stripped = line.split(";")[0].strip()  # strip inline comments
        if not stripped:
            continue
        m = _ZONE_RECORD_RE.match(stripped)
        if not m:
            continue
        name, ttl, rtype, value = m.group(1), m.group(2), m.group(3).upper(), m.group(4).strip()
        # Strip surrounding quotes from TXT/SPF values
        if value.startswith('"') and value.endswith('"'):
            value = value[1:-1]
        records.append({
            "name": name,
            "ttl": int(ttl) if ttl else None,
            "type": rtype,
            "value": value,
            "readonly": rtype in _DNS_READONLY_TYPES,
        })
    return records


def _increment_serial(content: str) -> str:
    """Increment the SOA serial. Tries YYYYMMDDnn style; falls back to plain int."""
    today = datetime.now().strftime("%Y%m%d")

    def replacer(m: re.Match) -> str:
        old = m.group(1)
        if len(old) == 10 and old[:8] == today:
            new = str(int(old) + 1)
        elif len(old) >= 8:
            new = today + "01"
        else:
            new = str(int(old) + 1)
        return m.group(0).replace(old, new, 1)

    # Try inline "NNNNNNNNNN ; serial" pattern
    new_content, n = _SERIAL_RE.subn(replacer, content)
    if n:
        return new_content
    # Fallback: first 8–10 digit number inside SOA block
    soa_start = content.find("SOA")
    soa_end = content.find(")", soa_start) + 1 if soa_start != -1 else -1
    if soa_start != -1 and soa_end > soa_start:
        soa_block = content[soa_start:soa_end]
        digits_re = re.compile(r"\b(\d{8,10})\b")
        m2 = digits_re.search(soa_block)
        if m2:
            old = m2.group(1)
            new = today + "01" if old[:8] != today else str(int(old) + 1)
            return content[:soa_start] + soa_block.replace(old, new, 1) + content[soa_end:]
    return content


def _write_zone(domain: str, content: str) -> None:
    """Write zone file via sudo tee, validate with named-checkzone, then reload."""
    zone_path = str(_zone_file(domain))
    proc = subprocess.run(
        ["sudo", "/usr/bin/tee", zone_path],
        input=content.encode(),
        capture_output=True,
        timeout=10,
    )
    if proc.returncode != 0:
        raise HTTPException(status_code=500, detail=f"Write failed: {proc.stderr.decode()}")
    # Validate the zone
    check = _run_out(["sudo", "/usr/sbin/named-checkzone", domain, zone_path], timeout=5)
    if "OK" not in check:
        raise HTTPException(status_code=500, detail=f"Zone validation failed: {check}")
    # Reload BIND for this zone only
    _run_out(["sudo", "/usr/sbin/rndc", "reload", domain], timeout=10)


class DnsAddRequest(BaseModel):
    name: str
    type: str
    value: str
    ttl: int | None = None


class DnsRemoveRequest(BaseModel):
    name: str
    type: str
    value: str


class DnsUpdateRequest(BaseModel):
    old_name: str
    old_type: str
    old_value: str
    name: str
    type: str
    value: str
    ttl: int | None = None


def _canonical_name(name: str, domain: str) -> str:
    """Ensure name is absolute (ends with '.') or is '@'."""
    if name == "@" or name.endswith("."):
        return name
    # If it already contains the domain, make it absolute
    if name.endswith(f".{domain}") or name == domain:
        return name.rstrip(".") + "."
    return name


@router.get("/domains/{domain}/dns")
async def domain_dns_records(domain: str, _: str = Depends(require_super_admin)) -> dict:
    """Return all DNS records by parsing the BIND zone file directly."""
    content = _read_zone_raw(domain)
    records = _parse_zone(content)
    return {"domain": domain, "records": records, "count": len(records)}


@router.post("/domains/{domain}/dns/add")
async def domain_dns_add(domain: str, body: DnsAddRequest, _: str = Depends(require_super_admin)) -> dict:
    """Add a DNS record to the zone file."""
    rtype = body.type.upper()
    if rtype not in _DNS_TYPES:
        raise HTTPException(status_code=400, detail=f"Unsupported record type: {rtype}")
    content = _read_zone_raw(domain)
    content = _increment_serial(content)
    ttl_str = f"\t{body.ttl}" if body.ttl else ""
    value = f'"{body.value}"' if rtype == "TXT" and not body.value.startswith('"') else body.value
    new_line = f"{body.name}{ttl_str}\tIN\t{rtype}\t{value}\n"
    content = content.rstrip("\n") + "\n" + new_line
    _write_zone(domain, content)
    return {"ok": True, "detail": "Record added and zone reloaded"}


@router.post("/domains/{domain}/dns/remove")
async def domain_dns_remove(domain: str, body: DnsRemoveRequest, _: str = Depends(require_super_admin)) -> dict:
    """Remove a DNS record from the zone file."""
    content = _read_zone_raw(domain)
    rtype = body.type.upper()
    new_lines = []
    removed = 0
    for line in content.splitlines(keepends=True):
        stripped = line.split(";")[0].strip()
        m = _ZONE_RECORD_RE.match(stripped)
        if m:
            ln, _, lt, lv = m.group(1), m.group(2), m.group(3).upper(), m.group(4).strip()
            lv_clean = lv.strip('"')
            if ln == body.name and lt == rtype and (lv == body.value or lv_clean == body.value):
                removed += 1
                continue
        new_lines.append(line)
    if not removed:
        raise HTTPException(status_code=404, detail="Record not found in zone file")
    new_content = _increment_serial("".join(new_lines))
    _write_zone(domain, new_content)
    return {"ok": True, "detail": f"Record removed and zone reloaded"}


@router.post("/domains/{domain}/dns/update")
async def domain_dns_update(domain: str, body: DnsUpdateRequest, _: str = Depends(require_super_admin)) -> dict:
    """Update (replace) a DNS record in the zone file."""
    content = _read_zone_raw(domain)
    rtype_old = body.old_type.upper()
    rtype_new = body.type.upper()
    if rtype_new not in _DNS_TYPES:
        raise HTTPException(status_code=400, detail=f"Unsupported record type: {rtype_new}")
    new_lines = []
    updated = 0
    for line in content.splitlines(keepends=True):
        stripped = line.split(";")[0].strip()
        m = _ZONE_RECORD_RE.match(stripped)
        if m and not updated:
            ln, ttl, lt, lv = m.group(1), m.group(2), m.group(3).upper(), m.group(4).strip()
            lv_clean = lv.strip('"')
            if ln == body.old_name and lt == rtype_old and (lv == body.old_value or lv_clean == body.old_value):
                ttl_str = f"\t{body.ttl}" if body.ttl else (f"\t{ttl}" if ttl else "")
                value = f'"{body.value}"' if rtype_new == "TXT" and not body.value.startswith('"') else body.value
                new_lines.append(f"{body.name}{ttl_str}\tIN\t{rtype_new}\t{value}\n")
                updated += 1
                continue
        new_lines.append(line)
    if not updated:
        raise HTTPException(status_code=404, detail="Record not found in zone file")
    new_content = _increment_serial("".join(new_lines))
    _write_zone(domain, new_content)
    return {"ok": True, "detail": "Record updated and zone reloaded"}
