"""
ServOps — per-server detailed data endpoints (super_admin only).
Each handler returns structured data for server-specific UI panels.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException

from .routes_auth import require_super_admin

router = APIRouter(prefix="/sysinfo/servers", tags=["server-detail"])


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _run(cmd: list[str], timeout: int = 10) -> tuple[str, str, int]:
    import subprocess
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout, r.stderr, r.returncode
    except Exception as e:
        return "", str(e), 1


def _out(cmd: list[str], timeout: int = 10) -> str:
    stdout, _, _ = _run(cmd, timeout)
    return stdout


def _extract_braced_blocks(content: str, keyword: str) -> list[str]:
    """Extract all blocks: `keyword ... { ... }` using bracket matching."""
    blocks = []
    pattern = re.compile(rf'\b{re.escape(keyword)}\b[^{{]*\{{')
    pos = 0
    while True:
        m = pattern.search(content, pos)
        if not m:
            break
        start = m.end()
        depth, i = 1, start
        while i < len(content) and depth > 0:
            if content[i] == '{':
                depth += 1
            elif content[i] == '}':
                depth -= 1
            i += 1
        blocks.append(content[start:i - 1])
        pos = m.start() + 1
    return blocks


def _directive(block: str, name: str) -> str | None:
    m = re.search(rf'(?:^|[\s;]){re.escape(name)}\s+([^;{{]+);', block, re.MULTILINE)
    return m.group(1).strip() if m else None


def _directives(block: str, name: str) -> list[str]:
    return [m.group(1).strip() for m in
            re.finditer(rf'(?:^|[\s;]){re.escape(name)}\s+([^;{{]+);', block, re.MULTILINE)]


def _apache_directive(block: str, name: str) -> str | None:
    m = re.search(rf'^\s*{re.escape(name)}\s+(.+)$', block, re.MULTILINE | re.IGNORECASE)
    return m.group(1).strip() if m else None


def _strip_comments(content: str, style: str = "hash") -> str:
    if style == "hash":
        return re.sub(r'#[^\n]*', '', content)
    if style == "c":
        content = re.sub(r'//[^\n]*', '', content)
        content = re.sub(r'/\*.*?\*/', '', content, flags=re.DOTALL)
        return content
    return content


# ---------------------------------------------------------------------------
# Nginx
# ---------------------------------------------------------------------------

def _nginx_detail() -> dict:
    import glob
    vhosts = []
    for pattern in ["/etc/nginx/sites-enabled/*", "/etc/nginx/conf.d/*.conf"]:
        for fpath in sorted(glob.glob(pattern)):
            try:
                raw = Path(fpath).read_text(errors="replace")
                clean = _strip_comments(raw)
                for block in _extract_braced_blocks(clean, "server"):
                    listens = _directives(block, "listen")
                    ports = list({re.search(r'\d+', l).group() for l in listens if re.search(r'\d+', l)})
                    ssl = any("ssl" in l for l in listens) or bool(_directive(block, "ssl_certificate"))
                    vhosts.append({
                        "file": Path(fpath).name,
                        "server_name": _directive(block, "server_name") or "_",
                        "listen": listens,
                        "ports": ports,
                        "ssl": ssl,
                        "root": _directive(block, "root"),
                        "proxy_pass": _directive(block, "proxy_pass"),
                        "return": _directive(block, "return"),
                        "access_log": _directive(block, "access_log"),
                        "error_log": _directive(block, "error_log"),
                    })
            except Exception:
                continue

    # stub_status if available
    stats: dict = {}
    for url in ["http://127.0.0.1/nginx_status", "http://localhost/nginx_status"]:
        out = _out(["curl", "-s", "--max-time", "2", url])
        if "Active connections" in out:
            if m := re.search(r'Active connections:\s*(\d+)', out):
                stats["active_connections"] = int(m.group(1))
            if m := re.search(r'(\d+)\s+(\d+)\s+(\d+)\s*\n', out):
                stats["accepts"] = int(m.group(1))
                stats["handled"] = int(m.group(2))
                stats["requests"] = int(m.group(3))
            if m := re.search(r'Reading:\s*(\d+)\s+Writing:\s*(\d+)\s+Waiting:\s*(\d+)', out):
                stats["reading"] = int(m.group(1))
                stats["writing"] = int(m.group(2))
                stats["waiting"] = int(m.group(3))
            break

    # Worker processes
    workers = _out(["pgrep", "-c", "nginx"])
    if workers.strip().isdigit():
        stats["worker_processes"] = int(workers.strip())

    return {"vhosts": vhosts, "stats": stats}


# ---------------------------------------------------------------------------
# Apache2
# ---------------------------------------------------------------------------

def _apache2_detail() -> dict:
    vhosts = []

    # Parse sites-enabled configs
    sites_dir = Path("/etc/apache2/sites-enabled")
    if sites_dir.is_dir():
        for f in sorted(sites_dir.iterdir()):
            if not f.is_file():
                continue
            try:
                content = f.read_text(errors="replace")
                content_clean = _strip_comments(content)
                for m in re.finditer(r'<VirtualHost\s+([^>]+)>(.*?)</VirtualHost>',
                                     content_clean, re.DOTALL | re.IGNORECASE):
                    addr = m.group(1).strip()
                    block = m.group(2)
                    port = re.search(r':(\d+)', addr)
                    port_num = port.group(1) if port else "80"
                    ssl_engine = _apache_directive(block, "SSLEngine") or ""
                    vhosts.append({
                        "file": f.name,
                        "address": addr,
                        "port": port_num,
                        "server_name": _apache_directive(block, "ServerName") or "_default_",
                        "server_alias": _apache_directive(block, "ServerAlias"),
                        "document_root": _apache_directive(block, "DocumentRoot"),
                        "ssl": port_num == "443" or ssl_engine.lower() == "on",
                        "ssl_cert": _apache_directive(block, "SSLCertificateFile"),
                        "error_log": _apache_directive(block, "ErrorLog"),
                        "custom_log": _apache_directive(block, "CustomLog"),
                        "proxy_pass": _apache_directive(block, "ProxyPass"),
                    })
            except Exception:
                continue

    # apache2ctl -S summary
    ctl_out = _out(["apache2ctl", "-S"], timeout=10)

    # Active connections via server-status if available
    stats: dict = {}
    for url in ["http://127.0.0.1/server-status?auto", "http://localhost/server-status?auto"]:
        out = _out(["curl", "-s", "--max-time", "2", url])
        if "Total Accesses" in out or "BusyWorkers" in out:
            for key, pat in [("total_accesses", r"Total Accesses:\s*(\d+)"),
                              ("busy_workers", r"BusyWorkers:\s*(\d+)"),
                              ("idle_workers", r"IdleWorkers:\s*(\d+)"),
                              ("requests_per_sec", r"ReqPerSec:\s*([\d.]+)")]:
                if mm := re.search(pat, out):
                    stats[key] = float(mm.group(1)) if "." in mm.group(1) else int(mm.group(1))
            break

    workers = _out(["pgrep", "-c", "apache2"])
    if workers.strip().isdigit():
        stats["worker_processes"] = int(workers.strip())

    return {"vhosts": vhosts, "stats": stats, "ctl_summary": ctl_out[:3000]}


# ---------------------------------------------------------------------------
# MySQL / MariaDB
# ---------------------------------------------------------------------------

def _mysql_query(sql: str, timeout: int = 5) -> str:
    for cmd in [
        ["mysql", "--no-defaults", "-N", "-B", "-e", sql],
        ["mariadb", "--no-defaults", "-N", "-B", "-e", sql],
        ["sudo", "mysql", "-N", "-B", "-e", sql],
    ]:
        out, err, rc = _run(cmd, timeout)
        if rc == 0 and "Access denied" not in err:
            return out
    return ""


def _mysql_detail() -> dict:
    # Databases
    dbs_raw = _mysql_query("SHOW DATABASES;")
    system_dbs = {"information_schema", "performance_schema", "sys", "mysql"}
    all_dbs = [l.strip() for l in dbs_raw.splitlines() if l.strip()]
    user_dbs = [d for d in all_dbs if d not in system_dbs]

    # Users
    users_raw = _mysql_query(
        "SELECT User, Host, IF(authentication_string != '' OR plugin IN ('auth_socket','unix_socket'),'yes','no') "
        "AS has_auth FROM mysql.user ORDER BY User;"
    )
    users = []
    for line in users_raw.splitlines():
        parts = line.strip().split('\t')
        if len(parts) >= 2:
            users.append({"user": parts[0], "host": parts[1],
                          "has_auth": parts[2] == "yes" if len(parts) > 2 else True})

    # Key variables
    var_names = ("max_connections", "max_allowed_packet", "innodb_buffer_pool_size",
                 "character_set_server", "version", "datadir", "port",
                 "bind_address", "log_bin", "slow_query_log", "query_cache_type",
                 "innodb_file_per_table", "default_storage_engine")
    vars_raw = _mysql_query(
        f"SHOW VARIABLES WHERE Variable_name IN ({','.join(repr(v) for v in var_names)});"
    )
    variables: dict[str, str] = {}
    for line in vars_raw.splitlines():
        parts = line.strip().split('\t')
        if len(parts) == 2:
            variables[parts[0]] = parts[1]

    # Status counters
    stat_names = ("Connections", "Threads_connected", "Threads_running",
                  "Questions", "Uptime", "Com_select", "Com_insert",
                  "Com_update", "Com_delete", "Bytes_received", "Bytes_sent",
                  "Innodb_buffer_pool_reads", "Innodb_buffer_pool_read_requests")
    status_raw = _mysql_query(
        f"SHOW GLOBAL STATUS WHERE Variable_name IN ({','.join(repr(v) for v in stat_names)});"
    )
    status: dict[str, str] = {}
    for line in status_raw.splitlines():
        parts = line.strip().split('\t')
        if len(parts) == 2:
            status[parts[0]] = parts[1]

    # Buffer pool hit ratio
    reads = int(status.get("Innodb_buffer_pool_reads", 0) or 0)
    read_reqs = int(status.get("Innodb_buffer_pool_read_requests", 1) or 1)
    bp_hit_pct = round((1 - reads / read_reqs) * 100, 2) if read_reqs > 0 else None

    accessible = bool(all_dbs)
    return {
        "accessible": accessible,
        "all_databases": all_dbs,
        "user_databases": user_dbs,
        "system_databases": [d for d in all_dbs if d in system_dbs],
        "db_count": len(user_dbs),
        "users": users,
        "variables": variables,
        "status": status,
        "bp_hit_pct": bp_hit_pct,
    }


def _mariadb_detail() -> dict:
    return _mysql_detail()


# ---------------------------------------------------------------------------
# Redis
# ---------------------------------------------------------------------------

def _redis_detail() -> dict:
    def r(*args: str) -> str:
        return _out(["redis-cli"] + list(args), timeout=5)

    info_raw = r("INFO")
    info: dict[str, dict] = {}
    section = "general"
    for line in info_raw.splitlines():
        line = line.strip()
        if line.startswith('#'):
            section = line.lstrip('# ').lower().replace(' ', '_')
            info.setdefault(section, {})
        elif ':' in line:
            k, v = line.split(':', 1)
            info.setdefault(section, {})[k.strip()] = v.strip()

    # Key config values
    config_keys = ["maxmemory", "maxmemory-policy", "bind", "port", "databases",
                   "loglevel", "save", "requirepass", "appendonly", "hz",
                   "tcp-keepalive", "timeout"]
    config: dict[str, str] = {}
    for key in config_keys:
        out = r("CONFIG", "GET", key)
        lines = [l for l in out.strip().splitlines() if l.strip()]
        if len(lines) >= 2:
            val = lines[1] if key != "requirepass" else ("*****" if lines[1] else "(not set)")
            config[key] = val

    # Keyspace
    keyspace: dict[str, dict] = {}
    for line in r("INFO", "keyspace").splitlines():
        if m := re.match(r'(db\d+):keys=(\d+),expires=(\d+),avg_ttl=(\d+)', line):
            keyspace[m.group(1)] = {"keys": int(m.group(2)),
                                    "expires": int(m.group(3)),
                                    "avg_ttl_ms": int(m.group(4))}

    accessible = bool(info)
    return {"accessible": accessible, "info": info, "config": config, "keyspace": keyspace}


# ---------------------------------------------------------------------------
# Postfix
# ---------------------------------------------------------------------------

def _postfix_detail() -> dict:
    # All non-default settings
    raw = _out(["postconf", "-n"], timeout=10)
    settings: dict[str, str] = {}
    for line in raw.splitlines():
        if '=' in line:
            k, v = line.split('=', 1)
            settings[k.strip()] = v.strip()

    # Queue stats
    queue_raw = _out(["postqueue", "-p"], timeout=8)
    queue_count = 0
    if "Mail queue is empty" in queue_raw:
        queue_count = 0
    else:
        m = re.search(r'-- (\d+) Kbytes in (\d+) Request', queue_raw)
        if m:
            queue_count = int(m.group(2))
        else:
            queue_count = queue_raw.count('\n(') if queue_raw else 0

    # Per-queue spool counts
    spool_counts: dict[str, int] = {}
    for q in ["active", "deferred", "bounce", "hold", "incoming"]:
        p = Path(f"/var/spool/postfix/{q}")
        if p.is_dir():
            try:
                spool_counts[q] = sum(1 for _ in p.iterdir())
            except Exception:
                spool_counts[q] = 0

    return {
        "settings": settings,
        "queue_count": queue_count,
        "spool_counts": spool_counts,
    }


# ---------------------------------------------------------------------------
# Dovecot
# ---------------------------------------------------------------------------

def _dovecot_detail() -> dict:
    # Non-default settings
    raw = _out(["doveconf", "-n"], timeout=10)
    settings: dict[str, str] = {}
    for line in raw.splitlines():
        line = line.strip()
        if '=' in line and not line.startswith('#'):
            k, v = line.split('=', 1)
            k = k.strip()
            if ' ' not in k:  # skip nested blocks
                settings[k] = v.strip()

    # Full config for protocol/auth extraction
    full_raw = _out(["doveconf", "protocols", "ssl", "auth_mechanisms",
                     "mail_location", "first_valid_uid"], timeout=5)
    quick: dict[str, str] = {}
    for line in full_raw.splitlines():
        if '=' in line:
            k, v = line.split('=', 1)
            quick[k.strip()] = v.strip()

    return {"settings": settings, "quick": quick}


# ---------------------------------------------------------------------------
# BIND9
# ---------------------------------------------------------------------------

def _bind9_detail() -> dict:
    zones: list[dict] = []
    visited: set[str] = set()

    def parse_file(path: str, depth: int = 0) -> None:
        if depth > 6 or path in visited:
            return
        visited.add(path)
        try:
            raw = Path(path).read_text(errors="replace")
            clean = _strip_comments(raw, style="c")

            # Includes
            for m in re.finditer(r'include\s+"([^"]+)"', clean, re.IGNORECASE):
                inc = m.group(1)
                if Path(inc).exists():
                    parse_file(inc, depth + 1)

            # Zone blocks
            for m in re.finditer(
                r'zone\s+"([^"]+)"\s*(?:IN\s*)?\{([^}]+)\}',
                clean, re.DOTALL | re.IGNORECASE,
            ):
                name, body = m.group(1), m.group(2)
                if tm := re.search(r'type\s+(\w+)', body, re.IGNORECASE):
                    ztype = tm.group(1).lower()
                else:
                    ztype = "unknown"

                zfile = None
                if fm := re.search(r'file\s+"([^"]+)"', body, re.IGNORECASE):
                    zfile = fm.group(1)

                masters: list[str] = []
                if mm := re.search(r'masters\s*\{([^}]+)\}', body, re.IGNORECASE):
                    masters = [ip.strip().rstrip(';') for ip in mm.group(1).split()
                               if re.match(r'[\d.:]', ip.strip().rstrip(';'))]

                # Count records if file accessible
                record_count: int | None = None
                if zfile:
                    for base in ["/etc/bind/", "/var/cache/bind/", ""]:
                        fp = Path(base + zfile) if not zfile.startswith('/') else Path(zfile)
                        if fp.exists():
                            try:
                                lines = fp.read_text(errors="replace").splitlines()
                                record_count = sum(
                                    1 for l in lines
                                    if l.strip() and not l.strip().startswith(';')
                                    and not l.strip().startswith('$')
                                )
                            except Exception:
                                pass
                            break

                zones.append({
                    "name": name,
                    "type": ztype,
                    "file": zfile,
                    "masters": masters,
                    "record_count": record_count,
                    "source": path,
                })
        except Exception:
            pass

    for start in ["/etc/bind/named.conf",
                  "/etc/named.conf",
                  "/usr/local/etc/named.conf"]:
        if Path(start).exists():
            parse_file(start)
            break

    type_order = {"master": 0, "primary": 0, "slave": 1, "secondary": 1,
                  "forward": 2, "hint": 3, "stub": 4}
    zones.sort(key=lambda z: (type_order.get(z["type"], 5), z["name"]))

    return {
        "zones": zones,
        "total": len(zones),
        "master_zones": [z for z in zones if z["type"] in ("master", "primary")],
        "slave_zones": [z for z in zones if z["type"] in ("slave", "secondary")],
        "forward_zones": [z for z in zones if z["type"] == "forward"],
        "other_zones": [z for z in zones if z["type"] not in (
            "master", "primary", "slave", "secondary", "forward")],
    }


# ---------------------------------------------------------------------------
# OpenSSH
# ---------------------------------------------------------------------------

def _openssh_detail() -> dict:
    cfg_path = Path("/etc/ssh/sshd_config")
    settings: dict[str, str] = {}
    if cfg_path.exists():
        for line in cfg_path.read_text(errors="replace").splitlines():
            line = line.strip()
            if line and not line.startswith('#') and ' ' in line:
                k, _, v = line.partition(' ')
                settings[k] = v.strip()

    active_conns = _out(["ss", "-tnp", "sport", "=", ":22"], timeout=5)
    conn_count = max(0, active_conns.count('\n') - 1)
    return {"settings": settings, "active_connections": conn_count}


# ---------------------------------------------------------------------------
# Dispatch endpoint
# ---------------------------------------------------------------------------

HANDLERS = {
    "nginx": _nginx_detail,
    "apache2": _apache2_detail,
    "mysql": _mysql_detail,
    "mariadb": _mariadb_detail,
    "redis": _redis_detail,
    "postfix": _postfix_detail,
    "dovecot": _dovecot_detail,
    "bind9": _bind9_detail,
    "openssh": _openssh_detail,
}


@router.get("/{key}/detail")
async def get_server_detail(key: str, _: str = Depends(require_super_admin)) -> dict:
    handler = HANDLERS.get(key)
    if not handler:
        raise HTTPException(404, f"No detail handler for server '{key}'")
    try:
        data = handler()
    except Exception as e:
        data = {"error": str(e)}
    return {"type": key, "data": data, "checked_at": datetime.now(UTC).isoformat()}
