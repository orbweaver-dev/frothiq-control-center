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

def _read_file_sudo(path: str) -> str:
    """Read a file via sudo cat — works even when frothiq can't directly access the path."""
    import subprocess
    try:
        r = subprocess.run(["sudo", "cat", path], capture_output=True, text=True, timeout=5)
        if r.returncode == 0:
            return r.stdout
    except Exception:
        pass
    # Fallback: direct read
    try:
        return Path(path).read_text(errors="replace")
    except Exception:
        return ""


def _nginx_detail() -> dict:
    import glob
    seen: set[str] = set()
    vhosts = []

    # Collect all nginx vhost config files — including symlinked paths
    config_files: list[str] = []
    for pattern in ["/etc/nginx/sites-enabled/*", "/etc/nginx/conf.d/*.conf"]:
        config_files.extend(sorted(glob.glob(pattern)))
    # Deduplicate by resolved path if possible
    config_files = list(dict.fromkeys(config_files))

    for fpath in config_files:
        try:
            raw = _read_file_sudo(fpath)
            if not raw:
                continue
            clean = _strip_comments(raw)
            for block in _extract_braced_blocks(clean, "server"):
                # Skip upstream blocks that might be mis-detected
                listens = _directives(block, "listen")
                if not listens:
                    continue
                ports = list({re.search(r'\d+', li).group() for li in listens if re.search(r'\d+', li)})
                ssl = any("ssl" in li for li in listens) or bool(_directive(block, "ssl_certificate"))
                # server_name may span multiple lines in Frappe configs
                sn_raw = _directive(block, "server_name") or ""
                server_name = " ".join(sn_raw.split())  # normalize whitespace

                # proxy_pass may live inside a location block — extract first occurrence anywhere
                proxy_pass = None
                for loc_block in _extract_braced_blocks(block, "location"):
                    pp = _directive(loc_block, "proxy_pass")
                    if pp:
                        proxy_pass = pp
                        break
                if not proxy_pass:
                    proxy_pass = _directive(block, "proxy_pass")

                key = (server_name, ",".join(sorted(ports)))
                if key in seen:
                    continue
                seen.add(key)
                vhosts.append({
                    "file": Path(fpath).name,
                    "server_name": server_name or "_",
                    "listen": listens,
                    "ports": ports,
                    "ssl": ssl,
                    "root": _directive(block, "root"),
                    "proxy_pass": proxy_pass,
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
    import subprocess
    vhosts = []

    # Parse sites-enabled configs — use sudo cat to resolve symlinks into protected paths
    sites_dir = Path("/etc/apache2/sites-enabled")
    if sites_dir.is_dir():
        try:
            files = sorted(f for f in sites_dir.iterdir() if f.name.endswith(".conf"))
        except Exception:
            files = []
        for f in files:
            try:
                content = _read_file_sudo(str(f))
                if not content:
                    continue
                content_clean = _strip_comments(content)
                for m in re.finditer(r'<VirtualHost\s+([^>]+)>(.*?)</VirtualHost>',
                                     content_clean, re.DOTALL | re.IGNORECASE):
                    addr = m.group(1).strip()
                    block = m.group(2)
                    port = re.search(r':(\d+)', addr)
                    port_num = port.group(1) if port else "80"
                    ssl_engine = _apache_directive(block, "SSLEngine") or ""
                    # ProxyPass may be in a Location block or top-level
                    proxy_pass = _apache_directive(block, "ProxyPass")
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
                        "proxy_pass": proxy_pass,
                    })
            except Exception:
                continue

    # apache2ctl -S summary (requires sudo)
    try:
        r = subprocess.run(["sudo", "apache2ctl", "-S"], capture_output=True, text=True, timeout=10)
        ctl_out = (r.stdout + r.stderr)[:3000]
    except Exception:
        ctl_out = ""

    # Active connections via server-status if available
    stats: dict = {}
    for url in ["http://127.0.0.1/server-status?auto", "http://localhost/server-status?auto"]:
        out = _out(["curl", "-s", "--max-time", "2", url])
        if "Total Accesses" in out or "BusyWorkers" in out:
            for stat_key, pat in [("total_accesses", r"Total Accesses:\s*(\d+)"),
                                   ("busy_workers", r"BusyWorkers:\s*(\d+)"),
                                   ("idle_workers", r"IdleWorkers:\s*(\d+)"),
                                   ("requests_per_sec", r"ReqPerSec:\s*([\d.]+)")]:
                if mm := re.search(pat, out):
                    stats[stat_key] = float(mm.group(1)) if "." in mm.group(1) else int(mm.group(1))
            break

    workers = _out(["pgrep", "-c", "apache2"])
    if workers.strip().isdigit():
        stats["worker_processes"] = int(workers.strip())

    return {"vhosts": vhosts, "stats": stats, "ctl_summary": ctl_out}


# ---------------------------------------------------------------------------
# MySQL / MariaDB
# ---------------------------------------------------------------------------

_MYSQL_DEFAULTS_FILE = "/etc/mysql/frothiq_monitor.cnf"

def _mysql_query(sql: str, timeout: int = 5) -> str:
    for cmd in [
        ["mysql", f"--defaults-file={_MYSQL_DEFAULTS_FILE}", "-N", "-B", "-e", sql],
        ["mariadb", f"--defaults-file={_MYSQL_DEFAULTS_FILE}", "-N", "-B", "-e", sql],
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
                   "tcp-keepalive", "timeout", "maxclients", "protected-mode",
                   "lazyfree-lazy-eviction", "activerehashing", "appendfsync"]
    config: dict[str, str] = {}
    for key in config_keys:
        out = r("CONFIG", "GET", key)
        lines = out.strip().splitlines()
        # CONFIG GET always returns key on line 0; value on line 1 (may be empty string)
        if lines:
            raw_val = lines[1] if len(lines) >= 2 else ""
            val = raw_val if key != "requirepass" else ("*****" if raw_val else "(not set)")
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

def _bind9_extract_zone_bodies(content: str) -> list[tuple[str, str]]:
    """Extract (zone_name, body) pairs from BIND9 config, handling nested braces."""
    results: list[tuple[str, str]] = []
    pos = 0
    pattern = re.compile(r'\bzone\s+"([^"]+)"\s*(?:IN\s*)?\{', re.IGNORECASE)
    while True:
        m = pattern.search(content, pos)
        if not m:
            break
        zone_name = m.group(1)
        start = m.end()
        depth, i = 1, start
        while i < len(content) and depth > 0:
            if content[i] == '{':
                depth += 1
            elif content[i] == '}':
                depth -= 1
            i += 1
        body = content[start:i - 1]
        results.append((zone_name, body))
        pos = i
    return results


def _bind9_detail() -> dict:
    zones: list[dict] = []
    visited: set[str] = set()

    def parse_file(path: str, depth: int = 0) -> None:
        if depth > 6 or path in visited:
            return
        visited.add(path)
        try:
            raw = _read_file_sudo(path)
            if not raw:
                raw = Path(path).read_text(errors="replace")
            clean = _strip_comments(raw, style="c")

            # Includes — collect before processing zones (order matters)
            for m in re.finditer(r'include\s+"([^"]+)"', clean, re.IGNORECASE):
                inc = m.group(1)
                if Path(inc).exists():
                    parse_file(inc, depth + 1)

            # Zone blocks — use brace-aware parser to handle nested blocks
            for zone_name, body in _bind9_extract_zone_bodies(clean):
                if tm := re.search(r'type\s+(\w+)', body, re.IGNORECASE):
                    ztype = tm.group(1).lower()
                else:
                    ztype = "unknown"

                zfile = None
                if fm := re.search(r'file\s+"([^"]+)"', body, re.IGNORECASE):
                    zfile = fm.group(1)

                # Masters: extract IPs from masters { } or primaries { } blocks
                masters: list[str] = []
                for masters_m in re.finditer(
                    r'(?:masters|primaries)\s*(?:"[^"]*"\s*)?\{([^}]+)\}', body, re.IGNORECASE
                ):
                    for tok in masters_m.group(1).split():
                        tok = tok.strip().rstrip(';')
                        if re.match(r'^[\d.:a-fA-F]+$', tok) and tok:
                            masters.append(tok)

                # also-notify IPs
                also_notify: list[str] = []
                for an_m in re.finditer(r'also-notify\s*\{([^}]+)\}', body, re.IGNORECASE):
                    for tok in an_m.group(1).split():
                        tok = tok.strip().rstrip(';')
                        if re.match(r'^[\d.:a-fA-F]+$', tok) and tok:
                            also_notify.append(tok)

                # Count records if file accessible
                record_count: int | None = None
                if zfile:
                    for base in ["/var/lib/bind/", "/etc/bind/", "/var/cache/bind/", ""]:
                        fp = Path(base + zfile) if not zfile.startswith('/') else Path(zfile)
                        try:
                            accessible = fp.exists()
                        except (PermissionError, OSError):
                            accessible = False
                        if accessible:
                            try:
                                content_lines = _read_file_sudo(str(fp)).splitlines()
                                record_count = sum(
                                    1 for l in content_lines
                                    if l.strip() and not l.strip().startswith(';')
                                    and not l.strip().startswith('$')
                                )
                            except Exception:
                                pass
                            break

                zones.append({
                    "name": zone_name,
                    "type": ztype,
                    "file": zfile,
                    "masters": masters,
                    "also_notify": also_notify,
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

    master_zones = [z for z in zones if z["type"] in ("master", "primary")]
    slave_zones = [z for z in zones if z["type"] in ("slave", "secondary")]
    forward_zones = [z for z in zones if z["type"] == "forward"]

    return {
        "zones": zones,
        "total": len(zones),
        "zone_count": len(zones),
        "master_count": len(master_zones),
        "slave_count": len(slave_zones),
        "master_zones": master_zones,
        "slave_zones": slave_zones,
        "forward_zones": forward_zones,
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


def _rails_detail() -> dict:
    def _v(cmd: list[str]) -> str:
        return _out(cmd, timeout=8).strip()

    ruby_version  = _v(["ruby",    "--version"])
    gem_version   = _v(["gem",     "--version"])
    bundler_ver   = _v(["bundle3.2", "--version"]) or _v(["bundle", "--version"])

    # Installed Rails gem version(s)
    gem_list_out  = _v(["gem", "list", "^rails$"])
    rails_version = gem_list_out if gem_list_out else "(not installed)"

    # Running Puma/Unicorn/Thin processes
    processes: list[dict] = []
    ps_out = _out(["ps", "aux"], timeout=5)
    for line in ps_out.splitlines():
        lower = line.lower()
        if any(kw in lower for kw in ("puma", "unicorn", "thin ", "passenger")):
            parts = line.split(None, 10)
            if len(parts) >= 11:
                processes.append({"user": parts[0], "pid": parts[1], "cpu": parts[2], "mem": parts[3], "cmd": parts[10]})

    # Gemfiles found in common deployment locations
    gemfiles: list[str] = []
    for base in ("/home", "/var/www", "/opt"):
        try:
            for gf in Path(base).rglob("Gemfile"):
                if ".bundle" not in str(gf) and len(gf.parts) - len(Path(base).parts) <= 5:
                    gemfiles.append(str(gf))
                    if len(gemfiles) >= 10:
                        break
        except (PermissionError, OSError):
            pass
        if len(gemfiles) >= 10:
            break

    return {
        "ruby_version": ruby_version,
        "gem_version": gem_version,
        "bundler_version": bundler_ver,
        "rails_version": rails_version,
        "app_processes": processes,
        "gemfiles_found": gemfiles,
    }


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
    "rails": _rails_detail,
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


# ---------------------------------------------------------------------------
# Health checks
# ---------------------------------------------------------------------------

_CONFIG_TEST_CMDS: dict[str, list[str]] = {
    "nginx":   ["sudo", "nginx", "-t"],
    "apache2": ["sudo", "apache2ctl", "-t"],
    "bind9":   ["sudo", "named-checkconf", "/etc/bind/named.conf"],
    "postfix": ["sudo", "postfix", "check"],
}

_ERROR_LOGS: dict[str, list[str]] = {
    "nginx":   ["/var/log/nginx/error.log"],
    "apache2": ["/var/log/apache2/error.log"],
    "mysql":   ["/var/log/mysql/error.log"],
    "mariadb": ["/var/log/mysql/error.log"],
    "redis":   ["/var/log/redis/redis-server.log"],
    "postfix": ["/var/log/mail.log"],
    "dovecot": ["/var/log/dovecot.log", "/var/log/mail.log"],
    "bind9":   ["/var/log/named/default", "/var/log/syslog"],
    "openssh": ["/var/log/auth.log"],
    "fail2ban": ["/var/log/fail2ban.log"],
}

_SYSTEMD_NAMES: dict[str, str] = {
    "nginx":   "nginx",
    "apache2": "apache2",
    "mysql":   "mysql",
    "mariadb": "mariadb",
    "redis":   "redis-server",
    "postfix": "postfix",
    "dovecot": "dovecot",
    "bind9":   "named",
    "openssh": "ssh",
    "fail2ban": "fail2ban",
}


def _health_checks(key: str) -> list[dict]:
    """Run service-specific health checks and return a list of check results."""
    import subprocess
    checks = []

    # 1. Process check
    svc_name = _SYSTEMD_NAMES.get(key, key)
    proc_out, _, proc_rc = _run(["pgrep", "-c", "-x", svc_name])
    if proc_rc == 0 and proc_out.strip().isdigit():
        count = int(proc_out.strip())
        checks.append({"name": "Process Running", "status": "ok" if count > 0 else "error",
                       "detail": f"{count} process(es) running"})
    else:
        # fallback to systemctl is-active
        _, _, rc = _run(["sudo", "systemctl", "is-active", "--quiet", svc_name])
        checks.append({"name": "Service Active", "status": "ok" if rc == 0 else "error",
                       "detail": "active" if rc == 0 else "inactive/failed"})

    # 2. Systemd status
    status_out, _, _ = _run(["sudo", "systemctl", "status", "--no-pager", "-l", svc_name], timeout=5)
    # Extract last activation time
    if m := re.search(r'Active:.*?since\s+(.+?);', status_out):
        checks.append({"name": "Last Started", "status": "info", "detail": m.group(1).strip()})
    if m := re.search(r'Main PID:\s*(\d+)', status_out):
        checks.append({"name": "Main PID", "status": "info", "detail": m.group(1).strip()})

    # 3. Config test (if available)
    if key in _CONFIG_TEST_CMDS:
        cmd = _CONFIG_TEST_CMDS[key]
        stdout, stderr, rc = _run(cmd, timeout=10)
        output = (stdout + stderr).strip()
        ok = rc == 0
        checks.append({"name": "Config Test", "status": "ok" if ok else "error",
                       "detail": output[:200] if output else ("OK" if ok else "FAILED")})

    # 4. Service-specific checks
    if key in ("nginx", "apache2"):
        # Check listening ports
        port_out = _out(["ss", "-tlnp"], timeout=5)
        ports_80 = ":80 " in port_out
        ports_443 = ":443 " in port_out
        checks.append({"name": "Listening :80", "status": "ok" if ports_80 else "warn", "detail": "yes" if ports_80 else "not listening"})
        checks.append({"name": "Listening :443", "status": "ok" if ports_443 else "warn", "detail": "yes" if ports_443 else "not listening"})

    if key in ("mysql", "mariadb"):
        # Try connecting
        result = _out(["mysqladmin", f"--defaults-file={_MYSQL_DEFAULTS_FILE}", "ping", "--connect-timeout=2"], timeout=5)
        ok = "alive" in result.lower()
        checks.append({"name": "DB Ping", "status": "ok" if ok else "error", "detail": result.strip() or "no response"})

    if key == "redis":
        result = _out(["redis-cli", "ping"], timeout=3)
        ok = "PONG" in result
        checks.append({"name": "Redis Ping", "status": "ok" if ok else "error", "detail": result.strip() or "no response"})

    if key == "postfix":
        # Queue summary
        queue_out = _out(["sudo", "postfix", "status"], timeout=5)
        mq_out = _out(["sudo", "mailq"], timeout=5)
        queue_count = mq_out.count("\n") - 1 if "empty" not in mq_out else 0
        checks.append({"name": "Mail Queue", "status": "ok" if queue_count == 0 else "warn",
                       "detail": f"{max(0, queue_count)} message(s) queued"})

    if key == "openssh":
        ss_out = _out(["ss", "-tnp", "sport", "=", ":22"], timeout=5)
        conns = max(0, ss_out.count("\n") - 1)
        checks.append({"name": "Active SSH Sessions", "status": "info", "detail": f"{conns} connection(s)"})

    if key == "fail2ban":
        # Only run client checks if service is running
        is_active_out, _, is_rc = _run(["sudo", "systemctl", "is-active", "fail2ban"], timeout=5)
        if is_rc == 0:
            status_out, _, rc = _run(["sudo", "fail2ban-client", "status"], timeout=8)
            if rc == 0:
                # Extract jail list
                jails_line = ""
                for line in status_out.splitlines():
                    if "Jail list:" in line:
                        jails_line = line.split("Jail list:", 1)[-1].strip()
                        break
                jails = [j.strip() for j in jails_line.split(",") if j.strip()] if jails_line else []
                checks.append({"name": "Active Jails", "status": "ok" if jails else "warn",
                               "detail": ", ".join(jails) if jails else "No jails active"})
                # Per-jail banned counts
                for jail in jails[:5]:
                    jout, _, jrc = _run(["sudo", "fail2ban-client", "status", jail], timeout=5)
                    if jrc == 0:
                        banned = 0
                        for line in jout.splitlines():
                            if "Currently banned:" in line:
                                try:
                                    banned = int(line.split(":", 1)[-1].strip())
                                except ValueError:
                                    pass
                        checks.append({"name": f"Jail: {jail}", "status": "warn" if banned > 0 else "ok",
                                       "detail": f"{banned} IP(s) currently banned"})
            else:
                checks.append({"name": "fail2ban-client", "status": "error",
                               "detail": "Could not reach fail2ban socket"})
        else:
            checks.append({"name": "Service Status", "status": "warn",
                           "detail": "fail2ban is not running — service is disabled or stopped"})

    return checks


def _modules_list(key: str) -> list[dict]:
    """Return a list of loaded modules/extensions for the service."""
    mods = []
    if key == "apache2":
        out = _out(["sudo", "apache2ctl", "-M"], timeout=10)
        for line in out.splitlines():
            line = line.strip()
            if line and not line.startswith("Loaded"):
                parts = line.split()
                if parts:
                    mods.append({"name": parts[0], "type": parts[1] if len(parts) > 1 else "static"})
    elif key == "nginx":
        out = _out(["nginx", "-V"], timeout=5)
        for m in re.finditer(r'--with-([\w-]+)', out):
            mods.append({"name": m.group(1), "type": "compiled-in"})
    return mods


@router.get("/{key}/health")
async def get_server_health(key: str, _: str = Depends(require_super_admin)) -> dict:
    """Return comprehensive health check results for a service."""
    svc_name = _SYSTEMD_NAMES.get(key, key)

    # Full systemd status block
    status_out, _, _ = _run(["sudo", "systemctl", "status", "--no-pager", "-l", svc_name], timeout=8)

    # Error log tail (last 50 lines)
    log_lines: list[str] = []
    log_path: str = ""
    for lp in _ERROR_LOGS.get(key, []):
        out = _out(["sudo", "tail", "-n", "50", lp], timeout=5)
        if out.strip():
            log_lines = out.splitlines()
            log_path = lp
            break

    # Error/warning counts in log
    error_count = sum(1 for l in log_lines if "error" in l.lower() or "crit" in l.lower())
    warn_count = sum(1 for l in log_lines if "warn" in l.lower() or "notice" in l.lower())

    checks = _health_checks(key)
    mods = _modules_list(key)

    return {
        "key": key,
        "systemd_status": status_out[:4000],
        "log_path": log_path,
        "log_lines": log_lines,
        "error_count": error_count,
        "warn_count": warn_count,
        "checks": checks,
        "modules": mods,
        "checked_at": datetime.now(UTC).isoformat(),
    }


# ---------------------------------------------------------------------------
# Config file paths
# ---------------------------------------------------------------------------

_CONFIG_PATHS: dict[str, list[str]] = {
    "postfix": ["/etc/postfix/main.cf"],
    "dovecot": ["/etc/dovecot/dovecot.conf"],
    "redis": ["/etc/redis/redis.conf"],
    "openssh": ["/etc/ssh/sshd_config"],
    "nginx": ["/etc/nginx/nginx.conf"],
    "apache2": ["/etc/apache2/apache2.conf"],
    "mysql": ["/etc/mysql/mariadb.conf.d/50-server.cnf", "/etc/mysql/my.cnf"],
    "mariadb": ["/etc/mysql/mariadb.conf.d/50-server.cnf", "/etc/mysql/my.cnf"],
    "bind9": ["/etc/bind/named.conf.options"],
    "fail2ban": ["/etc/fail2ban/jail.local", "/etc/fail2ban/jail.conf"],
}

_RELOAD_CMDS: dict[str, list[str]] = {
    "postfix": ["sudo", "postfix", "reload"],
    "dovecot": ["sudo", "doveadm", "reload"],
    "redis": ["sudo", "systemctl", "reload", "redis-server"],
    "openssh": ["sudo", "systemctl", "reload", "ssh"],
    "nginx": ["sudo", "nginx", "-s", "reload"],
    "apache2": ["sudo", "apache2ctl", "graceful"],
    "mysql": ["sudo", "systemctl", "restart", "mariadb"],
    "mariadb": ["sudo", "systemctl", "restart", "mariadb"],
    "bind9": ["sudo", "rndc", "reload"],
    "fail2ban": ["sudo", "fail2ban-client", "reload"],
}

# Format constants
_FMT_KV_EQUALS = "kv_equals"   # key = value  (postfix, dovecot, mysql)
_FMT_KV_SPACE = "kv_space"     # key value    (redis, openssh)
_FMT_NGINX = "nginx"            # key value;   (nginx directive)
_FMT_APACHE = "apache"          # Key Value    (apache, case-insensitive)

_KEY_FORMAT: dict[str, str] = {
    "postfix": _FMT_KV_EQUALS,
    "dovecot": _FMT_KV_EQUALS,
    "redis": _FMT_KV_SPACE,
    "openssh": _FMT_KV_SPACE,
    "nginx": _FMT_NGINX,
    "apache2": _FMT_APACHE,
    "mysql": _FMT_KV_EQUALS,
    "mariadb": _FMT_KV_EQUALS,
}


def _resolve_config_path(key: str) -> tuple[str | None, bool]:
    """Returns (path, exists) for the first matching config path for a service key."""
    for p in _CONFIG_PATHS.get(key, []):
        if Path(p).exists():
            return p, True
    paths = _CONFIG_PATHS.get(key, [])
    return (paths[0] if paths else None), False


def _write_conf(path: str, content: str) -> None:
    """Write content to path safely using a tempfile + sudo cp."""
    import tempfile, os
    with tempfile.NamedTemporaryFile(mode="w", suffix=".tmp", delete=False) as tf:
        tf.write(content)
        tmp = tf.name
    try:
        _, _, rc = _run(["sudo", "cp", tmp, path])
        if rc != 0:
            raise RuntimeError(f"sudo cp failed with rc={rc}")
        _run(["sudo", "chmod", "600", path])
    finally:
        try:
            os.unlink(tmp)
        except Exception:
            pass


def _update_config_lines(
    content: str,
    settings: dict[str, str],
    fmt: str,
    section: str | None = None,
) -> tuple[str, list[str], list[str]]:
    """
    Apply settings to config file content using in-place line substitution.

    Returns (new_content, applied_keys, not_found_keys).
    """
    lines = content.splitlines(keepends=True)
    applied: set[str] = set()
    pending = dict(settings)  # keys still to be placed

    in_section = section is None  # if no section filter, always in section

    new_lines: list[str] = []

    for line in lines:
        stripped = line.rstrip("\n\r")

        # Section tracking (for mysql [mysqld])
        if section is not None:
            sec_match = re.match(r'^\s*\[([^\]]+)\]', stripped)
            if sec_match:
                in_section = sec_match.group(1).strip().lower() == section.lower()
            new_lines.append(line)
            if not in_section:
                continue
            # We're in the right section — fall through to normal processing
            # But we already appended the section header line, skip further processing
            # Actually we need to check if the line IS the section header
            if sec_match:
                continue

        # Determine the key on this line (handles commented-out lines too)
        raw_stripped = stripped.lstrip()
        is_comment = raw_stripped.startswith("#")
        active_part = raw_stripped.lstrip("#").lstrip() if is_comment else raw_stripped

        matched_key: str | None = None

        if fmt == _FMT_KV_EQUALS:
            m = re.match(r'^([A-Za-z0-9_.+-]+)\s*=', active_part)
            if m:
                matched_key = m.group(1).strip()
        elif fmt == _FMT_KV_SPACE:
            m = re.match(r'^([A-Za-z0-9_.-]+)\s+', active_part)
            if m:
                matched_key = m.group(1).strip()
        elif fmt == _FMT_NGINX:
            m = re.match(r'^([A-Za-z0-9_]+)\s+', active_part)
            if m and not active_part.startswith("{") and not active_part.startswith("}"):
                matched_key = m.group(1).strip()
        elif fmt == _FMT_APACHE:
            m = re.match(r'^([A-Za-z][A-Za-z0-9_]+)\s+', active_part)
            if m:
                matched_key = m.group(1).strip()

        # Check if matched key is one we want to set (case-insensitive for openssh/apache)
        target_key: str | None = None
        if matched_key:
            for sk in list(pending.keys()):
                if fmt in (_FMT_KV_SPACE, _FMT_APACHE):
                    if matched_key.lower() == sk.lower():
                        target_key = sk
                        break
                else:
                    if matched_key == sk:
                        target_key = sk
                        break

        if target_key is not None:
            val = pending.pop(target_key)
            indent = re.match(r'^(\s*)', stripped).group(1)
            if fmt == _FMT_KV_EQUALS:
                new_line = f"{indent}{target_key} = {val}\n"
            elif fmt == _FMT_KV_SPACE:
                new_line = f"{indent}{target_key} {val}\n"
            elif fmt == _FMT_NGINX:
                new_line = f"{indent}{target_key} {val};\n"
            elif fmt == _FMT_APACHE:
                new_line = f"{indent}{target_key} {val}\n"
            else:
                new_line = line
            applied.add(target_key)
            new_lines.append(new_line)
        else:
            if section is None:
                new_lines.append(line)
            # (section header lines already appended above)

    # Append any keys that weren't found in the file
    not_found = list(pending.keys())
    if pending:
        new_lines.append("\n# Added by FrothIQ MC3\n")
        for k, v in pending.items():
            if fmt == _FMT_KV_EQUALS:
                new_lines.append(f"{k} = {v}\n")
            elif fmt == _FMT_KV_SPACE:
                new_lines.append(f"{k} {v}\n")
            elif fmt == _FMT_NGINX:
                new_lines.append(f"{k} {v};\n")
            elif fmt == _FMT_APACHE:
                new_lines.append(f"{k} {v}\n")

    return "".join(new_lines), list(applied), not_found


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

from pydantic import BaseModel


class ConfigRawBody(BaseModel):
    content: str
    reload: bool = True


class ConfigSettingsBody(BaseModel):
    settings: dict[str, str]
    reload: bool = True


# ---------------------------------------------------------------------------
# New endpoints
# ---------------------------------------------------------------------------

@router.get("/{key}/config-raw")
async def get_config_raw(key: str, _: str = Depends(require_super_admin)) -> dict:
    path, exists = _resolve_config_path(key)
    if path is None:
        raise HTTPException(404, f"No config path known for service '{key}'")
    content = None
    error = None
    if exists:
        try:
            content = Path(path).read_text(errors="replace")
        except Exception as e:
            error = str(e)
    return {"key": key, "path": path, "content": content, "exists": exists, "error": error}


@router.put("/{key}/config-raw")
async def put_config_raw(key: str, body: ConfigRawBody, _: str = Depends(require_super_admin)) -> dict:
    path, _ = _resolve_config_path(key)
    if path is None:
        raise HTTPException(404, f"No config path known for service '{key}'")
    try:
        _write_conf(path, body.content)
    except Exception as e:
        raise HTTPException(500, f"Write failed: {e}")

    reloaded = False
    reload_output = ""
    if body.reload:
        cmd = _RELOAD_CMDS.get(key)
        if cmd:
            stdout, stderr, rc = _run(cmd, timeout=15)
            reload_output = (stdout + stderr).strip()
            reloaded = rc == 0

    return {"ok": True, "reloaded": reloaded, "reload_output": reload_output, "path": path}


# ---------------------------------------------------------------------------
# BIND9 structured options editor
# ---------------------------------------------------------------------------

_BIND9_OPTIONS_FILE = "/etc/bind/named.conf.options"


def _parse_named_options(content: str) -> dict:
    """Parse named.conf.options and return structured settings."""
    clean = re.sub(r'//[^\n]*', '', content)
    clean = re.sub(r'/\*.*?\*/', '', clean, flags=re.DOTALL)

    # Extract options { ... } block
    m = re.search(r'\boptions\s*\{', clean)
    if not m:
        return {"_raw": content, "_parse_error": "No options { } block found"}

    start = m.end()
    depth, i = 1, start
    while i < len(clean) and depth > 0:
        if clean[i] == '{':
            depth += 1
        elif clean[i] == '}':
            depth -= 1
        i += 1
    block = clean[start:i - 1]

    def _directive(name: str) -> str | None:
        rx = re.search(rf'(?:^|[;\n])\s*{re.escape(name)}\s+([^;{{]+);', block, re.IGNORECASE | re.MULTILINE)
        return rx.group(1).strip() if rx else None

    def _acl_block(name: str) -> str:
        rx = re.search(rf'\b{re.escape(name)}\s*\{{([^}}]+)\}}', block, re.IGNORECASE | re.DOTALL)
        if rx:
            items = [s.strip().rstrip(';') for s in rx.group(1).split(';') if s.strip()]
            return "; ".join(items)
        return ""

    # Forwarders list
    fw_rx = re.search(r'\bforwarders\s*\{([^}]*)\}', block, re.IGNORECASE | re.DOTALL)
    forwarders: list[str] = []
    if fw_rx:
        for tok in fw_rx.group(1).split():
            tok = tok.strip().rstrip(';')
            if re.match(r'^[\d.:a-fA-F]+$', tok) and tok:
                forwarders.append(tok)

    raw_dir = _directive('directory') or '/var/cache/bind'
    directory = raw_dir.strip('"').strip("'")

    raw_ver = _directive('version') or ''
    version = raw_ver.strip('"').strip("'")

    return {
        "directory": directory,
        "forwarders": forwarders,
        "forward": _directive('forward') or 'first',
        "recursion": _directive('recursion') or 'yes',
        "auth_nxdomain": _directive('auth-nxdomain') or 'no',
        "dnssec_validation": _directive('dnssec-validation') or 'auto',
        "notify": _directive('notify') or 'no',
        "version": version,
        "allow_query": _acl_block('allow-query') or 'any',
        "allow_recursion": _acl_block('allow-recursion') or 'localhost',
        "allow_transfer": _acl_block('allow-transfer') or 'none',
        "listen_on": _acl_block('listen-on') or 'any',
        "listen_on_v6": _acl_block('listen-on-v6') or 'any',
        "max_cache_size": _directive('max-cache-size') or '',
        "max_cache_ttl": _directive('max-cache-ttl') or '',
        "max_ncache_ttl": _directive('max-ncache-ttl') or '',
        "additional_from_auth": _directive('additional-from-auth') or '',
        "additional_from_cache": _directive('additional-from-cache') or '',
    }


def _build_named_options(settings: dict) -> str:
    """Build named.conf.options content from structured settings."""
    lines: list[str] = ["options {"]

    directory = settings.get("directory", "/var/cache/bind").strip().strip('"')
    lines.append(f'\tdirectory "{directory}";')
    lines.append("")

    # Forwarders
    forwarders = settings.get("forwarders", [])
    if forwarders:
        lines.append("\tforwarders {")
        for ip in forwarders:
            ip = ip.strip().rstrip(';')
            if ip:
                lines.append(f"\t\t{ip};")
        lines.append("\t};")
        fwd_mode = settings.get("forward", "first").strip()
        if fwd_mode in ("only", "first"):
            lines.append(f"\tforward {fwd_mode};")
    else:
        lines.append("\tforwarders { };")
    lines.append("")

    # Query policy
    def _acl(name: str, val: str) -> None:
        val = val.strip().rstrip(';')
        if not val:
            val = "none"
        # normalize semicolons — val may be "any" or "localhost; 10.0.0.0/8"
        parts = [p.strip().rstrip(';') for p in val.split(';') if p.strip()]
        inner = "; ".join(parts)
        lines.append(f"\t{name} {{ {inner}; }};")

    _acl("allow-query", settings.get("allow_query", "any"))
    _acl("allow-recursion", settings.get("allow_recursion", "localhost"))
    _acl("allow-transfer", settings.get("allow_transfer", "none"))
    lines.append("")

    # Network
    _acl("listen-on", settings.get("listen_on", "any"))
    _acl("listen-on-v6", settings.get("listen_on_v6", "any"))
    lines.append("")

    # DNSSEC
    dnssec = settings.get("dnssec_validation", "auto").strip()
    lines.append(f"\tdnssec-validation {dnssec};")
    lines.append("")

    # Behaviour
    recursion = settings.get("recursion", "yes").strip()
    lines.append(f"\trecursion {recursion};")

    auth_nx = settings.get("auth_nxdomain", "no").strip()
    lines.append(f"\tauth-nxdomain {auth_nx};")

    notify = settings.get("notify", "no").strip()
    lines.append(f"\tnotify {notify};")

    version = settings.get("version", "").strip()
    if version:
        lines.append(f'\tversion "{version}";')
    lines.append("")

    # Performance
    for key, directive in [
        ("max_cache_size", "max-cache-size"),
        ("max_cache_ttl", "max-cache-ttl"),
        ("max_ncache_ttl", "max-ncache-ttl"),
    ]:
        val = settings.get(key, "").strip()
        if val:
            lines.append(f"\t{directive} {val};")

    lines.append("};")
    lines.append("")
    return "\n".join(lines)


class Bind9OptionsBody(BaseModel):
    settings: dict
    reload: bool = True


@router.get("/bind9/named-options")
async def get_bind9_options(_: str = Depends(require_super_admin)) -> dict:
    """Parse /etc/bind/named.conf.options and return structured settings."""
    path = _BIND9_OPTIONS_FILE
    if not Path(path).exists():
        # Try alternate paths
        for alt in ["/etc/named.conf.options", "/etc/named.conf"]:
            if Path(alt).exists():
                path = alt
                break
        else:
            raise HTTPException(404, "named.conf.options not found on this system")
    try:
        content = _read_file_sudo(path)
    except Exception as e:
        raise HTTPException(500, f"Read failed: {e}")
    parsed = _parse_named_options(content)
    return {"path": path, "settings": parsed, "raw": content}


@router.post("/bind9/named-options")
async def save_bind9_options(body: Bind9OptionsBody, _: str = Depends(require_super_admin)) -> dict:
    """Write structured BIND9 options back to named.conf.options and reload."""
    path = _BIND9_OPTIONS_FILE
    if not Path(path).exists():
        for alt in ["/etc/named.conf.options", "/etc/named.conf"]:
            if Path(alt).exists():
                path = alt
                break
        else:
            raise HTTPException(404, "named.conf.options not found on this system")

    new_content = _build_named_options(body.settings)

    # Validate before writing
    import tempfile, os
    with tempfile.NamedTemporaryFile(mode="w", suffix=".conf", delete=False, dir="/tmp") as tf:
        tf.write(new_content)
        tmp = tf.name
    try:
        _, check_err, check_rc = _run(["sudo", "/usr/bin/named-checkconf", tmp], timeout=10)
        if check_rc != 0:
            raise HTTPException(422, f"Config validation failed: {check_err.strip()}")
    finally:
        try:
            os.unlink(tmp)
        except Exception:
            pass

    try:
        _write_conf(path, new_content)
    except Exception as e:
        raise HTTPException(500, f"Write failed: {e}")

    reloaded = False
    reload_output = ""
    if body.reload:
        stdout, stderr, rc = _run(["sudo", "rndc", "reload"], timeout=15)
        reload_output = (stdout + stderr).strip()
        reloaded = rc == 0

    return {
        "ok": True,
        "path": path,
        "reloaded": reloaded,
        "reload_output": reload_output or "OK",
    }


# ---------------------------------------------------------------------------
# BIND9 zone status + records editor
# ---------------------------------------------------------------------------

def _file_exists_sudo(path: str) -> bool:
    """Check if a file exists, using sudo stat to bypass permission restrictions."""
    _, _, rc = _run(["sudo", "stat", "--format=%F", path], timeout=5)
    return rc == 0


def _bind9_zone_file(zone_name: str) -> str | None:
    """Return path to zone file for the given zone, or None if not found."""
    # First: parse named.conf.local to get the declared file path
    try:
        local = _read_file_sudo("/etc/bind/named.conf.local")
        clean = _strip_comments(local, style="c")
        for zn, body in _bind9_extract_zone_bodies(clean):
            if zn.lower() == zone_name.lower():
                if fm := re.search(r'file\s+"([^"]+)"', body, re.IGNORECASE):
                    declared = fm.group(1)
                    # Try declared path directly or with common bases
                    for candidate in [
                        declared,
                        "/var/lib/bind/" + declared.lstrip("/"),
                        "/etc/bind/" + declared.lstrip("/"),
                        "/var/cache/bind/" + declared.lstrip("/"),
                    ]:
                        if _file_exists_sudo(candidate):
                            return candidate
    except Exception:
        pass

    # Fallback: probe common paths by name pattern
    for base in ["/var/lib/bind/", "/etc/bind/", "/var/cache/bind/"]:
        for suffix in [".hosts", ".zone", ".db", ""]:
            candidate = base + zone_name + suffix
            if _file_exists_sudo(candidate):
                return candidate

    return None


def _rndc_zone_status(zone_name: str) -> dict:
    """Call rndc zonestatus and return parsed fields."""
    out, _, rc = _run(["sudo", "rndc", "zonestatus", zone_name], timeout=10)
    result: dict = {"raw": out.strip(), "ok": rc == 0}
    for line in out.splitlines():
        if ":" in line:
            k, _, v = line.partition(":")
            result[k.strip().lower().replace(" ", "_")] = v.strip()
    return result


def _dnssec_external_check(zone_name: str) -> dict:
    """Check DNSSEC validation externally via 8.8.8.8. Returns structured status."""
    out, _, rc = _run(
        ["dig", "+dnssec", "+time=4", "+tries=1", f"@8.8.8.8", zone_name, "SOA"],
        timeout=10,
    )
    validated = False
    bogus = False
    status_code = ""
    ede_msg = ""
    for line in out.splitlines():
        if "flags:" in line and " ad " in line:
            validated = True
        if "status:" in line:
            m = re.search(r'status:\s*(\w+)', line)
            if m:
                status_code = m.group(1)
                bogus = status_code == "SERVFAIL"
        if "EDE:" in line or "Extended DNS Error" in line:
            ede_msg = line.strip().lstrip("; ")
    return {
        "validated": validated,
        "bogus": bogus,
        "status": status_code,
        "ede": ede_msg,
        "ok": rc == 0 and not bogus,
    }


def _get_zone_notify_ips(zone_name: str) -> list[str]:
    """Return the also-notify IPs for a zone from named.conf.local."""
    ips: list[str] = []
    try:
        local = _read_file_sudo("/etc/bind/named.conf.local")
        clean = _strip_comments(local, style="c")
        for zn, body in _bind9_extract_zone_bodies(clean):
            if zn.lower() == zone_name.lower():
                for an_m in re.finditer(r'also-notify\s*\{([^}]+)\}', body, re.IGNORECASE):
                    for tok in an_m.group(1).split():
                        tok = tok.strip().rstrip(';')
                        if re.match(r'^[\d.:a-fA-F]+$', tok) and tok:
                            ips.append(tok)
                break
    except Exception:
        pass
    return ips


def _set_zone_notify_ips(zone_name: str, notify_ips: list[str]) -> tuple[bool, str]:
    """Update also-notify IPs for a zone in named.conf.local. Returns (ok, error_msg)."""
    path = "/etc/bind/named.conf.local"
    content = _read_file_sudo(path)
    if not content:
        return False, "Could not read named.conf.local"

    # Locate zone block using brace-depth tracking
    pattern = re.compile(r'\bzone\s+"' + re.escape(zone_name) + r'"\s*(?:IN\s*)?\{', re.IGNORECASE)
    m = pattern.search(content)
    if not m:
        return False, f"Zone '{zone_name}' not found in named.conf.local"

    brace_start = m.end()
    depth, i = 1, brace_start
    while i < len(content) and depth > 0:
        if content[i] == '{':
            depth += 1
        elif content[i] == '}':
            depth -= 1
        i += 1
    block_end = i  # position after closing '}'

    zone_body = content[brace_start:i - 1]
    prefix = content[:brace_start]
    suffix = content[i - 1:]  # includes closing '}'

    # Build new also-notify directive
    notify_directive = (
        "    also-notify { " + " ".join(ip + ";" for ip in notify_ips) + " };\n"
        if notify_ips else ""
    )

    # Replace existing also-notify or add before closing brace
    also_notify_re = re.compile(r'[ \t]*also-notify\s*\{[^}]*\}\s*;\n?', re.IGNORECASE)
    if also_notify_re.search(zone_body):
        new_body = also_notify_re.sub(notify_directive, zone_body)
    else:
        if notify_directive:
            new_body = zone_body.rstrip('\n') + "\n" + notify_directive
        else:
            new_body = zone_body

    new_content = prefix + new_body + suffix

    # Validate with named-checkconf before writing
    import tempfile, os
    with tempfile.NamedTemporaryFile(mode="w", suffix=".conf", delete=False, dir="/tmp") as tf:
        tf.write(new_content)
        tmp = tf.name
    try:
        _, check_err, check_rc = _run(["sudo", "/usr/bin/named-checkconf", tmp], timeout=10)
        if check_rc != 0:
            return False, f"Config validation failed: {check_err.strip()}"
    finally:
        try:
            os.unlink(tmp)
        except Exception:
            pass

    _write_conf(path, new_content)
    return True, ""


def _dig_soa_serial(zone_name: str, server_ip: str) -> dict:
    """Query @server_ip for zone SOA serial. Returns {ip, serial, ok}."""
    out, err, rc = _run(
        ["dig", f"@{server_ip}", zone_name, "SOA", "+short", "+time=3", "+tries=1"],
        timeout=8,
    )
    serial: int | None = None
    if rc == 0 and out.strip():
        parts = out.strip().split()
        if len(parts) >= 3:
            try:
                serial = int(parts[2])
            except ValueError:
                pass
    return {"ip": server_ip, "serial": serial, "ok": serial is not None}


def _parse_zone_records(content: str) -> list[dict]:
    """Parse zone file content into a list of record dicts."""
    records: list[dict] = []
    default_ttl: str = ""
    origin: str = ""

    # Join continuation lines (inside parentheses)
    joined = re.sub(r'\(([^)]*)\)', lambda m: m.group(0).replace('\n', ' '), content)

    for line in joined.splitlines():
        line = line.strip()
        if not line or line.startswith(';'):
            continue
        if line.startswith('$TTL'):
            parts = line.split(None, 1)
            if len(parts) > 1:
                default_ttl = parts[1].split(';')[0].strip()
            continue
        if line.startswith('$ORIGIN'):
            parts = line.split(None, 1)
            if len(parts) > 1:
                origin = parts[1].split(';')[0].strip()
            continue

        # Strip inline comments
        line = re.sub(r'\s;.*$', '', line).strip()
        if not line:
            continue

        # Try to parse: name [ttl] [class] type data
        m = re.match(
            r'^(\S+)\s+'                          # name
            r'(?:(\d+)\s+)?'                      # optional TTL
            r'(?:(IN|CH|HS|ANY)\s+)?'             # optional class
            r'(SOA|NS|A|AAAA|MX|CNAME|TXT|SRV|PTR|CAA|DNSKEY|RRSIG|NSEC|NSEC3|DS|TLSA)\s+'
            r'(.+)$',
            line, re.IGNORECASE,
        )
        if not m:
            continue

        name, ttl, cls, rtype, data = m.groups()
        data = data.strip()
        managed = rtype.upper() in ('DNSKEY', 'RRSIG', 'NSEC', 'NSEC3', 'DS')
        records.append({
            "name": name,
            "ttl": ttl or default_ttl,
            "class": (cls or "IN").upper(),
            "type": rtype.upper(),
            "data": data,
            "managed": managed,
        })

    return records


def _increment_zone_serial(current: str) -> str:
    """Increment zone serial. Handles YYYYMMDDNN and plain integer formats."""
    from datetime import date
    today = date.today().strftime("%Y%m%d")
    try:
        n = int(current)
        if len(current) == 10 and current[:8] == today:
            nn = n % 100
            return f"{today}{(nn + 1):02d}"
        elif len(current) == 10:
            return f"{today}00"
        else:
            return str(n + 1)
    except ValueError:
        return current


def _build_zone_file(records: list[dict], default_ttl: str, origin: str) -> str:
    """Reconstruct zone file text from records list."""
    lines = []
    if default_ttl:
        lines.append(f"$TTL {default_ttl}")
    if origin:
        lines.append(f"$ORIGIN {origin}")
    for r in records:
        ttl_part = f"{r['ttl']}\t" if r.get("ttl") and r["ttl"] != default_ttl else ""
        cls = r.get("class", "IN")
        lines.append(f"{r['name']}\t{ttl_part}{cls}\t{r['type']}\t{r['data']}")
    return "\n".join(lines) + "\n"


class ZoneRecordsBody(BaseModel):
    records: list[dict]
    default_ttl: str = "3600"
    origin: str = ""
    reload: bool = True


class NotifyIpsBody(BaseModel):
    notify_ips: list[str]


@router.get("/bind9/zones/{zone_name}/status")
async def get_bind9_zone_status(zone_name: str, _: str = Depends(require_super_admin)) -> dict:
    """Return rndc zonestatus + DNSSEC validation + notify IP sync status."""
    status = _rndc_zone_status(zone_name)
    master_serial = None
    if s := status.get("serial"):
        try:
            master_serial = int(s)
        except ValueError:
            pass

    # DNSSEC: local config from rndc + external validation check
    dnssec_local = status.get("secure", "no").lower() == "yes"
    dnssec_external: dict = {}
    if dnssec_local:
        dnssec_external = _dnssec_external_check(zone_name)
    dnssec = {
        "local_secure": dnssec_local,
        "next_resign_time": status.get("next_resign_time"),
        "next_resign_node": status.get("next_resign_node"),
        "key_maintenance": status.get("key_maintenance"),
        "inline_signing": status.get("inline_signing"),
        **dnssec_external,
    }

    notify_ips = _get_zone_notify_ips(zone_name)
    notify_status: list[dict] = []
    for ip in notify_ips:
        result = _dig_soa_serial(zone_name, ip)
        result["in_sync"] = (
            result["serial"] == master_serial
            if (result["serial"] is not None and master_serial is not None)
            else None
        )
        notify_status.append(result)

    return {
        "zone": zone_name,
        "rndc": status,
        "master_serial": master_serial,
        "dnssec": dnssec,
        "notify_ips": notify_ips,
        "notify_status": notify_status,
    }


@router.put("/bind9/zones/{zone_name}/notify-ips")
async def update_bind9_notify_ips(
    zone_name: str, body: NotifyIpsBody, _: str = Depends(require_super_admin)
) -> dict:
    """Add or remove also-notify IPs for a zone in named.conf.local."""
    # Basic IP validation
    valid_ips = []
    for ip in body.notify_ips:
        ip = ip.strip()
        if re.match(r'^[\d.:a-fA-F]+$', ip) and ip:
            valid_ips.append(ip)
        else:
            raise HTTPException(422, f"Invalid IP address: '{ip}'")

    ok, err = _set_zone_notify_ips(zone_name, valid_ips)
    if not ok:
        raise HTTPException(500, err)

    # Reload BIND to pick up named.conf.local change
    out, stderr, rc = _run(["sudo", "rndc", "reload"], timeout=15)
    reloaded = rc == 0

    return {
        "ok": True,
        "notify_ips": valid_ips,
        "reloaded": reloaded,
        "reload_output": (out + stderr).strip() or "OK",
    }


@router.get("/bind9/zones/{zone_name}/records")
async def get_bind9_zone_records(zone_name: str, _: str = Depends(require_super_admin)) -> dict:
    """Return parsed DNS records for a zone."""
    zone_file = _bind9_zone_file(zone_name)
    if not zone_file:
        raise HTTPException(404, f"Zone file for '{zone_name}' not found")
    try:
        content = _read_file_sudo(zone_file)
    except Exception as e:
        raise HTTPException(500, f"Read failed: {e}")

    records = _parse_zone_records(content)
    default_ttl = ""
    origin = ""
    for line in content.splitlines():
        if line.startswith('$TTL'):
            parts = line.split(None, 1)
            if len(parts) > 1:
                default_ttl = parts[1].split(';')[0].strip()
        if line.startswith('$ORIGIN'):
            parts = line.split(None, 1)
            if len(parts) > 1:
                origin = parts[1].split(';')[0].strip()

    rndc = _rndc_zone_status(zone_name)

    return {
        "zone": zone_name,
        "file": zone_file,
        "default_ttl": default_ttl,
        "origin": origin,
        "serial": rndc.get("serial"),
        "records": records,
        "raw": content,
    }


@router.post("/bind9/zones/{zone_name}/records")
async def save_bind9_zone_records(
    zone_name: str, body: ZoneRecordsBody, _: str = Depends(require_super_admin)
) -> dict:
    """Save DNS records to zone file, auto-increment serial, reload zone."""
    zone_file = _bind9_zone_file(zone_name)
    if not zone_file:
        raise HTTPException(404, f"Zone file for '{zone_name}' not found")

    # Find SOA record and increment serial
    records = list(body.records)
    for r in records:
        if r.get("type") == "SOA":
            # SOA data: master. admin. (serial refresh retry expire min)
            # serial is 3rd token, may be inside parens
            data = r["data"]
            parts = data.split()
            if len(parts) >= 3:
                old_serial = parts[2].strip("();")
                new_serial = _increment_zone_serial(old_serial)
                r["data"] = data.replace(old_serial, new_serial, 1)
            break

    new_content = _build_zone_file(records, body.default_ttl, body.origin)

    # Validate with named-checkzone
    import tempfile, os
    with tempfile.NamedTemporaryFile(mode="w", suffix=".zone", delete=False, dir="/tmp") as tf:
        tf.write(new_content)
        tmp = tf.name
    try:
        out, err, rc = _run(
            ["sudo", "named-checkzone", zone_name, tmp], timeout=10
        )
        if rc != 0:
            raise HTTPException(422, f"Zone validation failed: {(out + err).strip()}")
    finally:
        try:
            os.unlink(tmp)
        except Exception:
            pass

    # Write via sudo tee
    try:
        import subprocess
        proc = subprocess.run(
            ["sudo", "tee", zone_file],
            input=new_content, capture_output=True, text=True, timeout=10,
        )
        if proc.returncode != 0:
            raise HTTPException(500, f"Write failed: {proc.stderr.strip()}")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, f"Write failed: {e}")

    reloaded = False
    reload_output = ""
    if body.reload:
        out, err, rc = _run(["sudo", "rndc", "reload", zone_name], timeout=15)
        reload_output = (out + err).strip()
        reloaded = rc == 0

    return {
        "ok": True,
        "file": zone_file,
        "reloaded": reloaded,
        "reload_output": reload_output or "OK",
    }


@router.post("/{key}/config")
async def post_config(key: str, body: ConfigSettingsBody, _: str = Depends(require_super_admin)) -> dict:
    path, exists = _resolve_config_path(key)
    if path is None:
        raise HTTPException(404, f"No config path known for service '{key}'")

    if not exists:
        raise HTTPException(404, f"Config file not found at {path}")

    try:
        content = Path(path).read_text(errors="replace")
    except Exception as e:
        raise HTTPException(500, f"Read failed: {e}")

    fmt = _KEY_FORMAT.get(key, _FMT_KV_EQUALS)
    section = "mysqld" if key in ("mysql", "mariadb") else None

    new_content, applied, not_found = _update_config_lines(content, body.settings, fmt, section)

    try:
        _write_conf(path, new_content)
    except Exception as e:
        raise HTTPException(500, f"Write failed: {e}")

    reloaded = False
    reload_output = ""
    if body.reload:
        cmd = _RELOAD_CMDS.get(key)
        if cmd:
            stdout, stderr, rc = _run(cmd, timeout=15)
            reload_output = (stdout + stderr).strip()
            reloaded = rc == 0

    return {
        "ok": True,
        "applied": applied,
        "not_found": not_found,
        "reloaded": reloaded,
        "reload_output": reload_output,
    }
