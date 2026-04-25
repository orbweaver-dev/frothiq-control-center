"""
HTTP Policy Enforcement Engine

Background loop that reads all traffic sources (gateway audit stream, nginx, Apache),
aggregates per-IP behaviour over a rolling window, evaluates against policy rules,
and automatically adds violators to the nftables temp_ban set.

Rules evaluated (in priority order):
  1. MALICIOUS_PATH  — known scanner/attack paths in the request URI
  2. SCANNER_UA      — known scanner/bot user-agent strings
  3. RATE_ABUSE      — ≥ RATE_THRESHOLD requests in the analysis window
  4. ERROR_STORM     — ≥ ERROR_RATE_THRESHOLD % errors with ≥ ERROR_COUNT_MIN requests

Actions taken:
  - temp_ban: added to nftables temp_ban set (1h timeout, auto-expiry)
  - All enforcement actions logged to Redis stream  cc:enforcement:log
  - Whitelisted IPs are never touched
"""

from __future__ import annotations

import asyncio
import logging
import re
import subprocess
import time
from collections import defaultdict
from datetime import datetime

logger = logging.getLogger("frothiq.enforcement")

# ---------------------------------------------------------------------------
# Tunables
# ---------------------------------------------------------------------------

SCAN_INTERVAL    = 60        # seconds between sweeps
WINDOW_SECONDS   = 300       # traffic window to analyse (last 5 min)
RATE_THRESHOLD   = 300       # req/window before rate-abuse ban
ERROR_COUNT_MIN  = 8         # minimum requests before error-rate rule fires
ERROR_RATE_THRESHOLD = 0.65  # 65 % errors → ban
TEMP_BAN_TIMEOUT = "1h"
LOG_STREAM       = "cc:enforcement:log"
LOG_MAXLEN       = 2000      # max entries kept in Redis stream

# IPs that should never be auto-banned regardless of behaviour
_NEVER_BAN = frozenset({
    "127.0.0.1", "::1",
    "144.202.64.118",   # wh1 nginx IP
    "144.202.77.105",   # wh1 apache IP
})

# ---------------------------------------------------------------------------
# Pattern libraries
# ---------------------------------------------------------------------------

# Request paths that indicate a scanner, exploit attempt, or attack
_MALICIOUS_PATH_RE = re.compile(
    r"(?i)("
    r"\.env$|/\.git|/\.svn|/\.htaccess|/\.htpasswd|/\.DS_Store"
    r"|/wp-admin|/wp-login\.php|/xmlrpc\.php|/wp-config\.php"
    r"|/phpmyadmin|/pma/|/mysql|/myadmin"
    r"|/admin\.php|/administrator|/joomla"
    r"|/etc/passwd|/etc/shadow|/proc/self"
    r"|/actuator|/actuator/|/api/swagger|/swagger-ui"
    r"|/console|/manager/html|/solr/admin"
    r"|union\s+select|information_schema|sleep\("
    r"|\.\.\/|%2e%2e|%252e|\.\.%2f"
    r"|cmd=|exec\(|system\(|passthru\("
    r"|/cgi-bin/|\.cgi\?"
    r"|/boaform|/GponForm|/rom-0"
    r"|/autodiscover/autodiscover\.xml"
    r"|/owa/|/ecp/|/exchange/"
    r")"
)

# User-agent strings that identify known scanners, crawlers, and exploit tools
_SCANNER_UA_RE = re.compile(
    r"(?i)("
    r"masscan|zgrab|nmap|nikto|sqlmap|dirbuster|gobuster"
    r"|nuclei|acunetix|netsparker|openvas|w3af"
    r"|hydra|medusa|crowbar|burpsuite"
    r"|python-requests/|go-http-client/1\.1$|libwww-perl"
    r"|curl/[0-9]|wget/[0-9]"  # bare curl/wget — not in a browser UA
    r"|scrapy|httpx|aiohttp/[0-9]"
    r"|zgrab|internet-measurement|shodan|censys|binaryedge"
    r"|\bbot\b.*scan|\bscanner\b|\bcrawler\b"
    r")"
)


# ---------------------------------------------------------------------------
# nftables helpers
# ---------------------------------------------------------------------------

def _nft_is_whitelisted(ip: str) -> bool:
    try:
        r = subprocess.run(
            ["/usr/sbin/nft", "get", "element", "inet", "frothiq", "whitelist", f"{{ {ip} }}"],
            capture_output=True, timeout=3,
        )
        return r.returncode == 0
    except Exception:
        return False


def _nft_is_banned(ip: str) -> bool:
    """True if already in blacklist or temp_ban."""
    for set_name in ("blacklist", "temp_ban"):
        try:
            r = subprocess.run(
                ["/usr/sbin/nft", "get", "element", "inet", "frothiq", set_name, f"{{ {ip} }}"],
                capture_output=True, timeout=3,
            )
            if r.returncode == 0:
                return True
        except Exception:
            pass
    return False


def _nft_temp_ban(ip: str) -> bool:
    """Add ip to temp_ban set with 1h timeout. Returns True on success."""
    try:
        r = subprocess.run(
            ["/usr/sbin/nft", "add", "element", "inet", "frothiq", "temp_ban",
             f"{{ {ip} timeout {TEMP_BAN_TIMEOUT} }}"],
            capture_output=True, timeout=5,
        )
        return r.returncode == 0
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Traffic readers (sync — called via asyncio.to_thread)
# ---------------------------------------------------------------------------

import os

_GW_AUDIT_STREAM = "gw:audit"
_NGINX_LOG       = "/var/log/nginx/access.log"
_APACHE_LOG_DIR  = "/var/log/virtualmin"

_RE_NGINX_NEW = re.compile(
    r'^(\S+) (\S+) - \S+ \[([^\]]+)\] "(\w+) (\S+) [^"]+" (\d+) \d+ "[^"]*" "([^"]*)"'
)
_RE_NGINX_OLD = re.compile(
    r'^(\S+) - \S+ \[([^\]]+)\] "(\w+) (\S+) [^"]+" (\d+) \d+ "[^"]*" "([^"]*)"'
)
_RE_APACHE = re.compile(
    r'^(\S+) - \S+ \[([^\]]+)\] "(\w+) (\S+) [^"]+" (\d+) \d+ "[^"]*" "([^"]*)"'
)
_TS_FMT = "%d/%b/%Y:%H:%M:%S %z"


def _parse_nginx_recent(cutoff: float) -> list[dict]:
    entries = []
    try:
        with open(_NGINX_LOG, "rb") as fh:
            fh.seek(0, 2)
            size = fh.tell()
            fh.seek(max(0, size - 512 * 1024))
            lines = fh.read().decode("utf-8", errors="replace").splitlines()
    except Exception:
        return []

    for line in lines:
        line = line.strip()
        m = _RE_NGINX_NEW.match(line)
        if m:
            host, ip, ts_str, method, path, status, ua = m.groups()
        else:
            m = _RE_NGINX_OLD.match(line)
            if m:
                ip, ts_str, method, path, status, ua = m.groups()
                host = "unknown"
            else:
                continue
        try:
            ts = datetime.strptime(ts_str, _TS_FMT).timestamp()
        except Exception:
            continue
        if ts < cutoff:
            continue
        entries.append({"ip": ip, "path": path, "status": int(status), "ua": ua, "ts": ts})
    return entries


def _parse_apache_recent(cutoff: float) -> list[dict]:
    entries = []
    try:
        r = subprocess.run(
            ["sudo", "ls", _APACHE_LOG_DIR],
            capture_output=True, text=True, timeout=5,
        )
        filenames = [f for f in r.stdout.strip().splitlines()
                     if f.endswith("_access_log") and not f.endswith(".gz")]
    except Exception:
        return []

    for fname in filenames:
        try:
            r = subprocess.run(
                ["sudo", "tail", "-c", "131072", f"{_APACHE_LOG_DIR}/{fname}"],
                capture_output=True, text=True, timeout=5,
            )
            for line in r.stdout.splitlines():
                line = line.strip()
                m = _RE_APACHE.match(line)
                if not m:
                    continue
                ip, ts_str, method, path, status, ua = m.groups()
                try:
                    ts = datetime.strptime(ts_str, _TS_FMT).timestamp()
                except Exception:
                    continue
                if ts < cutoff:
                    continue
                entries.append({"ip": ip, "path": path, "status": int(status), "ua": ua, "ts": ts})
        except Exception:
            continue
    return entries


# ---------------------------------------------------------------------------
# Core enforcement logic
# ---------------------------------------------------------------------------

async def _read_gateway_recent(redis, cutoff: float) -> list[dict]:
    """Read gateway audit stream entries newer than cutoff."""
    try:
        raw = await redis.xrevrange(_GW_AUDIT_STREAM, count=2000)
    except Exception:
        return []
    entries = []
    for _sid, fields in raw:
        try:
            ts = int(fields.get("ts", 0))
        except (ValueError, TypeError):
            ts = 0
        if ts < cutoff:
            continue
        entries.append({
            "ip": fields.get("client_ip", ""),
            "path": fields.get("path", ""),
            "status": int(fields.get("status", 0) or 0),
            "ua": fields.get("user_agent", ""),
            "ts": ts,
        })
    return entries


async def enforce_policies(redis) -> dict:
    """
    Single enforcement sweep. Returns a summary dict with counts.
    """
    now    = time.time()
    cutoff = now - WINDOW_SECONDS

    # Collect traffic from all sources in parallel
    gw_entries, nginx_entries, apache_entries = await asyncio.gather(
        _read_gateway_recent(redis, cutoff),
        asyncio.to_thread(_parse_nginx_recent, cutoff),
        asyncio.to_thread(_parse_apache_recent, cutoff),
    )

    all_entries = [*gw_entries, *nginx_entries, *apache_entries]
    if not all_entries:
        return {"checked": 0, "banned": 0, "skipped": 0}

    # Aggregate per-IP
    ip_stats: dict[str, dict] = defaultdict(lambda: {
        "req": 0, "errors": 0, "paths": [], "uas": set(),
    })
    for e in all_entries:
        ip = e["ip"]
        if not ip or ip in _NEVER_BAN or ":" in ip:  # skip IPv6 (temp_ban set is ipv4_addr only)
            continue
        s = ip_stats[ip]
        s["req"] += 1
        if 400 <= e["status"] < 600:
            s["errors"] += 1
        if len(s["paths"]) < 5:
            s["paths"].append(e["path"])
        if e["ua"]:
            s["uas"].add(e["ua"][:120])

    # Evaluate each IP
    banned   = 0
    skipped  = 0
    checked  = len(ip_stats)

    whitelist_cache: set[str] = set()

    for ip, s in ip_stats.items():
        # Determine violation reason
        reason = None

        # Rule 1: malicious path
        for path in s["paths"]:
            if path and _MALICIOUS_PATH_RE.search(path):
                reason = f"malicious_path:{path[:80]}"
                break

        # Rule 2: scanner user-agent
        if reason is None:
            for ua in s["uas"]:
                if ua and _SCANNER_UA_RE.search(ua):
                    reason = f"scanner_ua:{ua[:60]}"
                    break

        # Rule 3: rate abuse
        if reason is None and s["req"] >= RATE_THRESHOLD:
            reason = f"rate_abuse:{s['req']}req/{WINDOW_SECONDS}s"

        # Rule 4: error storm
        if reason is None and s["req"] >= ERROR_COUNT_MIN:
            err_rate = s["errors"] / s["req"]
            if err_rate >= ERROR_RATE_THRESHOLD:
                reason = f"error_storm:{s['errors']}/{s['req']}({err_rate:.0%})"

        if reason is None:
            continue  # clean IP

        # Check whitelist and existing ban
        if ip in whitelist_cache:
            skipped += 1
            continue

        already_handled = await asyncio.to_thread(_nft_is_banned, ip)
        if already_handled:
            skipped += 1
            continue

        whitelisted = await asyncio.to_thread(_nft_is_whitelisted, ip)
        if whitelisted:
            whitelist_cache.add(ip)
            skipped += 1
            continue

        # Execute ban
        success = await asyncio.to_thread(_nft_temp_ban, ip)
        if success:
            banned += 1
            logger.info("enforcement: TEMP-BAN %s — %s", ip, reason)
            # Record to enforcement log stream
            try:
                await redis.xadd(
                    LOG_STREAM,
                    {
                        "ts":     str(int(now)),
                        "ip":     ip,
                        "action": "temp_ban",
                        "reason": reason,
                        "reqs":   str(s["req"]),
                        "errors": str(s["errors"]),
                    },
                    maxlen=LOG_MAXLEN,
                    approximate=True,
                )
            except Exception as _xadd_err:
                logger.warning("enforcement: xadd failed: %s", _xadd_err)
        else:
            logger.warning("enforcement: ban command failed for %s", ip)

    return {"checked": checked, "banned": banned, "skipped": skipped, "window": WINDOW_SECONDS}


# ---------------------------------------------------------------------------
# Background loop (started from main.py lifespan)
# ---------------------------------------------------------------------------

async def run_enforcement_loop(redis) -> None:
    """
    Long-running asyncio task. Runs enforce_policies() every SCAN_INTERVAL seconds.
    Logs a startup message, then runs silently unless violations are found.
    """
    await asyncio.sleep(15)  # let other services settle first
    logger.info(
        "enforcement_engine: started — interval=%ds window=%ds "
        "rate_threshold=%d error_threshold=%.0f%%",
        SCAN_INTERVAL, WINDOW_SECONDS, RATE_THRESHOLD, ERROR_RATE_THRESHOLD * 100,
    )

    while True:
        try:
            result = await enforce_policies(redis)
            if result["banned"] > 0:
                logger.info(
                    "enforcement: sweep complete — checked=%d banned=%d skipped=%d",
                    result["checked"], result["banned"], result["skipped"],
                )
        except asyncio.CancelledError:
            break
        except Exception as exc:
            logger.error("enforcement_engine: sweep error: %s", exc)
        await asyncio.sleep(SCAN_INTERVAL)
