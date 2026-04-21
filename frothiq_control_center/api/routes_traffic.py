"""
IP Traffic Monitor — live gateway request feed, traffic statistics, and active blocks.

Data source: gw:audit Redis stream written by the gateway's AuditLoggerMiddleware.
Both the gateway and CC backend share Redis DB 2, so CC can read gateway telemetry directly.
Block data is read directly from the live nftables sets (blacklist + temp_ban).
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
import subprocess
import time
from collections import Counter, defaultdict

from fastapi import APIRouter, Depends, Query, Request

from frothiq_control_center.auth import TokenPayload, require_security_analyst

router = APIRouter(prefix="/traffic", tags=["traffic"])

_GW_AUDIT_STREAM = "gw:audit"
_PROC_NET_DEV = "/proc/net/dev"
_NFT_TABLE = "inet frothiq"


# ---------------------------------------------------------------------------
# nftables helpers
# ---------------------------------------------------------------------------

def _nft_list_set(set_name: str) -> list[str]:
    """Return the list of IPs/CIDRs in a named nftables set."""
    try:
        result = subprocess.run(
            ["nft", "list", "set", "inet", "frothiq", set_name],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode != 0:
            return []
        # Extract IPs/CIDRs from the elements block
        elements_match = re.search(r"elements\s*=\s*\{([^}]+)\}", result.stdout, re.DOTALL)
        if not elements_match:
            return []
        raw = elements_match.group(1)
        # Each element may have a "timeout X expires Y" annotation — strip those
        entries = []
        for token in re.split(r",", raw):
            token = token.strip()
            # nftables temp_ban elements look like: "1.2.3.4 timeout 1h expires 59m30s"
            ip_part = token.split()[0] if token else ""
            if ip_part and re.match(r"^[\d./a-fA-F:]+$", ip_part):
                entries.append(ip_part)
        return entries
    except Exception:
        return []


def _build_block_sets() -> tuple[set[str], list, set[str]]:
    """
    Return (blacklist_exact, blacklist_networks, temp_ban_exact).

    blacklist_exact: plain IPs as strings for O(1) lookup
    blacklist_networks: parsed ip_network objects for CIDR membership checks
    temp_ban_exact: temp-banned IPs (nftables dynamic set — always individual IPs)
    """
    raw_bl   = _nft_list_set("blacklist")
    temp_ban = set(_nft_list_set("temp_ban"))

    exact_bl: set[str] = set()
    networks: list = []
    for entry in raw_bl:
        if "/" in entry:
            try:
                networks.append(ipaddress.ip_network(entry, strict=False))
            except ValueError:
                pass
        else:
            exact_bl.add(entry)

    return exact_bl, networks, temp_ban


def _ip_in_blacklist(ip: str, exact: set[str], networks: list) -> bool:
    """Check if an IP is in the blacklist (exact match or CIDR membership)."""
    if ip in exact:
        return True
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in networks)
    except ValueError:
        return False


def _classify_ip(ip: str, blacklist: set[str], temp_ban: set[str]) -> str:
    """Return the enforcement status for a single IP (legacy call-site shim)."""
    if ip in blacklist:
        return "blocked"
    if ip in temp_ban:
        return "temp_banned"
    return "allowed"


# ---------------------------------------------------------------------------
# Audit stream helpers
# ---------------------------------------------------------------------------

def _parse_proc_net_dev() -> list[dict]:
    """Read /proc/net/dev and return per-interface byte/packet counters."""
    results = []
    try:
        with open(_PROC_NET_DEV) as f:
            lines = f.readlines()[2:]
        for line in lines:
            parts = line.split()
            if len(parts) < 11:
                continue
            iface = parts[0].rstrip(":")
            if iface == "lo":
                continue
            results.append({
                "interface": iface,
                "rx_bytes": int(parts[1]),
                "rx_packets": int(parts[2]),
                "rx_errors": int(parts[3]),
                "tx_bytes": int(parts[9]),
                "tx_packets": int(parts[10]),
                "tx_errors": int(parts[11]),
            })
    except Exception:
        pass
    return results


async def _read_audit_entries(redis, count: int = 500) -> list[dict]:
    """Read the most recent entries from the gateway audit stream."""
    try:
        raw = await redis.xrevrange(_GW_AUDIT_STREAM, count=count)
    except Exception:
        return []
    entries = []
    for stream_id, fields in raw:
        entry: dict = dict(fields)
        entry["_id"] = stream_id
        try:
            entry["ts"] = int(entry.get("ts", 0))
        except (ValueError, TypeError):
            entry["ts"] = 0
        try:
            entry["status"] = int(entry.get("status", 0))
        except (ValueError, TypeError):
            entry["status"] = 0
        try:
            entry["latency_ms"] = int(entry.get("latency_ms", 0))
        except (ValueError, TypeError):
            entry["latency_ms"] = 0
        entries.append(entry)
    return entries


def _security_action(
    ip: str,
    status: int,
    bl_exact: set[str],
    bl_networks: list,
    temp_ban: set[str],
    ip_error_rates: dict[str, float],
) -> str:
    """Determine security action for one request entry (CIDR-aware)."""
    if _ip_in_blacklist(ip, bl_exact, bl_networks):
        return "blocked"
    if ip in temp_ban:
        return "temp_banned"
    if ip_error_rates.get(ip, 0.0) >= 0.5 and ip_error_rates.get(ip + ":n", 0) >= 3:
        return "suspicious"
    if status in (401, 403):
        return "suspicious"
    return "allowed"


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.get("/live")
async def get_live_traffic(
    request: Request,
    limit: int = Query(100, ge=10, le=500),
    _: TokenPayload = Depends(require_security_analyst),
):
    """Most recent gateway requests annotated with security_action."""
    redis = request.state.redis
    entries, (bl_exact, bl_nets, temp_ban) = await asyncio.gather(
        _read_audit_entries(redis, count=limit),
        asyncio.to_thread(_build_block_sets),
    )

    # Compute per-IP error rates across visible window
    ip_total: Counter = Counter()
    ip_errors: Counter = Counter()
    for e in entries:
        ip = e.get("client_ip", "")
        st = e.get("status", 0)
        ip_total[ip] += 1
        if 400 <= st < 600:
            ip_errors[ip] += 1
    ip_error_rates: dict[str, float] = {
        ip: ip_errors[ip] / ip_total[ip] for ip in ip_total
    }
    # Stash count under a sentinel key so _security_action can read it
    for ip in ip_total:
        ip_error_rates[ip + ":n"] = ip_total[ip]

    for e in entries:
        ip = e.get("client_ip", "")
        e["security_action"] = _security_action(
            ip, e.get("status", 0), bl_exact, bl_nets, temp_ban, ip_error_rates
        )

    return {"entries": entries, "count": len(entries), "stream": _GW_AUDIT_STREAM}


@router.get("/ip-sessions")
async def get_ip_sessions(
    request: Request,
    limit: int = Query(200, ge=50, le=1000),
    _: TokenPayload = Depends(require_security_analyst),
):
    """
    Consolidated per-IP session view: one row per source IP with worst-case
    security status, request count, last path, and time range.
    This is the WordFence-style live view — aggregated, not per-request.
    """
    redis = request.state.redis
    entries, (bl_exact, bl_nets, temp_ban) = await asyncio.gather(
        _read_audit_entries(redis, count=limit),
        asyncio.to_thread(_build_block_sets),
    )

    # First pass: per-IP totals for suspicious detection
    ip_total: Counter = Counter()
    ip_errors: Counter = Counter()
    for e in entries:
        ip = e.get("client_ip", "")
        st = e.get("status", 0)
        ip_total[ip] += 1
        if 400 <= st < 600:
            ip_errors[ip] += 1

    # Second pass: build per-IP session rows
    sessions: dict[str, dict] = {}
    for e in entries:
        ip = e.get("client_ip", "")
        if not ip:
            continue
        ts  = e.get("ts", 0)
        st  = e.get("status", 0)
        ip_blocked = _ip_in_blacklist(ip, bl_exact, bl_nets)
        if ip not in sessions:
            sessions[ip] = {
                "ip": ip,
                "first_seen": ts,
                "last_seen": ts,
                "request_count": 0,
                "error_count": 0,
                "last_method": e.get("method", ""),
                "last_path": e.get("path", ""),
                "last_status": st,
                "paths_seen": [],
                "is_blocked": ip_blocked,
                "is_temp_banned": ip in temp_ban,
                "security_action": "allowed",
            }
        s = sessions[ip]
        s["request_count"] += 1
        if 400 <= st < 600:
            s["error_count"] += 1
        # Keep chronologically latest request details
        if ts >= s["last_seen"]:
            s["last_seen"]   = ts
            s["last_method"] = e.get("method", s["last_method"])
            s["last_path"]   = e.get("path", s["last_path"])
            s["last_status"] = st
        if ts < s["first_seen"]:
            s["first_seen"] = ts
        path = e.get("path", "")
        if path and path not in s["paths_seen"] and len(s["paths_seen"]) < 5:
            s["paths_seen"].append(path)

    # Third pass: assign worst-case security_action (CIDR-aware)
    _ACTION_RANK = {"blocked": 3, "temp_banned": 2, "suspicious": 1, "allowed": 0}
    for ip, s in sessions.items():
        if _ip_in_blacklist(ip, bl_exact, bl_nets):
            s["security_action"] = "blocked"
        elif ip in temp_ban:
            s["security_action"] = "temp_banned"
        elif ip_total[ip] >= 3 and ip_errors[ip] / ip_total[ip] >= 0.5:
            s["security_action"] = "suspicious"
        else:
            s["security_action"] = "allowed"

    # Sort: blocked first, then temp_banned, then suspicious, then by last_seen desc
    ranked = sorted(
        sessions.values(),
        key=lambda s: (-_ACTION_RANK[s["security_action"]], -s["last_seen"]),
    )
    return {"sessions": ranked, "count": len(ranked)}


@router.get("/active-blocks")
async def get_active_blocks(
    _: TokenPayload = Depends(require_security_analyst),
):
    """
    Return currently active nftables blocks: permanent blacklist + active temp bans.
    Reads live nft sets — reflects real enforcement state.
    """
    bl_exact, bl_nets, temp_ban = await asyncio.to_thread(_build_block_sets)
    all_bl = list(bl_exact) + [str(n) for n in bl_nets]
    return {
        "blacklist": sorted(all_bl),
        "blacklist_count": len(all_bl),
        "temp_ban": sorted(temp_ban),
        "temp_ban_count": len(temp_ban),
        "total_blocked": len(all_bl) + len(temp_ban),
    }


@router.get("/stats")
async def get_traffic_stats(
    request: Request,
    window_seconds: int = Query(300, ge=60, le=3600),
    _: TokenPayload = Depends(require_security_analyst),
):
    """Aggregated traffic statistics over a rolling time window, including block counts."""
    redis = request.state.redis
    entries, (bl_exact, bl_nets, temp_ban) = await asyncio.gather(
        _read_audit_entries(redis, count=2000),
        asyncio.to_thread(_build_block_sets),
    )

    now = int(time.time())
    cutoff = now - window_seconds
    recent = [e for e in entries if e.get("ts", 0) >= cutoff]

    ip_counts: Counter = Counter()
    status_counts: Counter = Counter()
    upstream_counts: Counter = Counter()
    path_counts: Counter = Counter()
    latencies: list[int] = []

    for e in recent:
        ip = e.get("client_ip", "unknown")
        status = e.get("status", 0)
        upstream = e.get("upstream", "unknown")
        path = e.get("path", "")
        lat = e.get("latency_ms", 0)

        ip_counts[ip] += 1

        status_class = f"{status // 100}xx" if 100 <= status < 600 else "other"
        status_counts[status_class] += 1

        upstream_counts[upstream] += 1

        if path:
            segments = path.strip("/").split("/")
            root = "/" + segments[0] if segments[0] else "/"
            path_counts[root] += 1

        if isinstance(lat, int) and lat > 0:
            latencies.append(lat)

    avg_latency = int(sum(latencies) / len(latencies)) if latencies else 0
    p95_latency = 0
    if latencies:
        sorted_lats = sorted(latencies)
        p95_latency = sorted_lats[int(len(sorted_lats) * 0.95)]

    req_per_sec = round(len(recent) / window_seconds, 2) if recent else 0.0
    error_count = sum(v for k, v in status_counts.items() if k in ("4xx", "5xx"))
    error_rate = round(error_count / len(recent) * 100, 1) if recent else 0.0

    return {
        "window_seconds": window_seconds,
        "total_requests": len(recent),
        "requests_per_second": req_per_sec,
        "error_rate_pct": error_rate,
        "avg_latency_ms": avg_latency,
        "p95_latency_ms": p95_latency,
        "top_ips": [{"ip": ip, "count": c} for ip, c in ip_counts.most_common(15)],
        "status_breakdown": dict(status_counts),
        "upstream_breakdown": dict(upstream_counts),
        "top_paths": [{"path": p, "count": c} for p, c in path_counts.most_common(10)],
        "network_interfaces": _parse_proc_net_dev(),
        "blocked_ips": len(bl_exact) + len(bl_nets),
        "temp_banned_ips": len(temp_ban),
        "total_blocked": len(bl_exact) + len(bl_nets) + len(temp_ban),
        "ts": now,
    }
