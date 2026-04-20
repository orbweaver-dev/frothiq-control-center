"""
IP Traffic Monitor — live gateway request feed and traffic statistics.

Data source: gw:audit Redis stream written by the gateway's AuditLoggerMiddleware.
Both the gateway and CC backend share Redis DB 2, so CC can read gateway telemetry directly.
"""

from __future__ import annotations

import time
from collections import Counter

from fastapi import APIRouter, Depends, Query, Request

from frothiq_control_center.auth import TokenPayload, require_security_analyst

router = APIRouter(prefix="/traffic", tags=["traffic"])

_GW_AUDIT_STREAM = "gw:audit"
_PROC_NET_DEV = "/proc/net/dev"


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


@router.get("/live")
async def get_live_traffic(
    request: Request,
    limit: int = Query(100, ge=10, le=500),
    _: TokenPayload = Depends(require_security_analyst),
):
    """Most recent gateway requests — live feed for the traffic dashboard."""
    redis = request.state.redis
    entries = await _read_audit_entries(redis, count=limit)
    return {"entries": entries, "count": len(entries), "stream": _GW_AUDIT_STREAM}


@router.get("/stats")
async def get_traffic_stats(
    request: Request,
    window_seconds: int = Query(300, ge=60, le=3600),
    _: TokenPayload = Depends(require_security_analyst),
):
    """Aggregated traffic statistics over a rolling time window."""
    redis = request.state.redis
    entries = await _read_audit_entries(redis, count=2000)

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

        # Group status codes into classes (2xx, 3xx, 4xx, 5xx)
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
        "ts": now,
    }
