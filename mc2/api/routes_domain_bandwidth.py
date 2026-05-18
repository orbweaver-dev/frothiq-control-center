"""
Per-Domain Bandwidth & Traffic Reports.

Closes TASK-2026-00346.

Distinct from routes_bandwidth.py (per-interface). This module parses
Apache access logs to produce per-domain transfer totals, request counts,
and unique-visitor estimates. Designed to be cheap: scans recent log
lines only.

Endpoints (all under /domain-bandwidth):
  GET /                          — summary across all domains over N days
  GET /{domain}                  — detailed per-domain breakdown
"""

from __future__ import annotations

import os
import re
import subprocess
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException

from mc2.auth import TokenPayload, require_super_admin

router = APIRouter(prefix="/domain-bandwidth", tags=["domain-bandwidth"])

Auth = Annotated[TokenPayload, Depends(require_super_admin)]


LOG_DIRS = [
    "/var/log/virtualmin",
    "/etc/apache2/logs",
]
LOG_SUFFIXES = ["_access_log", "_access.log", "-access.log"]


_LOG_RE = re.compile(
    r"^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+"
    r'"(?P<method>\S+)\s(?P<path>\S+)\s\S+"\s+(?P<status>\d{3})\s+(?P<bytes>\d+|-)'
)


def _sudo_ls(dir_path: str) -> list[str]:
    """List files in a privileged log directory via sudo. Returns basenames."""
    r = subprocess.run(
        ["sudo", "ls", "-1", dir_path],
        capture_output=True, text=True, timeout=10,
    )
    if r.returncode != 0:
        return []
    return [line.strip() for line in r.stdout.splitlines() if line.strip()]


def _sudo_cat(path: str) -> str | None:
    """Read a privileged log file via sudo. None on failure."""
    r = subprocess.run(
        ["sudo", "cat", path],
        capture_output=True, text=True, timeout=30,
    )
    return r.stdout if r.returncode == 0 else None


def _candidate_logs_for_domain(domain: str) -> list[str]:
    out: list[str] = []
    for d in LOG_DIRS:
        files = _sudo_ls(d)
        for suffix in LOG_SUFFIXES:
            target = domain + suffix
            if target in files:
                out.append(os.path.join(d, target))
    return out


def _enumerate_domains() -> list[str]:
    found: set[str] = set()
    for d in LOG_DIRS:
        for f in _sudo_ls(d):
            for suffix in LOG_SUFFIXES:
                if f.endswith(suffix) and not f.endswith(".gz"):
                    name = f[: -len(suffix)]
                    if "." in name and not name.startswith("."):
                        found.add(name)
                    break
    return sorted(found)


def _scan_log(path: str, since: datetime) -> dict:
    bytes_total = 0
    requests = 0
    unique_ips: set[str] = set()
    status_counts: dict[str, int] = defaultdict(int)
    top_paths: dict[str, int] = defaultdict(int)

    content = _sudo_cat(path)
    if content is None:
        return {"error": "log not readable"}

    for line in content.splitlines():
        m = _LOG_RE.match(line)
        if not m:
            continue
        try:
            ts = datetime.strptime(m.group("ts").split()[0], "%d/%b/%Y:%H:%M:%S")
        except ValueError:
            continue
        if ts < since:
            continue
        b = m.group("bytes")
        bytes_total += int(b) if b.isdigit() else 0
        requests += 1
        unique_ips.add(m.group("ip"))
        status_counts[m.group("status")] += 1
        top_paths[m.group("path")] += 1

    return {
        "bytes": bytes_total,
        "requests": requests,
        "unique_ips": len(unique_ips),
        "status_counts": dict(status_counts),
        "top_paths": sorted(top_paths.items(), key=lambda kv: -kv[1])[:10],
    }


@router.get("")
def summary(_: Auth, days: int = 1):
    if days < 1 or days > 30:
        raise HTTPException(status_code=400, detail="days must be 1-30")
    since = datetime.now() - timedelta(days=days)
    domains = _enumerate_domains()
    rows: list[dict] = []
    totals = {"bytes": 0, "requests": 0}
    for d in domains:
        agg = {"bytes": 0, "requests": 0, "unique_ips": 0, "logs": 0}
        for log_path in _candidate_logs_for_domain(d):
            res = _scan_log(log_path, since)
            if "error" in res:
                continue
            agg["bytes"] += res["bytes"]
            agg["requests"] += res["requests"]
            agg["unique_ips"] += res["unique_ips"]
            agg["logs"] += 1
        rows.append({"domain": d, **agg})
        totals["bytes"] += agg["bytes"]
        totals["requests"] += agg["requests"]
    rows.sort(key=lambda r: -r["bytes"])
    return {
        "window_days": days,
        "since": since.replace(tzinfo=timezone.utc).isoformat(),
        "totals": totals,
        "domains": rows,
    }


@router.get("/{domain}")
def detail(domain: str, _: Auth, days: int = 7):
    if days < 1 or days > 30:
        raise HTTPException(status_code=400, detail="days must be 1-30")
    since = datetime.now() - timedelta(days=days)
    logs = _candidate_logs_for_domain(domain)
    if not logs:
        raise HTTPException(status_code=404, detail=f"no apache log found for {domain}")

    merged_bytes = 0
    merged_requests = 0
    merged_uniques: set[str] = set()
    status_counts: dict[str, int] = defaultdict(int)
    top_paths: dict[str, int] = defaultdict(int)

    for log_path in logs:
        content = _sudo_cat(log_path)
        if content is None:
            continue
        for line in content.splitlines():
            m = _LOG_RE.match(line)
            if not m:
                continue
            try:
                ts = datetime.strptime(m.group("ts").split()[0], "%d/%b/%Y:%H:%M:%S")
            except ValueError:
                continue
            if ts < since:
                continue
            b = m.group("bytes")
            merged_bytes += int(b) if b.isdigit() else 0
            merged_requests += 1
            merged_uniques.add(m.group("ip"))
            status_counts[m.group("status")] += 1
            top_paths[m.group("path")] += 1

    return {
        "domain": domain,
        "window_days": days,
        "since": since.replace(tzinfo=timezone.utc).isoformat(),
        "logs_scanned": logs,
        "bytes": merged_bytes,
        "requests": merged_requests,
        "unique_ips": len(merged_uniques),
        "status_counts": dict(status_counts),
        "top_paths": sorted(top_paths.items(), key=lambda kv: -kv[1])[:25],
    }
