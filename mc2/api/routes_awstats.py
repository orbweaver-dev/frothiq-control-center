"""
AWStats per-domain web analytics.

Closes TASK-2026-00364.

Discovers domains via `/etc/awstats/awstats.<domain>.conf` files and parses
the corresponding AWStats data file directly (the documented section-based
text format) for the most recent month. No HTML scraping.

Data file naming:  awstatsMMYYYY.<domain>.txt
Data dir per conf: DirData=… directive in each per-domain conf
"""

from __future__ import annotations

import os
import re
import subprocess
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException

from mc2.auth import TokenPayload, require_super_admin

router = APIRouter(prefix="/awstats", tags=["awstats"])

Auth = Annotated[TokenPayload, Depends(require_super_admin)]


AWSTATS_CONF_DIR = "/etc/awstats"
AWSTATS_BIN = "/usr/bin/awstats"


# ─────────────────────────────────────────────────────────────────────────────
# Discovery
# ─────────────────────────────────────────────────────────────────────────────

def _list_configs() -> list[str]:
    """Return per-domain conf basenames (the part between awstats. and .conf)."""
    out: list[str] = []
    try:
        for f in os.listdir(AWSTATS_CONF_DIR):
            if f.startswith("awstats.") and f.endswith(".conf"):
                name = f[len("awstats."):-len(".conf")]
                if name and name != "conf" and name != "local":
                    out.append(name)
    except (OSError, PermissionError):
        return []
    return sorted(set(out))


def _read_conf_value(conf_path: str, key: str) -> str | None:
    """Read a single key from an awstats conf, via sudo cat (root-owned)."""
    rc, txt, _ = _sudo_read(conf_path)
    if rc != 0:
        return None
    for line in txt.splitlines():
        line = line.strip()
        if line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        if k.strip() == key:
            return v.strip().strip('"')
    return None


def _sudo_read(path: str) -> tuple[int, str, str]:
    r = subprocess.run(["sudo", "cat", path], capture_output=True, text=True, timeout=15)
    return r.returncode, r.stdout, r.stderr


def _dir_data_for(domain: str) -> str | None:
    conf = os.path.join(AWSTATS_CONF_DIR, f"awstats.{domain}.conf")
    if not os.path.exists(conf):
        return None
    return _read_conf_value(conf, "DirData")


def _latest_data_file(domain: str) -> tuple[str | None, str | None]:
    """Locate the most-recent awstatsMMYYYY.<domain>.txt file. Returns
    (path, period_label) like ('/.../awstats052026.foo.txt', '052026')."""
    data_dir = _dir_data_for(domain)
    if not data_dir:
        return None, None
    # Use sudo ls because the dir is owned by the virtualmin domain user
    r = subprocess.run(["sudo", "ls", "-1", data_dir], capture_output=True, text=True, timeout=15)
    if r.returncode != 0:
        return None, None
    candidates: list[tuple[str, str]] = []
    pat = re.compile(rf"^awstats(\d{{6}})\.{re.escape(domain)}\.txt$")
    for f in r.stdout.splitlines():
        m = pat.match(f.strip())
        if m:
            candidates.append((m.group(1), os.path.join(data_dir, f.strip())))
    if not candidates:
        return None, None
    # Period is MMYYYY — sort by YYYY*100+MM
    def key(c):
        p = c[0]
        return int(p[2:]) * 100 + int(p[:2])
    candidates.sort(key=key, reverse=True)
    period, path = candidates[0]
    return path, period


# ─────────────────────────────────────────────────────────────────────────────
# Data file parser
# ─────────────────────────────────────────────────────────────────────────────

def _parse_data_file(path: str) -> dict:
    """Parse the section-based AWStats text format into a dict of sections.
    Each section is a list of tokenized rows."""
    rc, text, _ = _sudo_read(path)
    if rc != 0:
        return {}
    sections: dict[str, list[list[str]]] = {}
    current: str | None = None
    for raw in text.splitlines():
        line = raw.rstrip("\r")
        if line.startswith("BEGIN_"):
            current = line.split()[0][6:]  # strip BEGIN_
            sections[current] = []
            continue
        if line.startswith("END_"):
            current = None
            continue
        if current is None or not line.strip():
            continue
        sections[current].append(line.split())
    return sections


def _row_dict(section: list[list[str]]) -> dict[str, str]:
    """Some sections (GENERAL) are key-value rows like:
       TotalVisits 1234 …
       Convert to dict, taking only the first value (count)."""
    out: dict[str, str] = {}
    for row in section:
        if not row:
            continue
        key = row[0]
        val = row[1] if len(row) > 1 else ""
        out[key] = val
    return out


def _summarize(sections: dict[str, list[list[str]]]) -> dict:
    g = _row_dict(sections.get("GENERAL", []))

    def _int(v: str | None) -> int:
        try: return int(v) if v else 0
        except ValueError: return 0

    # DAY rows: YYYYMMDD pages hits bytes visits
    days = []
    for row in sections.get("DAY", []):
        if len(row) >= 5 and row[0].isdigit():
            days.append({
                "date":     row[0],
                "pages":    _int(row[1]),
                "hits":     _int(row[2]),
                "bytes":    _int(row[3]),
                "visits":   _int(row[4]),
            })
    days.sort(key=lambda r: r["date"])

    # TOP PAGES (SIDER): "/url pages bytes entry exit"
    top_pages = []
    for row in sections.get("SIDER", [])[:25]:
        if len(row) >= 3:
            top_pages.append({
                "url":   row[0],
                "pages": _int(row[1]),
                "bytes": _int(row[2]),
            })

    # TOP REFERRERS (SEREFERRALS): "engine pages hits"
    top_referrers = []
    for row in sections.get("SEREFERRALS", [])[:15]:
        if len(row) >= 3:
            top_referrers.append({
                "name":  row[0],
                "pages": _int(row[1]),
                "hits":  _int(row[2]),
            })

    # TOP BROWSERS (BROWSER): "browser_id hits"
    top_browsers = []
    for row in sections.get("BROWSER", [])[:10]:
        if len(row) >= 2:
            top_browsers.append({"browser": row[0], "hits": _int(row[1])})

    # TOP OS (OS): "os_id hits"
    top_os = []
    for row in sections.get("OS", [])[:10]:
        if len(row) >= 2:
            top_os.append({"os": row[0], "hits": _int(row[1])})

    return {
        "total_unique_visitors":   _int(g.get("TotalUnique")),
        "total_visits":            _int(g.get("TotalVisits")),
        "total_pages":             _int(g.get("TotalPages")),
        "total_hits":              _int(g.get("TotalHits")),
        "total_bandwidth_bytes":   _int(g.get("TotalBandwidth")),
        "last_line":               g.get("LastLine"),
        "last_update":             g.get("LastUpdate"),
        "days":                    days,
        "top_pages":               top_pages,
        "top_referrers":           top_referrers,
        "top_browsers":            top_browsers,
        "top_os":                  top_os,
    }


# ─────────────────────────────────────────────────────────────────────────────
# API
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/domains")
def domains(_: Auth):
    """Configured AWStats domains with whether a data file exists."""
    rows: list[dict] = []
    for d in _list_configs():
        path, period = _latest_data_file(d)
        rows.append({
            "domain": d,
            "has_data": path is not None,
            "latest_period": period,
        })
    rows.sort(key=lambda r: (not r["has_data"], r["domain"]))
    return {"domains": rows, "count": len(rows)}


@router.get("/{domain}")
def detail(domain: str, _: Auth):
    """Per-domain summary from the most-recent month's data file."""
    if not re.match(r"^[A-Za-z0-9.\-_]{1,253}$", domain):
        raise HTTPException(status_code=400, detail="invalid domain")
    path, period = _latest_data_file(domain)
    if not path:
        raise HTTPException(status_code=404, detail=f"no awstats data file for {domain}")
    sections = _parse_data_file(path)
    if not sections:
        raise HTTPException(status_code=502, detail="data file empty or unreadable")
    summary = _summarize(sections)
    return {
        "domain": domain,
        "period": period,
        "data_file": path,
        **summary,
    }


@router.post("/{domain}/update")
def update(domain: str, _: Auth):
    """Run awstats -update for one domain. Used after big log activity."""
    if not re.match(r"^[A-Za-z0-9.\-_]{1,253}$", domain):
        raise HTTPException(status_code=400, detail="invalid domain")
    if not os.path.exists(os.path.join(AWSTATS_CONF_DIR, f"awstats.{domain}.conf")):
        raise HTTPException(status_code=404, detail=f"no awstats conf for {domain}")
    r = subprocess.run(
        ["sudo", AWSTATS_BIN, f"-config={domain}", "-update"],
        capture_output=True, text=True, timeout=300,
    )
    return {
        "domain": domain,
        "rc": r.returncode,
        "stdout_tail": r.stdout.splitlines()[-15:] if r.stdout else [],
        "stderr_tail": r.stderr.splitlines()[-15:] if r.stderr else [],
    }
