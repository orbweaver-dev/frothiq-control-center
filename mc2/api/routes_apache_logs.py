"""
Per-Domain Apache Log Viewer — reads access_log and error_log per Virtualmin domain.
"""
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query

from mc2.auth import TokenPayload, require_super_admin

router = APIRouter(prefix="/apache-logs", tags=["apache-logs"])
Auth = Annotated[TokenPayload, Depends(require_super_admin)]


def _run(cmd: list[str], timeout: int = 15) -> tuple[int, str, str]:
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return r.returncode, r.stdout.strip(), r.stderr.strip()


def _list_virtualmin_domains() -> list[dict]:
    rc, out, _ = _run(["sudo", "virtualmin", "list-domains", "--json"])
    if rc != 0 or not out:
        return []
    try:
        data = json.loads(out)
        result = []
        for item in data.get("data", []):
            v = item.get("values", {})
            domain = item.get("name", "")
            home = v.get("home_directory", [""])[0]
            result.append({"domain": domain, "home": home})
        return result
    except Exception:
        return []


def _log_path(home: str, log_type: str) -> Path:
    base = Path(home) / "logs"
    if log_type == "error":
        return base / "error_log"
    return base / "access_log"


@router.get("/domains")
def list_log_domains(_: Auth):
    """List all domains with their log file info."""
    domains = _list_virtualmin_domains()
    result = []
    for d in domains:
        access = _log_path(d["home"], "access")
        error = _log_path(d["home"], "error")
        result.append({
            "domain": d["domain"],
            "access_log": str(access),
            "error_log": str(error),
            "access_exists": access.exists(),
            "error_exists": error.exists(),
            "access_size_mb": round(access.stat().st_size / (1024 * 1024), 2) if access.exists() else 0,
            "error_size_mb": round(error.stat().st_size / (1024 * 1024), 2) if error.exists() else 0,
        })
    return {"domains": result}


@router.get("/tail")
def tail_log(
    _: Auth,
    domain: str = Query(...),
    log_type: str = Query("access", pattern="^(access|error)$"),
    lines: int = Query(100, ge=10, le=2000),
    search: str | None = Query(None),
):
    """Return the last N lines of a domain's log, with optional keyword search."""
    domains = _list_virtualmin_domains()
    home = next((d["home"] for d in domains if d["domain"] == domain), None)
    if not home:
        raise HTTPException(404, f"Domain '{domain}' not found")

    log_file = _log_path(home, log_type)
    if not log_file.exists():
        raise HTTPException(404, f"Log file not found: {log_file}")

    # Read last N lines via tail
    rc, out, err = _run(["sudo", "tail", f"-{lines * 3 if search else lines}", str(log_file)])
    if rc != 0:
        raise HTTPException(500, err or "Failed to read log")

    raw_lines = out.splitlines()

    # Apply search filter
    if search:
        raw_lines = [ln for ln in raw_lines if search.lower() in ln.lower()]

    # Return most recent first, up to `lines` count
    raw_lines = raw_lines[-lines:]
    raw_lines.reverse()

    return {
        "domain": domain,
        "log_type": log_type,
        "log_file": str(log_file),
        "lines": raw_lines,
        "count": len(raw_lines),
    }
