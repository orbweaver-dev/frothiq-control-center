"""
ClamAV Virus Scanner Management — status, database info, on-demand scans.
"""
from __future__ import annotations

import asyncio
import re
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from mc2.auth import TokenPayload, require_super_admin

router = APIRouter(prefix="/clamav", tags=["clamav"])
Auth = Annotated[TokenPayload, Depends(require_super_admin)]

_SCAN_LOG = Path("/var/log/clamav/clamav.log")
_FRESHCLAM_LOG = Path("/var/log/clamav/freshclam.log")
_DB_DIR = Path("/var/lib/clamav")


def _run(cmd: list[str], timeout: int = 30) -> tuple[int, str, str]:
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return r.returncode, r.stdout.strip(), r.stderr.strip()


def _service_active(name: str) -> bool:
    rc, out, _ = _run(["sudo", "systemctl", "is-active", name])
    return out.strip() == "active"


def _db_info(path: Path) -> dict | None:
    if not path.exists():
        return None
    rc, out, _ = _run(["sudo", "sigtool", "--info", str(path)])
    if rc != 0:
        return None
    info: dict = {}
    for line in out.splitlines():
        if ":" in line:
            k, _, v = line.partition(":")
            info[k.strip()] = v.strip()
    return info


def _version_string() -> str:
    rc, out, _ = _run(["clamscan", "--version"])
    return out.splitlines()[0] if out else "Unknown"


@router.get("/status")
def get_status(_: Auth):
    """ClamAV daemon status, database versions, log tail."""
    daemon_active = _service_active("clamav-daemon")
    freshclam_active = _service_active("clamav-freshclam")

    daily = _db_info(_DB_DIR / "daily.cld") or _db_info(_DB_DIR / "daily.cvd")
    main = _db_info(_DB_DIR / "main.cld") or _db_info(_DB_DIR / "main.cvd")
    bytecode = _db_info(_DB_DIR / "bytecode.cld") or _db_info(_DB_DIR / "bytecode.cvd")

    # Tail clamav log
    _, log_tail, _ = _run(["sudo", "tail", "-50", str(_SCAN_LOG)])
    # Tail freshclam log
    _, fc_tail, _ = _run(["sudo", "tail", "-30", str(_FRESHCLAM_LOG)])

    return {
        "daemon_active": daemon_active,
        "freshclam_active": freshclam_active,
        "version": _version_string(),
        "databases": {
            "daily": daily,
            "main": main,
            "bytecode": bytecode,
        },
        "scan_log": list(reversed(log_tail.splitlines())) if log_tail else [],
        "freshclam_log": list(reversed(fc_tail.splitlines())) if fc_tail else [],
    }


@router.post("/update-db")
def update_database(_: Auth):
    """Trigger freshclam database update."""
    rc, out, err = _run(["sudo", "freshclam"], timeout=120)
    return {
        "ok": rc == 0,
        "output": out or err,
    }


@router.post("/service/{action}")
def control_service(action: str, _: Auth):
    """Start, stop, or restart clamav-daemon or clamav-freshclam."""
    if action not in ("start", "stop", "restart"):
        raise HTTPException(400, "action must be start, stop, or restart")
    for svc in ("clamav-daemon", "clamav-freshclam"):
        _run(["sudo", "systemctl", action, svc])
    return {
        "ok": True,
        "daemon_active": _service_active("clamav-daemon"),
        "freshclam_active": _service_active("clamav-freshclam"),
    }


class ScanRequest(BaseModel):
    path: str
    recursive: bool = True
    max_depth: int = 10


# Scan results are stored in memory (one concurrent scan)
_scan_running = False
_scan_result: dict | None = None


@router.post("/scan")
async def trigger_scan(payload: ScanRequest, _: Auth):
    """Run clamscan on a path (non-blocking — returns immediately, poll /scan/result)."""
    global _scan_running, _scan_result
    if _scan_running:
        raise HTTPException(409, "A scan is already running")

    # Validate path is safe
    safe_prefixes = ("/home", "/var/www", "/tmp")
    if not any(payload.path.startswith(p) for p in safe_prefixes):
        raise HTTPException(400, f"Path must be under: {', '.join(safe_prefixes)}")

    _scan_running = True
    _scan_result = None

    async def _do_scan():
        global _scan_running, _scan_result
        cmd = ["sudo", "clamscan", "--no-summary", "--infected"]
        if payload.recursive:
            cmd += ["--recursive", f"--max-dir-depth={payload.max_depth}"]
        cmd.append(payload.path)
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await proc.communicate()
        infected_lines = [l for l in stdout.decode().splitlines() if l.strip()]
        _scan_result = {
            "path": payload.path,
            "return_code": proc.returncode,
            "infected_files": infected_lines,
            "infected_count": len(infected_lines),
            "clean": proc.returncode == 0,
            "error": stderr.decode().strip() if proc.returncode > 1 else None,
            "completed_at": datetime.utcnow().isoformat(),
        }
        _scan_running = False

    asyncio.create_task(_do_scan())
    return {"ok": True, "message": f"Scan started for {payload.path}. Poll /clamav/scan/result for results."}


@router.get("/scan/result")
def get_scan_result(_: Auth):
    """Get the result of the most recent on-demand scan."""
    return {
        "running": _scan_running,
        "result": _scan_result,
    }
