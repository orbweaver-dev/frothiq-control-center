"""
Fail2ban Configuration & Jail Manager.
Gracefully handles not-installed state; shows full management when installed.
"""
from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from frothiq_control_center.auth import TokenPayload, require_super_admin

router = APIRouter(prefix="/fail2ban", tags=["fail2ban"])
Auth = Annotated[TokenPayload, Depends(require_super_admin)]

_CLIENT = shutil.which("fail2ban-client") or "/usr/bin/fail2ban-client"


def _installed() -> bool:
    return Path(_CLIENT).exists()


def _run(cmd: list[str], timeout: int = 15) -> tuple[int, str, str]:
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return r.returncode, r.stdout.strip(), r.stderr.strip()


def _f2b(*args: str, timeout: int = 15) -> tuple[int, str, str]:
    return _run(["sudo", _CLIENT] + list(args), timeout=timeout)


def _service_active() -> bool:
    rc, out, _ = _run(["sudo", "systemctl", "is-active", "fail2ban"])
    return out.strip() == "active"


@router.get("/status")
def get_status(_: Auth):
    """Overall fail2ban status: installed, service state, jail list."""
    if not _installed():
        return {
            "installed": False,
            "active": False,
            "jails": [],
            "install_cmd": "sudo apt install fail2ban -y",
        }

    active = _service_active()
    if not active:
        return {"installed": True, "active": False, "jails": []}

    rc, out, _ = _f2b("status")
    jails: list[str] = []
    if rc == 0:
        m = re.search(r"Jail list:\s*(.+)", out)
        if m:
            jails = [j.strip() for j in m.group(1).split(",") if j.strip()]

    return {"installed": True, "active": True, "jails": jails}


@router.get("/jail/{jail_name}")
def get_jail(jail_name: str, _: Auth):
    """Get detailed status of a specific jail."""
    if not _installed():
        raise HTTPException(503, "fail2ban is not installed")

    rc, out, err = _f2b("status", jail_name)
    if rc != 0:
        raise HTTPException(500, err or f"Unknown jail: {jail_name}")

    # Parse key fields from output
    def _extract(label: str) -> str:
        m = re.search(rf"{label}:\s*(.+)", out)
        return m.group(1).strip() if m else ""

    currently_failed = _extract("Currently failed")
    total_failed = _extract("Total failed")
    currently_banned = _extract("Currently banned")
    total_banned = _extract("Total banned")
    banned_ips_str = _extract("Banned IP list")
    banned_ips = [ip.strip() for ip in banned_ips_str.split() if ip.strip()]
    filter_name = _extract("Filter")
    log_path = _extract("Log path")
    actions = _extract("Actions")

    return {
        "jail": jail_name,
        "currently_failed": int(currently_failed) if currently_failed.isdigit() else 0,
        "total_failed": int(total_failed) if total_failed.isdigit() else 0,
        "currently_banned": int(currently_banned) if currently_banned.isdigit() else 0,
        "total_banned": int(total_banned) if total_banned.isdigit() else 0,
        "banned_ips": banned_ips,
        "filter": filter_name,
        "log_path": log_path,
        "actions": actions,
        "raw": out,
    }


class UnbanRequest(BaseModel):
    jail: str
    ip: str


@router.post("/unban")
def unban_ip(payload: UnbanRequest, _: Auth):
    """Unban an IP from a specific jail."""
    if not _installed():
        raise HTTPException(503, "fail2ban is not installed")

    rc, out, err = _f2b("set", payload.jail, "unbanip", payload.ip)
    if rc != 0:
        raise HTTPException(500, err or "Unban failed")
    return {"ok": True, "ip": payload.ip, "jail": payload.jail}


@router.post("/service/{action}")
def control_service(action: str, _: Auth):
    """Start, stop, or restart fail2ban."""
    if action not in ("start", "stop", "restart", "reload"):
        raise HTTPException(400, "action must be start, stop, restart, or reload")
    if not _installed():
        raise HTTPException(503, "fail2ban is not installed")
    _run(["sudo", "systemctl", action, "fail2ban"])
    return {"ok": True, "active": _service_active()}


@router.get("/config")
def get_config(_: Auth):
    """Read fail2ban.conf and jail.conf content."""
    if not _installed():
        raise HTTPException(503, "fail2ban is not installed")

    result = {}
    for name, path in [("fail2ban_conf", "/etc/fail2ban/fail2ban.conf"),
                       ("jail_conf", "/etc/fail2ban/jail.conf"),
                       ("jail_local", "/etc/fail2ban/jail.local")]:
        p = Path(path)
        if p.exists():
            rc, out, _ = _run(["sudo", "cat", str(p)])
            result[name] = out if rc == 0 else None
        else:
            result[name] = None
    return result
