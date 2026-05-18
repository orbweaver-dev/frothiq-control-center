"""
ProFTPD Global Configuration.

Closes TASK-2026-00363.

Read-mostly view of the server-wide ProFTPD configuration plus controlled
restart action. The intent is observability + lifecycle control, NOT a
free-form config editor — every directive write goes through an allow-list
so we cannot accidentally lock ourselves out of the FTP service.

Endpoints:
  GET    /proftpd                — service state + selected directives + active sessions
  POST   /proftpd/restart        — systemctl restart proftpd (super_admin only)
  POST   /proftpd/reload         — systemctl reload proftpd
  PUT    /proftpd/directive      — set a single allow-listed directive
"""

from __future__ import annotations

import re
import subprocess
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from mc2.auth import TokenPayload, require_super_admin

router = APIRouter(prefix="/proftpd", tags=["proftpd"])

Auth = Annotated[TokenPayload, Depends(require_super_admin)]


PROFTPD_CONF = "/etc/proftpd/proftpd.conf"

# Allow-listed directives the API may write. Anything else is intentionally
# read-only — limits blast radius if the endpoint is ever abused.
EDITABLE_DIRECTIVES = {
    "PassivePorts": re.compile(r"^\d{4,5}\s+\d{4,5}$"),    # "49152 65534"
    "MaxInstances": re.compile(r"^\d{1,5}$"),
    "MaxClients":   re.compile(r"^\d{1,5}(?:\s+.+)?$"),
    "DefaultRoot":  re.compile(r"^[\S ]+$"),                # path + optional group
    "TimeoutIdle":  re.compile(r"^\d{2,5}$"),
    "TimeoutLogin": re.compile(r"^\d{2,5}$"),
}

DISPLAY_DIRECTIVES = [
    "ServerName", "ServerType", "DefaultServer", "Port",
    "PassivePorts", "MaxInstances", "MaxClients",
    "DefaultRoot", "UseReverseDNS", "IdentLookups",
    "TimeoutIdle", "TimeoutLogin",
    "TLSEngine", "TLSRequired", "TLSRSACertificateFile", "TLSRSACertificateKeyFile",
]


def _run(cmd: list[str], timeout: int = 15) -> tuple[int, str, str]:
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return r.returncode, r.stdout, r.stderr


def _systemctl_active(unit: str) -> tuple[str, bool]:
    rc, out, err = _run(["systemctl", "is-active", unit])
    status = (out or err or "unknown").strip()
    return status, status == "active"


def _read_conf() -> str:
    try:
        with open(PROFTPD_CONF) as f:
            return f.read()
    except (OSError, PermissionError):
        return ""


def _parse_directives(text: str) -> dict[str, str]:
    """Return the first top-level value for each directive of interest.
    Does NOT descend into <VirtualHost> / <Anonymous> blocks."""
    out: dict[str, str] = {}
    depth = 0
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("</") and line.endswith(">"):
            depth = max(0, depth - 1)
            continue
        if line.startswith("<") and line.endswith(">") and not line.startswith("</"):
            depth += 1
            continue
        if depth != 0:
            continue
        # "Directive  value …"
        parts = line.split(None, 1)
        if len(parts) < 2:
            continue
        name, value = parts[0], parts[1].strip()
        if name in DISPLAY_DIRECTIVES and name not in out:
            out[name] = value
    return out


def _active_sessions() -> dict:
    """`ftpwho` if available, otherwise `proftpd ftpcount`-equivalent."""
    rc, out, _ = _run(["sudo", "ftpwho"])
    if rc == 0 and out.strip():
        lines = [l for l in out.splitlines() if l.strip()]
        return {"available": True, "raw": out, "line_count": len(lines)}
    return {"available": False, "raw": None, "line_count": 0}


@router.get("")
def status(_: Auth):
    svc_text, svc_active = _systemctl_active("proftpd.service")
    conf_text = _read_conf()
    directives = _parse_directives(conf_text)
    return {
        "service": {
            "unit": "proftpd.service",
            "active": svc_active,
            "status_text": svc_text,
        },
        "config_path": PROFTPD_CONF,
        "config_readable": bool(conf_text),
        "directives": directives,
        "editable_directives": sorted(EDITABLE_DIRECTIVES.keys()),
        "sessions": _active_sessions(),
    }


def _lifecycle(action: str) -> dict:
    rc, out, err = _run(["sudo", "systemctl", action, "proftpd.service"], timeout=30)
    if rc != 0:
        raise HTTPException(status_code=502, detail=f"systemctl {action} rc={rc}: {(err or out)[:300]}")
    _, active = _systemctl_active("proftpd.service")
    return {"action": action, "ok": True, "active_after": active}


@router.post("/restart")
def restart(_: Auth):
    return _lifecycle("restart")


@router.post("/reload")
def reload(_: Auth):
    return _lifecycle("reload")


class DirectiveUpdate(BaseModel):
    name: str = Field(..., min_length=1, max_length=40)
    value: str = Field(..., min_length=1, max_length=200)


@router.put("/directive")
def set_directive(body: DirectiveUpdate, _: Auth):
    if body.name not in EDITABLE_DIRECTIVES:
        raise HTTPException(status_code=400, detail=f"directive '{body.name}' is not in the allow-list")
    if not EDITABLE_DIRECTIVES[body.name].match(body.value):
        raise HTTPException(status_code=400, detail=f"value did not pass validation for {body.name}")

    text = _read_conf()
    if not text:
        raise HTTPException(status_code=500, detail="proftpd.conf is not readable")

    pattern = re.compile(rf"^(\s*){re.escape(body.name)}\b.*$", re.MULTILINE)
    new_line = f"{body.name} {body.value}"

    if pattern.search(text):
        new_text = pattern.sub(rf"\g<1>{new_line}", text, count=1)
        action = "updated"
    else:
        # Append a clearly-marked block to the top-level config.
        new_text = text.rstrip() + f"\n\n# MC²-managed directive ({body.name})\n{new_line}\n"
        action = "appended"

    # Write via sudo tee so root-owned config remains owned correctly.
    try:
        proc = subprocess.run(
            ["sudo", "tee", PROFTPD_CONF],
            input=new_text, capture_output=True, text=True, timeout=10,
        )
        if proc.returncode != 0:
            raise HTTPException(status_code=502, detail=f"tee rc={proc.returncode}: {proc.stderr[:200]}")
    except FileNotFoundError:
        raise HTTPException(status_code=500, detail="sudo not available")

    # Validate config syntax — proftpd -t exits non-zero on any parse error.
    rc, _out, err = _run(["sudo", "proftpd", "-t"])
    if rc != 0:
        # Roll back to prior text
        subprocess.run(["sudo", "tee", PROFTPD_CONF], input=text, capture_output=True, text=True, timeout=10)
        raise HTTPException(status_code=502, detail=f"proftpd -t failed; reverted. {(err)[:300]}")

    return {"action": action, "directive": body.name, "value": body.value}
