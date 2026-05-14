"""
Logrotate Rule Editor — read/write /etc/logrotate.d/* configurations.
"""
from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from frothiq_control_center.auth import TokenPayload, require_super_admin

router = APIRouter(prefix="/logrotate", tags=["logrotate"])
Auth = Annotated[TokenPayload, Depends(require_super_admin)]

_LOGROTATE_D = Path("/etc/logrotate.d")
_LOGROTATE_CONF = Path("/etc/logrotate.conf")

_ALLOWED_NAMES = set("abcdefghijklmnopqrstuvwxyz0123456789-_.")


def _run(cmd: list[str], timeout: int = 15) -> tuple[int, str, str]:
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return r.returncode, r.stdout.strip(), r.stderr.strip()


def _safe_name(name: str) -> str:
    clean = "".join(c for c in name.lower() if c in _ALLOWED_NAMES)
    if not clean:
        raise HTTPException(400, "Invalid rule name")
    return clean


@router.get("")
def list_rules(_: Auth):
    """List all logrotate rules in /etc/logrotate.d/."""
    rules = []
    for f in sorted(_LOGROTATE_D.iterdir()):
        if f.is_file():
            rc, content, _ = _run(["sudo", "cat", str(f)])
            rules.append({
                "name": f.name,
                "path": str(f),
                "content": content if rc == 0 else "",
                "size": f.stat().st_size,
            })
    return {"rules": rules, "total": len(rules)}


@router.get("/global")
def get_global_config(_: Auth):
    """Get the global logrotate.conf."""
    rc, content, _ = _run(["sudo", "cat", str(_LOGROTATE_CONF)])
    return {"path": str(_LOGROTATE_CONF), "content": content if rc == 0 else ""}


@router.get("/{name}")
def get_rule(name: str, _: Auth):
    """Get a specific logrotate rule."""
    safe = _safe_name(name)
    path = _LOGROTATE_D / safe
    if not path.exists():
        raise HTTPException(404, f"Rule '{safe}' not found")
    rc, content, _ = _run(["sudo", "cat", str(path)])
    return {"name": safe, "path": str(path), "content": content}


class RuleWrite(BaseModel):
    name: str
    content: str


@router.put("/{name}")
def save_rule(name: str, payload: RuleWrite, _: Auth):
    """Create or update a logrotate rule. Content is written verbatim."""
    safe = _safe_name(name)
    path = _LOGROTATE_D / safe

    # Basic safety: reject content that tries to escape the rule file
    if ".." in payload.content or "/etc/shadow" in payload.content:
        raise HTTPException(400, "Potentially unsafe content rejected")

    # Write via sudo tee
    rc, _, err = _run(
        ["sudo", "tee", str(path)],
        timeout=10,
    )
    # Use a separate approach since we need to pipe content
    proc = subprocess.run(
        ["sudo", "tee", str(path)],
        input=payload.content,
        capture_output=True,
        text=True,
        timeout=10,
    )
    if proc.returncode != 0:
        raise HTTPException(500, proc.stderr or "Write failed")

    return {"ok": True, "path": str(path)}


@router.delete("/{name}")
def delete_rule(name: str, _: Auth):
    """Delete a logrotate rule."""
    safe = _safe_name(name)
    path = _LOGROTATE_D / safe
    if not path.exists():
        raise HTTPException(404, f"Rule '{safe}' not found")

    # Protect system-critical rules
    protected = {"cron", "dpkg", "apt", "syslog", "rsyslog"}
    if safe in protected:
        raise HTTPException(403, f"Cannot delete protected rule: {safe}")

    rc, _, err = _run(["sudo", "rm", str(path)])
    if rc != 0:
        raise HTTPException(500, err or "Delete failed")
    return {"ok": True}


@router.post("/test")
def test_logrotate(_: Auth):
    """Run logrotate in debug/dry-run mode to validate all configs."""
    rc, out, err = _run(["sudo", "logrotate", "--debug", str(_LOGROTATE_CONF)], timeout=30)
    return {"ok": rc == 0, "output": out or err}
