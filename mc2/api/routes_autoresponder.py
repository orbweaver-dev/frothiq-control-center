"""
Email Autoresponder & Vacation Manager — reads/writes Virtualmin per-mailbox
autoresponder settings.

Closes TASK-2026-00341.

Wraps `virtualmin modify-user --autoreply / --no-autoreply` and exposes a
flat per-mailbox view that the WebOps UI consumes.
"""

from __future__ import annotations

import re
import subprocess
from typing import Annotated, Literal

from fastapi import APIRouter, Body, Depends, HTTPException
from pydantic import BaseModel

from mc2.auth import TokenPayload, require_super_admin

router = APIRouter(prefix="/autoresponder", tags=["autoresponder"])

Auth = Annotated[TokenPayload, Depends(require_super_admin)]


def _run(cmd: list[str], timeout: int = 30) -> tuple[int, str, str]:
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return r.returncode, r.stdout, r.stderr


def _vmin(*args: str) -> tuple[int, str, str]:
    return _run(["sudo", "virtualmin", *args])


def _list_domains() -> list[str]:
    rc, out, _err = _vmin("list-domains", "--name-only")
    if rc != 0:
        return []
    return [d.strip() for d in out.splitlines() if d.strip()]


def _parse_users_multiline(text: str) -> list[dict]:
    """Parse `virtualmin list-users --multiline` output. Same shape as
    routes_mailman; duplicated to keep modules independent."""
    users: list[dict] = []
    current: dict | None = None
    for raw in text.splitlines():
        if not raw:
            continue
        if not raw.startswith("    "):
            if current:
                users.append(current)
            current = {"raw": {}, "key": raw.strip()}
        else:
            line = raw.strip()
            if ":" in line and current is not None:
                k, _, v = line.partition(":")
                current["raw"][k.strip()] = v.strip()
    if current:
        users.append(current)
    return users


def _autoreply_state(raw: dict) -> dict:
    """Project raw virtualmin attrs to autoresponder fields."""
    on = (raw.get("Auto-responder") or "").lower() == "yes"
    msg = raw.get("Auto-responder message") or ""
    start = raw.get("Auto-responder start") or ""
    end = raw.get("Auto-responder end") or ""
    period = raw.get("Auto-responder period") or ""
    return {
        "enabled": on,
        "message": msg,
        "start": start or None,
        "end": end or None,
        "period_seconds": int(period) if period.isdigit() else None,
    }


@router.get("")
def autoresponder_index(_: Auth):
    """Return every mailbox across every domain with its autoresponder state."""
    domains = _list_domains()
    out: list[dict] = []
    errors: list[str] = []
    for d in domains:
        rc, txt, err = _vmin("list-users", "--domain", d, "--multiline")
        if rc != 0:
            errors.append(f"{d}: rc={rc} {err[:120]}")
            continue
        for u in _parse_users_multiline(txt):
            raw = u["raw"]
            email = raw.get("Email address")
            if not email or "@" not in email:
                continue
            entry = {
                "email": email,
                "user": raw.get("User"),
                "domain": raw.get("Domain") or d,
                "real_name": raw.get("Real name") or None,
            }
            entry.update(_autoreply_state(raw))
            out.append(entry)
    out.sort(key=lambda u: (u.get("domain") or "", u["email"]))
    summary = {
        "total": len(out),
        "active": sum(1 for u in out if u["enabled"]),
    }
    return {"users": out, "summary": summary, "errors": errors}


@router.get("/{email}")
def autoresponder_show(email: str, _: Auth):
    user, _, domain = email.partition("@")
    if not domain:
        raise HTTPException(status_code=400, detail="invalid email")
    rc, txt, err = _vmin("list-users", "--domain", domain, "--user", user, "--multiline")
    if rc != 0:
        raise HTTPException(status_code=502, detail=f"virtualmin rc={rc}: {err[:200]}")
    parsed = _parse_users_multiline(txt)
    if not parsed:
        raise HTTPException(status_code=404, detail="user not found")
    raw = parsed[0]["raw"]
    return {"email": email, **_autoreply_state(raw)}


class AutoreplyUpdate(BaseModel):
    enabled: bool
    message: str | None = None
    start: str | None = None      # ISO date/datetime; virtualmin accepts yyyy-mm-dd
    end: str | None = None
    period_seconds: int | None = None


_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2})?)?$")


@router.put("/{email}")
def autoresponder_update(email: str, body: AutoreplyUpdate, _: Auth):
    user, _, domain = email.partition("@")
    if not domain:
        raise HTTPException(status_code=400, detail="invalid email")

    args: list[str] = ["modify-user", "--domain", domain, "--user", user]
    if not body.enabled:
        args.append("--no-autoreply")
    else:
        if not body.message:
            raise HTTPException(status_code=400, detail="message is required when enabling")
        args.extend(["--autoreply", body.message])
        if body.start:
            if not _DATE_RE.match(body.start):
                raise HTTPException(status_code=400, detail="start must be yyyy-mm-dd")
            args.extend(["--autoreply-start", body.start])
        else:
            args.append("--no-autoreply-start")
        if body.end:
            if not _DATE_RE.match(body.end):
                raise HTTPException(status_code=400, detail="end must be yyyy-mm-dd")
            args.extend(["--autoreply-end", body.end])
        else:
            args.append("--no-autoreply-end")
        if body.period_seconds is not None and body.period_seconds > 0:
            args.extend(["--autoreply-period", str(body.period_seconds)])

    rc, out, err = _vmin(*args)
    if rc != 0:
        raise HTTPException(status_code=502, detail=f"virtualmin rc={rc}: {(err or out)[:300]}")
    # Echo back fresh state
    return autoresponder_show(email, _)  # type: ignore[arg-type]
