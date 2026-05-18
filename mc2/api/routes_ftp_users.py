"""
FTP / SFTP User Manager — read/write Virtualmin FTP-capable users.

Closes TASK-2026-00343.

Wraps `virtualmin create-user / delete-user / modify-user` with the FTP
flags exposed via the WebOps UI. A user is treated as "FTP" when it has
the FTP service enabled in Virtualmin (i.e. `Shell` includes /usr/bin/ftponly
or `ftp` flag is set per the multiline output).
"""

from __future__ import annotations

import re
import subprocess
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from mc2.auth import TokenPayload, require_super_admin

router = APIRouter(prefix="/ftp-users", tags=["ftp-users"])

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


def _parse_multiline(text: str) -> list[dict]:
    users: list[dict] = []
    current: dict | None = None
    for raw in text.splitlines():
        if not raw:
            continue
        if not raw.startswith("    "):
            if current:
                users.append(current)
            current = {"raw": {}}
        else:
            line = raw.strip()
            if ":" in line and current is not None:
                k, _, v = line.partition(":")
                current["raw"][k.strip()] = v.strip()
    if current:
        users.append(current)
    return users


def _is_ftp(raw: dict) -> bool:
    """Detect FTP-capable users from multiline output. Virtualmin reports
    `FTP login` or sets the `Shell` to a known ftp-only shell."""
    if (raw.get("FTP login") or "").lower() == "yes":
        return True
    shell = (raw.get("Shell") or "").lower()
    return "ftponly" in shell or "ftp-only" in shell or shell.endswith("/false")


def _project(raw: dict, domain_fallback: str) -> dict:
    return {
        "user": raw.get("User"),
        "email": raw.get("Email address") or None,
        "domain": raw.get("Domain") or domain_fallback,
        "real_name": raw.get("Real name") or None,
        "home_dir": raw.get("Home directory"),
        "shell": raw.get("Shell"),
        "disabled": (raw.get("Disabled") or "").lower() == "yes",
        "quota_used": raw.get("Home quota used") or None,
        "quota_total": raw.get("Home quota") or None,
        "ftp_enabled": _is_ftp(raw),
    }


@router.get("")
def index(_: Auth):
    """All FTP-enabled users across all Virtualmin domains."""
    domains = _list_domains()
    out: list[dict] = []
    errors: list[str] = []
    domain_counts: dict[str, int] = {}
    for d in domains:
        rc, txt, err = _vmin("list-users", "--domain", d, "--multiline")
        if rc != 0:
            errors.append(f"{d}: rc={rc} {err[:120]}")
            continue
        ftp_users = []
        for u in _parse_multiline(txt):
            row = _project(u["raw"], d)
            if row["ftp_enabled"]:
                ftp_users.append(row)
        domain_counts[d] = len(ftp_users)
        out.extend(ftp_users)
    out.sort(key=lambda u: (u.get("domain") or "", u.get("user") or ""))
    return {
        "users": out,
        "totals": {
            "domains": len(domains),
            "ftp_users": len(out),
            "disabled": sum(1 for u in out if u["disabled"]),
        },
        "domain_counts": domain_counts,
        "errors": errors,
    }


_USER_RE = re.compile(r"^[A-Za-z0-9._-]{1,32}$")


class CreateUser(BaseModel):
    domain: str = Field(..., min_length=3, max_length=253)
    username: str = Field(..., min_length=1, max_length=32)
    password: str = Field(..., min_length=8, max_length=128)
    real_name: str | None = None
    quota_blocks: int | None = None  # 1024-byte blocks; None = unlimited


@router.post("")
def create(body: CreateUser, _: Auth):
    if not _USER_RE.match(body.username):
        raise HTTPException(status_code=400, detail="invalid username; use [A-Za-z0-9._-]{1,32}")
    args: list[str] = [
        "create-user",
        "--domain", body.domain,
        "--user", body.username,
        "--pass", body.password,
        "--ftp",
    ]
    if body.real_name:
        args += ["--real", body.real_name]
    if body.quota_blocks is not None:
        args += ["--quota", str(body.quota_blocks)]

    rc, out, err = _vmin(*args)
    if rc != 0:
        raise HTTPException(status_code=502, detail=f"virtualmin rc={rc}: {(err or out)[:300]}")
    return {"created": True, "username": body.username, "domain": body.domain}


class ModifyUser(BaseModel):
    disabled: bool | None = None
    ftp_enabled: bool | None = None
    new_password: str | None = Field(default=None, min_length=8, max_length=128)
    real_name: str | None = None


@router.put("/{domain}/{username}")
def modify(domain: str, username: str, body: ModifyUser, _: Auth):
    if not _USER_RE.match(username):
        raise HTTPException(status_code=400, detail="invalid username")
    args: list[str] = ["modify-user", "--domain", domain, "--user", username]

    if body.disabled is True:
        args.append("--disable")
    elif body.disabled is False:
        args.append("--enable")

    if body.ftp_enabled is True:
        args.append("--enable-ftp")
    elif body.ftp_enabled is False:
        args.append("--disable-ftp")

    if body.new_password:
        args += ["--pass", body.new_password]
    if body.real_name is not None:
        args += ["--real", body.real_name]

    if len(args) == 4:
        # Nothing to actually change beyond identification
        return {"updated": False, "reason": "no changes specified"}

    rc, out, err = _vmin(*args)
    if rc != 0:
        raise HTTPException(status_code=502, detail=f"virtualmin rc={rc}: {(err or out)[:300]}")
    return {"updated": True}


@router.delete("/{domain}/{username}")
def delete(domain: str, username: str, _: Auth):
    if not _USER_RE.match(username):
        raise HTTPException(status_code=400, detail="invalid username")
    rc, out, err = _vmin("delete-user", "--domain", domain, "--user", username)
    if rc != 0:
        raise HTTPException(status_code=502, detail=f"virtualmin rc={rc}: {(err or out)[:300]}")
    return {"deleted": True}
