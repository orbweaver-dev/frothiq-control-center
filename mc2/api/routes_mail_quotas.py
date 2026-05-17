"""
Per-Mailbox Disk Quota Management — Virtualmin user quota read/write.
"""
from __future__ import annotations

import json
import subprocess

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Annotated

from fastapi import Depends
from mc3.auth import TokenPayload, require_super_admin

router = APIRouter(prefix="/mail-quotas", tags=["mail-quotas"])
Auth = Annotated[TokenPayload, Depends(require_super_admin)]

# 1 block = 1 KiB in Virtualmin/Linux quota system
BYTES_PER_BLOCK = 1024


def _run(cmd: list[str], timeout: int = 30) -> tuple[int, str, str]:
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return r.returncode, r.stdout.strip(), r.stderr.strip()


def _vmin(*args: str, timeout: int = 30) -> tuple[int, str, str]:
    return _run(["sudo", "virtualmin"] + list(args), timeout=timeout)


def _list_domains() -> list[str]:
    rc, out, _ = _vmin("list-domains", "--name-only")
    return [d for d in out.splitlines() if d.strip()] if rc == 0 else []


def _bytes_to_mb(b: int) -> float:
    return round(b / (1024 * 1024), 2)


def _mb_to_blocks(mb: float) -> int:
    """Convert MB to 1-KiB blocks."""
    return int(mb * 1024)


@router.get("")
def list_quotas(_: Auth, domain: str | None = None):
    """List all mailbox users with quota usage."""
    domains = [domain] if domain else _list_domains()
    users: list[dict] = []

    for d in domains:
        rc, out, _ = _vmin("list-users", "--domain", d, "--json")
        if rc != 0 or not out:
            continue
        try:
            data = json.loads(out)
        except Exception:
            continue
        for item in data.get("data", []):
            v = item.get("values", {})
            user_type = v.get("user_type", [""])[0]
            if "database" in user_type.lower():
                continue
            byte_quota = int(v.get("home_byte_quota", ["0"])[0] or 0)
            byte_used = int(v.get("home_byte_quota_used", ["0"])[0] or 0)
            users.append({
                "username": v.get("user", [""])[0],
                "email": item.get("name", ""),
                "domain": d,
                "quota_mb": None if byte_quota == 0 else _bytes_to_mb(byte_quota),
                "used_mb": _bytes_to_mb(byte_used),
                "used_bytes": byte_used,
                "unlimited": byte_quota == 0,
                "home_directory": v.get("home_directory", [""])[0],
                "user_type": user_type,
                "disabled": v.get("disabled", ["No"])[0] == "Yes",
            })

    users.sort(key=lambda u: (u["domain"], u["username"]))
    return {"users": users, "total": len(users)}


class QuotaUpdate(BaseModel):
    domain: str
    username: str
    quota_mb: float | None = None  # None = unlimited (0 blocks)


@router.put("")
def set_quota(payload: QuotaUpdate, _: Auth):
    """Set or remove disk quota for a mailbox user."""
    blocks = 0 if payload.quota_mb is None else _mb_to_blocks(payload.quota_mb)
    if payload.quota_mb is not None and payload.quota_mb < 0:
        raise HTTPException(400, "quota_mb must be >= 0 (use null for unlimited)")

    rc, _, err = _vmin(
        "modify-user",
        "--domain", payload.domain,
        "--user", payload.username,
        "--quota", str(blocks),
    )
    if rc != 0:
        raise HTTPException(500, err or "Failed to update quota")
    return {
        "ok": True,
        "username": payload.username,
        "quota_mb": payload.quota_mb,
        "unlimited": payload.quota_mb is None,
    }
