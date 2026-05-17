"""
Per-User & Per-Group Disk Quota Management — reads and writes Linux quotas.
"""
from __future__ import annotations

import csv
import io
import subprocess
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from mc2.auth import TokenPayload, require_super_admin

router = APIRouter(prefix="/disk-quotas", tags=["disk-quotas"])
Auth = Annotated[TokenPayload, Depends(require_super_admin)]

# Blocks = 1 KiB in Linux quota system
BLOCKS_PER_MB = 1024
FILESYSTEM = "/"  # Main filesystem


def _run(cmd: list[str], timeout: int = 30) -> tuple[int, str, str]:
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return r.returncode, r.stdout.strip(), r.stderr.strip()


def _parse_repquota(csv_text: str, entity_type: str) -> list[dict]:
    reader = csv.DictReader(io.StringIO(csv_text))
    entries = []
    for row in reader:
        name = list(row.values())[0]  # first column is username/groupname
        block_used = int(row.get("BlockUsed", 0) or 0)
        block_soft = int(row.get("BlockSoftLimit", 0) or 0)
        block_hard = int(row.get("BlockHardLimit", 0) or 0)
        file_used = int(row.get("FileUsed", 0) or 0)
        file_soft = int(row.get("FileSoftLimit", 0) or 0)
        file_hard = int(row.get("FileHardLimit", 0) or 0)
        entries.append({
            "name": name,
            "type": entity_type,
            "block_used_mb": round(block_used / BLOCKS_PER_MB, 2),
            "block_soft_mb": round(block_soft / BLOCKS_PER_MB, 2) if block_soft else None,
            "block_hard_mb": round(block_hard / BLOCKS_PER_MB, 2) if block_hard else None,
            "block_used_kb": block_used,
            "block_soft_kb": block_soft,
            "block_hard_kb": block_hard,
            "inode_used": file_used,
            "inode_soft": file_soft if file_soft else None,
            "inode_hard": file_hard if file_hard else None,
            "over_limit": block_hard > 0 and block_used > block_hard,
            "near_limit": block_hard > 0 and block_used > block_hard * 0.8,
        })
    return entries


@router.get("")
def list_quotas(_: Auth, entity_type: Literal["user", "group", "both"] = "both"):
    """List all user and/or group disk quotas."""
    users: list[dict] = []
    groups: list[dict] = []

    if entity_type in ("user", "both"):
        rc, out, err = _run(["sudo", "repquota", "-a", "-u", "--output=csv"])
        if rc == 0 and out:
            users = _parse_repquota(out, "user")

    if entity_type in ("group", "both"):
        rc, out, err = _run(["sudo", "repquota", "-a", "-g", "--output=csv"])
        if rc == 0 and out:
            groups = _parse_repquota(out, "group")

    all_entries = users + groups
    total_used_mb = sum(e["block_used_mb"] for e in all_entries)
    return {
        "users": users,
        "groups": groups,
        "total_used_mb": round(total_used_mb, 2),
    }


class QuotaSet(BaseModel):
    name: str
    entity_type: Literal["user", "group"]
    block_soft_mb: float | None = None   # None = 0 (no limit)
    block_hard_mb: float | None = None   # None = 0 (no limit)
    inode_soft: int | None = None
    inode_hard: int | None = None


@router.put("")
def set_quota(payload: QuotaSet, _: Auth):
    """Set disk quota for a user or group."""
    flag = "-u" if payload.entity_type == "user" else "-g"

    block_soft = int((payload.block_soft_mb or 0) * BLOCKS_PER_MB)
    block_hard = int((payload.block_hard_mb or 0) * BLOCKS_PER_MB)
    inode_soft = payload.inode_soft or 0
    inode_hard = payload.inode_hard or 0

    rc, _, err = _run([
        "sudo", "setquota",
        flag, payload.name,
        str(block_soft), str(block_hard),
        str(inode_soft), str(inode_hard),
        FILESYSTEM,
    ])
    if rc != 0:
        raise HTTPException(500, err or "Failed to set quota")
    return {"ok": True, "name": payload.name}


@router.delete("/{entity_type}/{name}")
def remove_quota(entity_type: Literal["user", "group"], name: str, _: Auth):
    """Remove quota limits for a user or group (set all to 0)."""
    flag = "-u" if entity_type == "user" else "-g"
    rc, _, err = _run(["sudo", "setquota", flag, name, "0", "0", "0", "0", FILESYSTEM])
    if rc != 0:
        raise HTTPException(500, err or "Failed to remove quota")
    return {"ok": True}
