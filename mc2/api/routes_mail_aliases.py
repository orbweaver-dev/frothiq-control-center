"""
Email Alias & Forwarding Manager — reads/writes Virtualmin mail aliases.
"""
from __future__ import annotations

import json
import subprocess
from typing import Annotated

from fastapi import APIRouter, Body, Depends, HTTPException
from pydantic import BaseModel

from mc3.auth import TokenPayload, require_super_admin

router = APIRouter(prefix="/mail-aliases", tags=["mail-aliases"])

Auth = Annotated[TokenPayload, Depends(require_super_admin)]


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _run(cmd: list[str], timeout: int = 20) -> tuple[int, str, str]:
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return r.returncode, r.stdout.strip(), r.stderr.strip()


def _vmin(*args: str) -> tuple[int, str, str]:
    return _run(["sudo", "virtualmin"] + list(args))


def _list_domains() -> list[str]:
    rc, out, _ = _vmin("list-domains", "--name-only")
    if rc != 0:
        return []
    return [d for d in out.splitlines() if d.strip()]


def _parse_aliases(domain: str) -> list[dict]:
    rc, out, _ = _vmin("list-aliases", "--domain", domain, "--json")
    if rc != 0 or not out:
        return []
    try:
        data = json.loads(out)
        aliases = []
        for item in data.get("data", []):
            from_addr = item.get("name", "")
            to_list = item.get("values", {}).get("to", [])
            to_clean = [t.replace("\\@", "@") for t in to_list]
            aliases.append({
                "domain": domain,
                "from_address": from_addr,
                "to_addresses": to_clean,
            })
        return aliases
    except Exception:
        return []


# ---------------------------------------------------------------------------
# endpoints
# ---------------------------------------------------------------------------

@router.get("")
def list_aliases(
    _: Auth,
    domain: str | None = None,
):
    """List all mail aliases, optionally filtered to one domain."""
    domains = [domain] if domain else _list_domains()
    result: list[dict] = []
    for d in domains:
        result.extend(_parse_aliases(d))
    return {"aliases": result, "total": len(result)}


@router.get("/domains")
def list_domains(_: Auth):
    """List all Virtualmin domains."""
    return {"domains": _list_domains()}


class AliasCreate(BaseModel):
    domain: str
    from_local: str          # local-part only (before @)
    to_addresses: list[str]  # full email addresses


@router.post("", status_code=201)
def create_alias(payload: AliasCreate, _: Auth):
    """Create a new mail alias (from_local@domain → to_addresses)."""
    from_local = payload.from_local.strip().lower()
    if not from_local or not payload.domain:
        raise HTTPException(400, "from_local and domain are required")
    if not payload.to_addresses:
        raise HTTPException(400, "at least one to_address required")

    cmd = ["sudo", "virtualmin", "create-alias",
           "--domain", payload.domain,
           "--from", from_local]
    for addr in payload.to_addresses:
        cmd += ["--to", addr.strip()]

    rc, out, err = _run(cmd)
    if rc != 0:
        raise HTTPException(500, err or "Failed to create alias")
    return {"ok": True, "from_address": f"{from_local}@{payload.domain}"}


class ForwardingUpdate(BaseModel):
    domain: str
    from_local: str
    to_addresses: list[str]


@router.put("")
def update_alias(payload: ForwardingUpdate, _: Auth):
    """Replace alias destinations by deleting and re-creating."""
    from_local = payload.from_local.strip().lower()

    # delete first
    rc, _, err = _run(["sudo", "virtualmin", "delete-alias",
                       "--domain", payload.domain,
                       "--from", from_local])
    if rc != 0:
        raise HTTPException(500, err or "Failed to delete existing alias")

    # re-create
    cmd = ["sudo", "virtualmin", "create-alias",
           "--domain", payload.domain,
           "--from", from_local]
    for addr in payload.to_addresses:
        cmd += ["--to", addr.strip()]

    rc, _, err = _run(cmd)
    if rc != 0:
        raise HTTPException(500, err or "Failed to re-create alias")
    return {"ok": True}


@router.delete("/{domain}/{from_local}")
def delete_alias(domain: str, from_local: str, _: Auth):
    """Delete an email alias."""
    rc, _, err = _run(["sudo", "virtualmin", "delete-alias",
                       "--domain", domain,
                       "--from", from_local])
    if rc != 0:
        raise HTTPException(500, err or "Failed to delete alias")
    return {"ok": True}
