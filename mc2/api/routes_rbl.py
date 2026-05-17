"""
Real-time Blackhole List (RBL/DNSBL) Integration — check IPs against public blocklists.
"""
from __future__ import annotations

import asyncio
import ipaddress
import subprocess
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from mc3.auth import TokenPayload, require_super_admin

router = APIRouter(prefix="/rbl", tags=["rbl"])
Auth = Annotated[TokenPayload, Depends(require_super_admin)]

# Well-known public RBL zones
_RBLS: list[dict] = [
    {"zone": "zen.spamhaus.org",         "name": "Spamhaus ZEN",          "category": "spam"},
    {"zone": "bl.spamcop.net",           "name": "SpamCop",               "category": "spam"},
    {"zone": "dnsbl.sorbs.net",          "name": "SORBS",                  "category": "spam"},
    {"zone": "psbl.surriel.com",         "name": "PSBL",                  "category": "spam"},
    {"zone": "dnsbl-1.uceprotect.net",   "name": "UCEPROTECT L1",         "category": "spam"},
    {"zone": "dnsbl.dronebl.org",        "name": "DroneBL",               "category": "botnet"},
    {"zone": "bl.0spam.org",             "name": "0Spam",                 "category": "spam"},
    {"zone": "ips.backscatterer.org",    "name": "Backscatterer",         "category": "backscatter"},
    {"zone": "ix.dnsbl.manitu.net",      "name": "Manitu NiX Spam",       "category": "spam"},
    {"zone": "xbl.spamhaus.org",         "name": "Spamhaus XBL",          "category": "exploits"},
    {"zone": "sbl.spamhaus.org",         "name": "Spamhaus SBL",          "category": "spam"},
    {"zone": "pbl.spamhaus.org",         "name": "Spamhaus PBL",          "category": "policy"},
    {"zone": "dnsbl.justspam.org",       "name": "JustSpam",              "category": "spam"},
    {"zone": "truncate.gbudb.net",       "name": "GBUdb Truncate",        "category": "spam"},
    {"zone": "noptr.spamrats.com",       "name": "SPAMRATS No-PTR",       "category": "spam"},
]


def _reverse_ip(ip: str) -> str:
    """Reverse an IPv4 address for DNSBL lookup."""
    parts = ip.split(".")
    return ".".join(reversed(parts))


def _check_rbl_sync(reversed_ip: str, zone: str, timeout: int = 4) -> tuple[bool, str]:
    """Returns (listed, answer_string) using dig."""
    query = f"{reversed_ip}.{zone}"
    try:
        r = subprocess.run(
            ["dig", "+short", "+time=3", "+tries=1", query, "A"],
            capture_output=True, text=True, timeout=timeout
        )
        answer = r.stdout.strip()
        if answer:
            return True, answer
        return False, ""
    except subprocess.TimeoutExpired:
        return False, "timeout"
    except Exception as e:
        return False, str(e)


async def _check_one(ip: str, rbl: dict) -> dict:
    rev = _reverse_ip(ip)
    loop = asyncio.get_event_loop()
    listed, answer = await loop.run_in_executor(
        None, _check_rbl_sync, rev, rbl["zone"]
    )
    return {
        "zone": rbl["zone"],
        "name": rbl["name"],
        "category": rbl["category"],
        "listed": listed,
        "answer": answer if listed else "",
    }


@router.get("/check")
async def check_ip(
    ip: str = Query(..., description="IPv4 address to check"),
    zones: str = Query("all", description="Comma-separated zone names, or 'all'"),
    _: Auth = None,
):
    """Check a single IP against all (or specified) RBL zones concurrently."""
    try:
        addr = ipaddress.IPv4Address(ip)
        if addr.is_private or addr.is_loopback or addr.is_link_local:
            raise HTTPException(400, "Private/loopback IPs cannot be checked against RBLs")
    except ValueError:
        raise HTTPException(400, f"Invalid IPv4 address: {ip}")

    if zones == "all":
        selected = _RBLS
    else:
        zone_list = [z.strip() for z in zones.split(",")]
        selected = [r for r in _RBLS if r["zone"] in zone_list]
        if not selected:
            raise HTTPException(400, "No matching RBL zones found")

    results = await asyncio.gather(*[_check_one(ip, rbl) for rbl in selected])

    listed_count = sum(1 for r in results if r["listed"])
    return {
        "ip": ip,
        "listed_count": listed_count,
        "total_checked": len(results),
        "listed": listed_count > 0,
        "results": results,
    }


@router.get("/zones")
def list_zones(_: Auth = None):
    """List all supported RBL zones."""
    categories: dict[str, list] = {}
    for rbl in _RBLS:
        cat = rbl["category"]
        if cat not in categories:
            categories[cat] = []
        categories[cat].append({"zone": rbl["zone"], "name": rbl["name"]})
    return {"zones": _RBLS, "by_category": categories, "total": len(_RBLS)}


class BulkCheckRequest(BaseModel):
    ips: list[str]


@router.post("/bulk")
async def bulk_check(payload: BulkCheckRequest, _: Auth = None):
    """Check multiple IPs against all RBLs. Max 20 IPs per request."""
    if len(payload.ips) > 20:
        raise HTTPException(400, "Maximum 20 IPs per bulk request")

    results = []
    for ip in payload.ips:
        try:
            addr = ipaddress.IPv4Address(ip)
            if addr.is_private or addr.is_loopback:
                results.append({"ip": ip, "error": "private/loopback", "listed": False, "listed_count": 0})
                continue
        except ValueError:
            results.append({"ip": ip, "error": "invalid", "listed": False, "listed_count": 0})
            continue

        checks = await asyncio.gather(*[_check_one(ip, rbl) for rbl in _RBLS])
        listed_count = sum(1 for r in checks if r["listed"])
        results.append({
            "ip": ip,
            "listed": listed_count > 0,
            "listed_count": listed_count,
            "results": [r for r in checks if r["listed"]],  # only listing entries
        })

    return {"results": results}
