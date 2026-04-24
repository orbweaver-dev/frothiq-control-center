"""
CIDR Consolidation Analyzer — finds patterns in the blacklist and recommends
CIDR ranges that can replace multiple individual IP block entries.

This is the FrothIQ equivalent of CSF's LF_NETBLOCK feature, extended with:
  - Retroactive analysis of the entire blacklist
  - Multi-prefix support (/24, /20, /16)
  - Density scoring
  - Operator review workflow before any live nftables change

Algorithm
---------
  Pass 1 — extract individual IPs from the nftables blacklist set
  Pass 2 — group by /24 supernet; flag subnets with ≥ THRESHOLD_24 IPs
  Pass 3 — group flagged /24s by /16; flag /16s with ≥ THRESHOLD_16 covered /24s
  Pass 4 — deduplicate against already-blocked CIDRs
  Output — sorted by entries_saved descending
"""

from __future__ import annotations

import ipaddress
import json
import logging
import subprocess
import time
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from frothiq_control_center.models.defense_settings import FrothiqCidrRecommendation

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Thresholds
# ---------------------------------------------------------------------------

# Minimum individual IPs in a /24 to recommend blocking the whole /24
THRESHOLD_24: int = 5

# Minimum /24s covered in a /16 to recommend blocking the whole /16
THRESHOLD_16: int = 4

# Maximum recommendations to store per scan (prevents bloat)
MAX_RECS_PER_SCAN: int = 200


# ---------------------------------------------------------------------------
# nftables reader (mirrors routes_traffic._nft_list_set but synchronous)
# ---------------------------------------------------------------------------

def _read_blacklist_raw() -> list[str]:
    """Read all entries from the live nftables blacklist set."""
    try:
        import re
        result = subprocess.run(
            ["sudo", "nft", "list", "set", "inet", "frothiq", "blacklist"],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode != 0:
            logger.warning("nft list blacklist failed: %s", result.stderr.strip())
            return []
        match = re.search(r"elements\s*=\s*\{([^}]+)\}", result.stdout, re.DOTALL)
        if not match:
            return []
        raw = match.group(1)
        entries = []
        for token in re.split(r",", raw):
            token = token.strip().split()[0] if token.strip() else ""
            if token and re.match(r"^[\d./a-fA-F:]+$", token):
                entries.append(token)
        return entries
    except Exception as exc:
        logger.error("blacklist read error: %s", exc)
        return []


# ---------------------------------------------------------------------------
# Analysis engine
# ---------------------------------------------------------------------------

def _subnet_size(prefix_len: int) -> int:
    """Usable addresses in a subnet (2^(32-prefix_len) - 2, min 1)."""
    return max(2 ** (32 - prefix_len) - 2, 1)


def analyze(existing_recs: set[str] | None = None) -> list[dict[str, Any]]:
    """
    Read live blacklist and return a list of CIDR recommendation dicts.

    existing_recs: set of CIDR strings already in pending/applied state — skip these.
    """
    existing_recs = existing_recs or set()
    raw_entries = _read_blacklist_raw()
    if not raw_entries:
        return []

    # Separate individual IPs from existing CIDRs
    individual_ips: list[ipaddress.IPv4Address] = []
    existing_cidrs: list[ipaddress.IPv4Network] = []

    for entry in raw_entries:
        if "/" in entry:
            try:
                existing_cidrs.append(ipaddress.ip_network(entry, strict=False))
            except ValueError:
                pass
        else:
            try:
                individual_ips.append(ipaddress.ip_address(entry))
            except ValueError:
                pass

    def already_covered(ip: ipaddress.IPv4Address) -> bool:
        return any(ip in net for net in existing_cidrs)

    # Only consider IPs not already covered by an existing CIDR block
    uncovered = [ip for ip in individual_ips if not already_covered(ip)]

    # Pass 2: group by /24
    by_24: dict[str, list[ipaddress.IPv4Address]] = defaultdict(list)
    for ip in uncovered:
        net24 = ipaddress.ip_network(f"{ip}/24", strict=False)
        by_24[str(net24)].append(ip)

    recommendations: list[dict[str, Any]] = []
    covered_24s: list[ipaddress.IPv4Network] = []

    for cidr_str, ips in by_24.items():
        if len(ips) < THRESHOLD_24:
            continue
        if cidr_str in existing_recs:
            continue
        net = ipaddress.ip_network(cidr_str)
        density = round(len(ips) / _subnet_size(24) * 100, 1)
        recommendations.append({
            "cidr": cidr_str,
            "prefix_len": 24,
            "covered_ips": sorted(str(ip) for ip in ips),
            "covered_count": len(ips),
            "total_in_subnet": _subnet_size(24),
            "density_pct": density,
            "entries_saved": len(ips) - 1,
        })
        covered_24s.append(net)

    # Pass 3: group flagged /24s by /16
    by_16: dict[str, list[ipaddress.IPv4Network]] = defaultdict(list)
    for net24 in covered_24s:
        net16 = ipaddress.ip_network(f"{net24.network_address}/16", strict=False)
        by_16[str(net16)].append(net24)

    for cidr_str, nets_24 in by_16.items():
        if len(nets_24) < THRESHOLD_16:
            continue
        if cidr_str in existing_recs:
            continue
        all_ips = []
        for n24 in nets_24:
            all_ips.extend(str(ip) for ip in uncovered if ip in n24)
        net16 = ipaddress.ip_network(cidr_str)
        density = round(len(all_ips) / _subnet_size(16) * 100, 2)
        recommendations.append({
            "cidr": cidr_str,
            "prefix_len": 16,
            "covered_ips": sorted(all_ips),
            "covered_count": len(all_ips),
            "total_in_subnet": _subnet_size(16),
            "density_pct": density,
            "entries_saved": len(all_ips) - 1,
        })

    recommendations.sort(key=lambda r: (-r["entries_saved"], -r["density_pct"]))
    return recommendations[:MAX_RECS_PER_SCAN]


# ---------------------------------------------------------------------------
# DB layer
# ---------------------------------------------------------------------------

async def run_scan(session: AsyncSession) -> dict[str, Any]:
    """
    Execute a full blacklist analysis scan and persist new recommendations.

    Returns a summary dict.
    """
    scan_id = str(uuid.uuid4())
    started_at = time.time()

    # Collect existing pending/applied CIDRs so we don't duplicate suggestions
    existing_rows = await session.scalars(
        select(FrothiqCidrRecommendation).where(
            FrothiqCidrRecommendation.status.in_(["pending", "applied"])
        )
    )
    existing_recs: set[str] = {row.cidr for row in existing_rows}

    recs = await __import__("asyncio").to_thread(analyze, existing_recs)

    new_count = 0
    for r in recs:
        if r["cidr"] in existing_recs:
            continue
        session.add(FrothiqCidrRecommendation(
            id=str(uuid.uuid4()),
            scan_id=scan_id,
            cidr=r["cidr"],
            prefix_len=r["prefix_len"],
            covered_ips=json.dumps(r["covered_ips"]),
            covered_count=r["covered_count"],
            total_in_subnet=r["total_in_subnet"],
            density_pct=r["density_pct"],
            entries_saved=r["entries_saved"],
            status="pending",
            created_at=datetime.now(timezone.utc).replace(tzinfo=None),
        ))
        new_count += 1

    if new_count > 0:
        await session.commit()

    elapsed = round(time.time() - started_at, 2)
    logger.info(
        "cidr_analyzer: scan %s complete — %d new recommendations in %.2fs",
        scan_id[:8], new_count, elapsed,
    )
    return {
        "scan_id": scan_id,
        "new_recommendations": new_count,
        "total_analyzed": len(recs),
        "elapsed_seconds": elapsed,
    }


async def list_recommendations(session: AsyncSession, status: str | None = None) -> list[dict]:
    q = select(FrothiqCidrRecommendation).order_by(
        FrothiqCidrRecommendation.created_at.desc()
    )
    if status:
        q = q.where(FrothiqCidrRecommendation.status == status)
    rows = await session.scalars(q)
    return [_row_to_dict(r) for r in rows]


def _row_to_dict(r: FrothiqCidrRecommendation) -> dict:
    try:
        covered_ips = json.loads(r.covered_ips)
    except Exception:
        covered_ips = []
    return {
        "id": r.id,
        "scan_id": r.scan_id,
        "cidr": r.cidr,
        "prefix_len": r.prefix_len,
        "covered_ips": covered_ips,
        "covered_count": r.covered_count,
        "total_in_subnet": r.total_in_subnet,
        "density_pct": r.density_pct,
        "entries_saved": r.entries_saved,
        "status": r.status,
        "created_at": r.created_at.isoformat(),
        "reviewed_at": r.reviewed_at.isoformat() if r.reviewed_at else None,
        "reviewed_by": r.reviewed_by,
    }


async def apply_recommendation(
    session: AsyncSession,
    rec_id: str,
    user_email: str,
) -> dict[str, Any]:
    """
    Apply a pending recommendation:
      1. Add CIDR to nftables blacklist
      2. Remove covered individual IPs from nftables blacklist
      3. Remove covered IPs from frothiq_ip_list DB table
      4. Mark recommendation as applied
    """
    from frothiq_control_center.models.defense_settings import FrothiqIPEntry
    from frothiq_control_center.services.frothiq_nft_service import _run

    row = await session.get(FrothiqCidrRecommendation, rec_id)
    if not row:
        return {"success": False, "error": "Recommendation not found"}
    if row.status != "pending":
        return {"success": False, "error": f"Cannot apply — status is {row.status!r}"}

    cidr = row.cidr
    covered_ips: list[str] = json.loads(row.covered_ips)

    # 1. Add CIDR to blacklist.
    # "interval overlaps" means the CIDR is already in the set — treat as
    # idempotent success so retries and pre-existing entries don't block the
    # rest of the apply flow (IP removal + DB update still run).
    rc, _, err = await _run(["nft", "add", "element", "inet", "frothiq", "blacklist", f"{{ {cidr} }}"])
    if rc != 0 and "interval overlaps" not in err:
        return {"success": False, "error": f"nft add CIDR failed: {err.strip()}"}

    # 2. Remove individual IPs from nftables (best-effort — they're now covered by CIDR)
    removed_nft = 0
    for ip in covered_ips:
        rc2, _, _ = await _run(["nft", "delete", "element", "inet", "frothiq", "blacklist", f"{{ {ip} }}"])
        if rc2 == 0:
            removed_nft += 1

    # 3. Remove covered IPs from DB ip list
    ip_rows = await session.scalars(
        select(FrothiqIPEntry).where(
            FrothiqIPEntry.ip.in_(covered_ips),
            FrothiqIPEntry.list_type == "blacklist",
        )
    )
    removed_db = 0
    for ip_row in ip_rows:
        await session.delete(ip_row)
        removed_db += 1

    # 4. Mark recommendation applied
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    row.status = "applied"
    row.reviewed_at = now
    row.reviewed_by = user_email
    await session.commit()

    logger.info(
        "cidr_analyzer: applied %s — removed %d nft entries, %d db entries",
        cidr, removed_nft, removed_db,
    )
    return {
        "success": True,
        "cidr": cidr,
        "nft_applied": True,
        "individual_ips_removed_nft": removed_nft,
        "individual_ips_removed_db": removed_db,
    }


async def dismiss_recommendation(
    session: AsyncSession,
    rec_id: str,
    user_email: str,
) -> dict[str, Any]:
    row = await session.get(FrothiqCidrRecommendation, rec_id)
    if not row:
        return {"success": False, "error": "Recommendation not found"}
    if row.status != "pending":
        return {"success": False, "error": f"Cannot dismiss — status is {row.status!r}"}

    now = datetime.now(timezone.utc).replace(tzinfo=None)
    row.status = "dismissed"
    row.reviewed_at = now
    row.reviewed_by = user_email
    await session.commit()
    return {"success": True}
