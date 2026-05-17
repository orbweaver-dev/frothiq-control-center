"""
Bandwidth Monitoring per Network Interface — reads /proc/net/dev statistics.
"""
from __future__ import annotations

import asyncio
import time
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends

from mc2.auth import TokenPayload, require_super_admin

router = APIRouter(prefix="/bandwidth", tags=["bandwidth"])
Auth = Annotated[TokenPayload, Depends(require_super_admin)]

# Cache previous sample for rate calculation
_prev_sample: dict[str, dict] = {}
_prev_time: float = 0.0


def _read_proc_net_dev() -> dict[str, dict]:
    stats: dict[str, dict] = {}
    with open("/proc/net/dev") as f:
        lines = f.readlines()[2:]  # skip 2-line header
    for line in lines:
        parts = line.split()
        if not parts:
            continue
        iface = parts[0].rstrip(":")
        rx_bytes = int(parts[1])
        rx_packets = int(parts[2])
        rx_errs = int(parts[3])
        rx_drop = int(parts[4])
        tx_bytes = int(parts[9])
        tx_packets = int(parts[10])
        tx_errs = int(parts[11])
        tx_drop = int(parts[12])
        # Read operstate if available
        operstate_path = Path(f"/sys/class/net/{iface}/operstate")
        operstate = operstate_path.read_text().strip() if operstate_path.exists() else "unknown"
        speed_path = Path(f"/sys/class/net/{iface}/speed")
        try:
            speed_mbps = int(speed_path.read_text().strip()) if speed_path.exists() else None
        except (ValueError, OSError):
            speed_mbps = None

        stats[iface] = {
            "rx_bytes": rx_bytes,
            "rx_packets": rx_packets,
            "rx_errs": rx_errs,
            "rx_drop": rx_drop,
            "tx_bytes": tx_bytes,
            "tx_packets": tx_packets,
            "tx_errs": tx_errs,
            "tx_drop": tx_drop,
            "operstate": operstate,
            "speed_mbps": speed_mbps,
        }
    return stats


def _format_bytes(b: int) -> str:
    if b >= 1_073_741_824:
        return f"{b / 1_073_741_824:.2f} GB"
    if b >= 1_048_576:
        return f"{b / 1_048_576:.2f} MB"
    if b >= 1024:
        return f"{b / 1024:.2f} KB"
    return f"{b} B"


@router.get("")
async def get_bandwidth(_: Auth):
    """
    Return current stats plus per-second rates (sampled over 1 second).
    """
    global _prev_sample, _prev_time

    current = _read_proc_net_dev()
    now = time.monotonic()

    result: list[dict] = []
    for iface, cur in current.items():
        prev = _prev_sample.get(iface)
        elapsed = now - _prev_time if _prev_time > 0 else 1.0

        if prev and elapsed > 0:
            rx_rate = (cur["rx_bytes"] - prev["rx_bytes"]) / elapsed
            tx_rate = (cur["tx_bytes"] - prev["tx_bytes"]) / elapsed
            rx_pps = (cur["rx_packets"] - prev["rx_packets"]) / elapsed
            tx_pps = (cur["tx_packets"] - prev["tx_packets"]) / elapsed
        else:
            rx_rate = tx_rate = rx_pps = tx_pps = 0.0

        result.append({
            "interface": iface,
            "operstate": cur["operstate"],
            "speed_mbps": cur["speed_mbps"],
            "rx_total_bytes": cur["rx_bytes"],
            "tx_total_bytes": cur["tx_bytes"],
            "rx_total_human": _format_bytes(cur["rx_bytes"]),
            "tx_total_human": _format_bytes(cur["tx_bytes"]),
            "rx_rate_bps": round(rx_rate),
            "tx_rate_bps": round(tx_rate),
            "rx_rate_human": f"{_format_bytes(round(rx_rate))}/s",
            "tx_rate_human": f"{_format_bytes(round(tx_rate))}/s",
            "rx_pps": round(rx_pps, 1),
            "tx_pps": round(tx_pps, 1),
            "rx_errs": cur["rx_errs"],
            "tx_errs": cur["tx_errs"],
            "rx_drop": cur["rx_drop"],
            "tx_drop": cur["tx_drop"],
        })

    _prev_sample = current
    _prev_time = now

    return {"interfaces": result, "sampled_at": now}
