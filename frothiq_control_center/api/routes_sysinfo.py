"""
ServOps — system information endpoint (super_admin only).
Returns host-level metrics via psutil: CPU, memory, disk, network, uptime, processes.
"""

from __future__ import annotations

import platform
import time
from datetime import UTC, datetime

from fastapi import APIRouter, Depends

import psutil

from .routes_auth import require_super_admin

router = APIRouter(prefix="/sysinfo", tags=["sysinfo"])


def _uptime_str(boot_ts: float) -> str:
    secs = int(time.time() - boot_ts)
    days, rem = divmod(secs, 86400)
    hours, rem = divmod(rem, 3600)
    mins = rem // 60
    parts = []
    if days:
        parts.append(f"{days}d")
    if hours or days:
        parts.append(f"{hours}h")
    parts.append(f"{mins}m")
    return " ".join(parts)


@router.get("")
async def get_sysinfo(_: str = Depends(require_super_admin)) -> dict:
    boot_ts = psutil.boot_time()
    cpu_pct = psutil.cpu_percent(interval=0.2)
    cpu_count_logical = psutil.cpu_count(logical=True)
    cpu_count_physical = psutil.cpu_count(logical=False)
    load_avg = list(psutil.getloadavg())

    mem = psutil.virtual_memory()
    swap = psutil.swap_memory()

    disks = []
    for part in psutil.disk_partitions(all=False):
        try:
            usage = psutil.disk_usage(part.mountpoint)
        except PermissionError:
            continue
        disks.append({
            "mountpoint": part.mountpoint,
            "device": part.device,
            "fstype": part.fstype,
            "total_gb": round(usage.total / 1e9, 2),
            "used_gb": round(usage.used / 1e9, 2),
            "free_gb": round(usage.free / 1e9, 2),
            "percent": usage.percent,
        })

    net = psutil.net_io_counters()
    net_if = psutil.net_if_addrs()
    interfaces = list(net_if.keys())

    proc_count = len(psutil.pids())

    uname = platform.uname()

    return {
        "hostname": uname.node,
        "os": f"{uname.system} {uname.release}",
        "kernel": uname.version,
        "arch": uname.machine,
        "python": platform.python_version(),
        "uptime": _uptime_str(boot_ts),
        "boot_time": datetime.fromtimestamp(boot_ts, tz=UTC).isoformat(),
        "cpu": {
            "percent": cpu_pct,
            "logical_cores": cpu_count_logical,
            "physical_cores": cpu_count_physical,
            "load_avg_1m": round(load_avg[0], 2),
            "load_avg_5m": round(load_avg[1], 2),
            "load_avg_15m": round(load_avg[2], 2),
        },
        "memory": {
            "total_gb": round(mem.total / 1e9, 2),
            "used_gb": round(mem.used / 1e9, 2),
            "available_gb": round(mem.available / 1e9, 2),
            "percent": mem.percent,
            "swap_total_gb": round(swap.total / 1e9, 2),
            "swap_used_gb": round(swap.used / 1e9, 2),
            "swap_percent": swap.percent,
        },
        "disks": disks,
        "network": {
            "bytes_sent_mb": round(net.bytes_sent / 1e6, 2),
            "bytes_recv_mb": round(net.bytes_recv / 1e6, 2),
            "packets_sent": net.packets_sent,
            "packets_recv": net.packets_recv,
            "interfaces": interfaces,
        },
        "processes": proc_count,
        "checked_at": datetime.now(UTC).isoformat(),
    }
