"""
Package Manager — list installed packages, search apt cache, install/remove packages.
"""
from __future__ import annotations

import asyncio
import subprocess
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from frothiq_control_center.auth import TokenPayload, require_super_admin

router = APIRouter(prefix="/packages", tags=["packages"])
Auth = Annotated[TokenPayload, Depends(require_super_admin)]

# Track background install/remove jobs
_job_running: bool = False
_job_result: dict | None = None
_job_action: str = ""
_job_package: str = ""


def _run(cmd: list[str], timeout: int = 30) -> tuple[int, str, str]:
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return r.returncode, r.stdout.strip(), r.stderr.strip()


def _parse_dpkg_list(output: str) -> list[dict]:
    packages = []
    for line in output.splitlines():
        parts = line.split(None, 4)
        if len(parts) < 4:
            continue
        status = parts[0]
        name = parts[1]
        version = parts[2]
        arch = parts[3]
        description = parts[4] if len(parts) > 4 else ""
        if status.startswith("ii"):
            packages.append({
                "name": name,
                "version": version,
                "arch": arch,
                "description": description,
                "status": "installed",
            })
    return packages


@router.get("")
def list_packages(search: str = "", limit: int = 100, _: Auth = None):
    """List installed packages (dpkg -l), optionally filtered by name."""
    rc, out, err = _run(["dpkg", "-l"], timeout=30)
    if rc != 0:
        raise HTTPException(500, err or "dpkg -l failed")

    packages = _parse_dpkg_list(out)
    if search:
        q = search.lower()
        packages = [p for p in packages if q in p["name"].lower() or q in p["description"].lower()]

    total = len(packages)
    packages = packages[:limit]
    return {"packages": packages, "total": total, "showing": len(packages)}


@router.get("/search")
def search_apt(query: str, _: Auth = None):
    """Search the apt cache for available packages."""
    if not query or len(query) < 2:
        raise HTTPException(400, "Query must be at least 2 characters")

    rc, out, err = _run(["apt-cache", "search", "--names-only", query], timeout=20)
    if rc != 0:
        raise HTTPException(500, err or "apt-cache search failed")

    results = []
    for line in out.splitlines():
        if " - " in line:
            name, _, desc = line.partition(" - ")
            results.append({"name": name.strip(), "description": desc.strip()})

    # Check which ones are installed
    installed_rc, installed_out, _ = _run(["dpkg", "-l"], timeout=30)
    installed_names: set[str] = set()
    if installed_rc == 0:
        for line in installed_out.splitlines():
            parts = line.split(None, 2)
            if len(parts) >= 2 and parts[0].startswith("ii"):
                installed_names.add(parts[1])

    for r in results:
        r["installed"] = r["name"] in installed_names

    return {"results": results[:50], "total": len(results)}


@router.get("/info/{name}")
def package_info(name: str, _: Auth = None):
    """Get detailed info about a package (apt-cache show)."""
    rc, out, err = _run(["apt-cache", "show", name], timeout=15)
    if rc != 0:
        raise HTTPException(404, f"Package '{name}' not found")

    info: dict = {"name": name, "raw": out}
    for line in out.splitlines():
        if ": " in line:
            key, _, val = line.partition(": ")
            key = key.strip().lower().replace("-", "_")
            if key in {"version", "installed_size", "maintainer", "homepage", "description", "depends", "recommends"}:
                info[key] = val.strip()

    # Check if installed
    rc2, out2, _ = _run(["dpkg", "-s", name], timeout=10)
    info["installed"] = rc2 == 0 and "Status: install ok installed" in out2

    return info


@router.get("/job")
def get_job_status(_: Auth = None):
    """Get the status of the current background install/remove job."""
    global _job_running, _job_result
    return {
        "running": _job_running,
        "action": _job_action,
        "package": _job_package,
        "result": _job_result,
    }


class PackageAction(BaseModel):
    package: str
    action: str  # "install" or "remove"


async def _run_apt_job(package: str, action: str):
    global _job_running, _job_result, _job_action, _job_package
    _job_running = True
    _job_result = None
    _job_action = action
    _job_package = package

    try:
        if action == "install":
            cmd = ["sudo", "apt-get", "install", "-y", package]
        elif action == "remove":
            cmd = ["sudo", "apt-get", "remove", "-y", package]
        elif action == "purge":
            cmd = ["sudo", "apt-get", "purge", "-y", package]
        else:
            _job_result = {"ok": False, "error": f"Unknown action: {action}"}
            return

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env={"DEBIAN_FRONTEND": "noninteractive", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"},
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=300)
        _job_result = {
            "ok": proc.returncode == 0,
            "returncode": proc.returncode,
            "stdout": stdout.decode(errors="replace").strip()[-3000:],
            "stderr": stderr.decode(errors="replace").strip()[-1000:],
        }
    except asyncio.TimeoutError:
        _job_result = {"ok": False, "error": "Timed out after 5 minutes"}
    except Exception as e:
        _job_result = {"ok": False, "error": str(e)}
    finally:
        _job_running = False


@router.post("/action")
async def package_action(payload: PackageAction, _: Auth = None):
    """Install or remove a package (async — poll /packages/job for result)."""
    global _job_running

    if not payload.package or len(payload.package) > 128:
        raise HTTPException(400, "Invalid package name")
    # Basic name validation
    if not all(c.isalnum() or c in "-_.+" for c in payload.package):
        raise HTTPException(400, "Invalid package name characters")
    if payload.action not in {"install", "remove", "purge"}:
        raise HTTPException(400, "action must be install, remove, or purge")
    if _job_running:
        raise HTTPException(409, "Another package operation is already running")

    asyncio.create_task(_run_apt_job(payload.package, payload.action))
    return {"ok": True, "message": f"{payload.action} started for {payload.package}"}


@router.get("/upgradable")
def list_upgradable(_: Auth = None):
    """List packages with available upgrades."""
    rc, out, _ = _run(["apt", "list", "--upgradable", "--quiet=2"], timeout=30)
    packages = []
    for line in out.splitlines():
        if "/" in line:
            parts = line.split()
            if len(parts) >= 4:
                name = parts[0].split("/")[0]
                version = parts[1]
                packages.append({"name": name, "available_version": version})
    return {"upgradable": packages, "count": len(packages)}
