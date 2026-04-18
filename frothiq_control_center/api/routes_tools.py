"""
ServOps — System Tools API (super_admin only).
Terminal command execution, file manager, and network tools.
"""

from __future__ import annotations

import os
import socket
import subprocess
from datetime import UTC, datetime
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, field_validator

from .routes_auth import require_super_admin

router = APIRouter(prefix="/sysinfo/tools", tags=["tools"])


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _run(cmd: list[str], timeout: int = 15) -> tuple[str, str, int]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout, r.stderr, r.returncode
    except subprocess.TimeoutExpired:
        return "", f"Command timed out after {timeout}s", 1
    except Exception as e:
        return "", str(e), 1


# ---------------------------------------------------------------------------
# Terminal — command execution
# ---------------------------------------------------------------------------

class TerminalRequest(BaseModel):
    command: str
    cwd: str = "/"

    @field_validator("command")
    @classmethod
    def no_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("command cannot be empty")
        return v


@router.post("/exec")
async def execute_command(req: TerminalRequest, _: str = Depends(require_super_admin)) -> dict:
    """Execute a shell command and return combined output. Requires super_admin."""
    cwd = req.cwd if Path(req.cwd).is_dir() else "/"
    try:
        result = subprocess.run(
            req.command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=30,
            cwd=cwd,
            env={**os.environ, "TERM": "xterm-256color", "COLUMNS": "200"},
        )
        return {
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode,
            "command": req.command,
            "cwd": cwd,
            "executed_at": datetime.now(UTC).isoformat(),
        }
    except subprocess.TimeoutExpired:
        return {
            "stdout": "",
            "stderr": "Command timed out after 30 seconds",
            "returncode": -1,
            "command": req.command,
            "cwd": cwd,
            "executed_at": datetime.now(UTC).isoformat(),
        }
    except Exception as e:
        raise HTTPException(500, str(e))


# ---------------------------------------------------------------------------
# File Manager
# ---------------------------------------------------------------------------

@router.get("/files")
async def list_directory(path: str = "/", _: str = Depends(require_super_admin)) -> dict:
    """List directory contents."""
    try:
        p = Path(path).resolve()
        if not p.exists():
            raise HTTPException(404, f"Path not found: {path}")
        if not p.is_file():
            # Allow navigating through; treat non-dirs gracefully
            if not p.is_dir():
                raise HTTPException(400, f"Not a directory: {path}")

        entries = []
        try:
            items = sorted(p.iterdir(), key=lambda x: (not x.is_dir(), x.name.lower()))
            for child in items:
                try:
                    stat = child.stat()
                    entries.append({
                        "name": child.name,
                        "path": str(child),
                        "type": "dir" if child.is_dir() else "file",
                        "size": stat.st_size if child.is_file() else None,
                        "modified": datetime.fromtimestamp(stat.st_mtime, UTC).isoformat(),
                        "permissions": oct(stat.st_mode)[-3:],
                    })
                except PermissionError:
                    entries.append({
                        "name": child.name,
                        "path": str(child),
                        "type": "dir" if child.is_dir() else "file",
                        "size": None,
                        "modified": None,
                        "permissions": "???",
                    })
        except PermissionError:
            raise HTTPException(403, f"Permission denied reading: {path}")

        parent = str(p.parent) if str(p) != "/" else None
        return {
            "path": str(p),
            "parent": parent,
            "entries": entries,
            "count": len(entries),
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, str(e))


@router.get("/files/content")
async def read_file_content(path: str, _: str = Depends(require_super_admin)) -> dict:
    """Read a text file (max 512 KB)."""
    try:
        p = Path(path).resolve()
        if not p.exists():
            raise HTTPException(404, f"File not found: {path}")
        if not p.is_file():
            raise HTTPException(400, f"Not a file: {path}")

        size = p.stat().st_size
        if size > 524288:
            return {
                "path": str(p),
                "content": None,
                "size": size,
                "truncated": True,
                "error": f"File too large ({size // 1024} KB). Use terminal to view.",
            }

        try:
            content = p.read_text(errors="replace")
            return {"path": str(p), "content": content, "size": size, "truncated": False, "error": None}
        except PermissionError:
            raise HTTPException(403, f"Permission denied: {path}")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, str(e))


# ---------------------------------------------------------------------------
# Network Tools
# ---------------------------------------------------------------------------

@router.get("/network/ping")
async def ping(host: str, count: int = 4, _: str = Depends(require_super_admin)) -> dict:
    """Ping a host."""
    count = min(max(count, 1), 10)
    stdout, stderr, rc = _run(["ping", "-c", str(count), "-W", "3", host], timeout=20)
    return {"host": host, "output": stdout or stderr, "reachable": rc == 0}


@router.get("/network/traceroute")
async def traceroute(host: str, _: str = Depends(require_super_admin)) -> dict:
    """Traceroute to a host."""
    stdout, stderr, _ = _run(["traceroute", "-n", "-m", "20", host], timeout=45)
    return {"host": host, "output": stdout or stderr}


@router.get("/network/dns")
async def dns_lookup(host: str, record_type: str = "A", _: str = Depends(require_super_admin)) -> dict:
    """DNS lookup using dig."""
    rtype = record_type.upper() if record_type.upper() in ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "PTR", "SOA") else "A"
    stdout, stderr, _ = _run(["dig", "+short", "@8.8.8.8", host, rtype], timeout=10)
    return {"host": host, "type": rtype, "output": (stdout or stderr).strip()}


@router.get("/network/ports")
async def check_ports(
    host: str,
    ports: str = "22,80,443,3306,6379",
    _: str = Depends(require_super_admin),
) -> dict:
    """Check if TCP ports are open on a host."""
    results = []
    for port_str in ports.split(",")[:20]:  # limit to 20 ports
        try:
            port = int(port_str.strip())
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((host, port))
            sock.close()
            results.append({"port": port, "open": result == 0})
        except Exception:
            try:
                results.append({"port": int(port_str.strip()), "open": False})
            except ValueError:
                pass
    return {"host": host, "ports": results}
