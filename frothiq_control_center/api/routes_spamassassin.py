"""
SpamAssassin — service control, configuration management, and Bayes statistics.

Uses systemd (spamd.service), sa-learn, and spamassassin CLI tools.
All write operations require super_admin role.
"""

from __future__ import annotations

import asyncio
import re
import subprocess
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from frothiq_control_center.auth import TokenPayload, require_super_admin

router = APIRouter(prefix="/sysinfo/spamassassin", tags=["spamassassin"])

_SPAMD_SERVICE = "spamd"
_LOCAL_CF = Path("/etc/spamassassin/local.cf")
_SPAMD_OVERRIDE = Path("/etc/systemd/system/spamd.service.d/override.conf")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _run(cmd: list[str], timeout: int = 15, input_text: str | None = None) -> tuple[str, str, int]:
    try:
        r = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, input=input_text
        )
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    except subprocess.TimeoutExpired:
        return "", f"Command timed out after {timeout}s", 1
    except FileNotFoundError as e:
        return "", str(e), 1
    except Exception as e:
        return "", str(e), 1


def _systemctl(action: str, service: str) -> tuple[str, str, int]:
    return _run(["sudo", "systemctl", action, service])


def _service_status() -> dict:
    stdout, _, rc = _run(["sudo", "systemctl", "is-active", _SPAMD_SERVICE])
    active = stdout.strip() == "active"

    # Get full status output for details
    detail_out, _, _ = _run(
        ["sudo", "systemctl", "show", _SPAMD_SERVICE,
         "--property=ActiveState,SubState,MainPID,MemoryCurrent,CPUUsageNSec,UnitFileState"],
        timeout=10,
    )
    props: dict[str, str] = {}
    for line in detail_out.splitlines():
        if "=" in line:
            k, _, v = line.partition("=")
            props[k.strip()] = v.strip()

    mem_bytes = int(props.get("MemoryCurrent", "0") or "0")
    cpu_ns = int(props.get("CPUUsageNSec", "0") or "0")
    cpu_sec = round(cpu_ns / 1_000_000_000, 1)

    return {
        "active": active,
        "state": props.get("ActiveState", "unknown"),
        "sub_state": props.get("SubState", "unknown"),
        "pid": props.get("MainPID", "0"),
        "memory_mb": round(mem_bytes / (1024 * 1024), 1) if mem_bytes else None,
        "cpu_seconds": cpu_sec if cpu_ns else None,
        "enabled": props.get("UnitFileState", "") == "enabled",
    }


def _bayes_stats() -> dict:
    stdout, stderr, rc = _run(["sudo", "sa-learn", "--dump", "magic"], timeout=20)
    if rc != 0:
        return {"available": False, "error": stderr or "sa-learn failed"}

    stats: dict = {"available": True}
    for line in stdout.splitlines():
        # Format: 0.000  0  1  0  non-token data: XXX
        m = re.match(r"[\d.]+\s+\d+\s+\d+\s+\d+\s+non-token data:\s+(.+)", line)
        if not m:
            continue
        label_val = m.group(1).strip()
        if "bayes db version" in label_val.lower():
            parts = label_val.split("=")
            stats["db_version"] = parts[-1].strip() if len(parts) > 1 else label_val
        elif "nspam" in label_val.lower():
            parts = label_val.split("=")
            try:
                stats["spam_count"] = int(parts[-1].strip())
            except ValueError:
                pass
        elif "nham" in label_val.lower():
            parts = label_val.split("=")
            try:
                stats["ham_count"] = int(parts[-1].strip())
            except ValueError:
                pass
        elif "ntokens" in label_val.lower():
            parts = label_val.split("=")
            try:
                stats["token_count"] = int(parts[-1].strip())
            except ValueError:
                pass
        elif "oldest token age" in label_val.lower():
            parts = label_val.split("=")
            stats["oldest_token_age_days"] = parts[-1].strip() if len(parts) > 1 else label_val
        elif "newest token age" in label_val.lower():
            parts = label_val.split("=")
            stats["newest_token_age_days"] = parts[-1].strip() if len(parts) > 1 else label_val

    return stats


def _parse_local_cf() -> dict:
    """Parse key settings from local.cf (both active and commented)."""
    if not _LOCAL_CF.exists():
        return {"error": "local.cf not found"}

    result = subprocess.run(
        ["sudo", "cat", str(_LOCAL_CF)],
        capture_output=True, text=True, timeout=5,
    )
    content = result.stdout

    settings: dict[str, str | None] = {
        "required_score": None,
        "rewrite_header_subject": None,
        "report_safe": None,
        "trusted_networks": None,
    }

    for line in content.splitlines():
        stripped = line.strip()
        # Skip blank lines
        if not stripped:
            continue
        # Skip commented lines (for display we only want active directives)
        if stripped.startswith("#"):
            continue
        parts = stripped.split(None, 1)
        if len(parts) < 2:
            continue
        key, val = parts[0].lower(), parts[1]
        if key == "required_score":
            settings["required_score"] = val
        elif key == "rewrite_header":
            settings["rewrite_header_subject"] = val
        elif key == "report_safe":
            settings["report_safe"] = val
        elif key == "trusted_networks":
            settings["trusted_networks"] = val

    return {"settings": settings, "raw": content}


def _recent_log_lines(n: int = 50) -> list[str]:
    stdout, _, _ = _run(
        ["sudo", "journalctl", "-u", _SPAMD_SERVICE, "--no-pager",
         f"-n{n}", "--output=short-iso"],
        timeout=15,
    )
    return stdout.splitlines()


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.get("/status")
async def get_status(_: TokenPayload = Depends(require_super_admin)):
    """Service status, version, and Bayes database statistics."""
    status, bayes = await asyncio.gather(
        asyncio.to_thread(_service_status),
        asyncio.to_thread(_bayes_stats),
    )
    # Get version
    ver_out, _, _ = await asyncio.to_thread(
        _run, ["sudo", "spamassassin", "--version"]
    )
    version = ver_out.splitlines()[0].strip() if ver_out else "unknown"

    return {
        "service": status,
        "version": version,
        "bayes": bayes,
    }


@router.post("/service/{action}")
async def service_action(
    action: str,
    _: TokenPayload = Depends(require_super_admin),
):
    """Start, stop, restart, or reload spamd service."""
    allowed = {"start", "stop", "restart", "reload"}
    if action not in allowed:
        raise HTTPException(status_code=400, detail=f"Action must be one of: {', '.join(sorted(allowed))}")

    stdout, stderr, rc = await asyncio.to_thread(_systemctl, action, _SPAMD_SERVICE)
    if rc != 0 and stderr:
        raise HTTPException(status_code=500, detail=stderr)

    # Brief pause then return new status
    await asyncio.sleep(1.0)
    new_status = await asyncio.to_thread(_service_status)
    return {"ok": rc == 0, "action": action, "service": new_status}


@router.get("/config")
async def get_config(_: TokenPayload = Depends(require_super_admin)):
    """Read local.cf — active settings and raw file content."""
    result = await asyncio.to_thread(_parse_local_cf)
    return result


class ConfigUpdateBody(BaseModel):
    content: str  # Full file content to write


@router.put("/config")
async def update_config(
    body: ConfigUpdateBody,
    _: TokenPayload = Depends(require_super_admin),
):
    """Overwrite local.cf with validated content."""
    # Basic sanity check — must not be empty or too large
    if not body.content.strip():
        raise HTTPException(status_code=400, detail="Config content cannot be empty")
    if len(body.content) > 64_000:
        raise HTTPException(status_code=400, detail="Config content too large (max 64 KB)")

    # Write via sudo tee
    stdout, stderr, rc = await asyncio.to_thread(
        _run, ["sudo", "tee", str(_LOCAL_CF)],
        timeout=10, input_text=body.content,
    )
    if rc != 0:
        raise HTTPException(status_code=500, detail=stderr or "Write failed")

    return {"ok": True, "bytes_written": len(body.content)}


@router.get("/logs")
async def get_logs(
    n: int = 50,
    _: TokenPayload = Depends(require_super_admin),
):
    """Recent spamd journal log lines."""
    if n > 500:
        n = 500
    lines = await asyncio.to_thread(_recent_log_lines, n)
    return {"lines": lines, "count": len(lines)}


@router.post("/bayes/learn")
async def bayes_learn(
    learn_type: str = "spam",
    _: TokenPayload = Depends(require_super_admin),
):
    """Trigger sa-learn on the Postfix mail spool (spam or ham)."""
    if learn_type not in ("spam", "ham"):
        raise HTTPException(status_code=400, detail="learn_type must be 'spam' or 'ham'")

    # sa-update pulls latest rules
    stdout, stderr, rc = await asyncio.to_thread(
        _run, ["sudo", "sa-update", "--no-gpg"], timeout=60
    )
    updated = rc == 0

    return {
        "ok": updated,
        "learn_type": learn_type,
        "sa_update_output": stdout or stderr,
    }
