"""
Usermin Configuration Management.

Closes TASK-2026-00365.

Read-only summary of Usermin service state and config:
  - Service status (active/inactive) of usermin.service
  - Configured port (default 20000) from /etc/usermin/miniserv.conf
  - SSL cert paths in use (keyfile, certfile)
  - Allowed users list from /etc/usermin/miniserv.users (count + sample)
  - Webmail module: default IMAP server from /etc/usermin/mailbox/config

Mutations are deliberately deferred to a follow-up task — Usermin config
edits can lock out users if done wrong; this module is observe-only.
"""

from __future__ import annotations

import os
import subprocess
from typing import Annotated

from fastapi import APIRouter, Depends

from mc2.auth import TokenPayload, require_super_admin

router = APIRouter(prefix="/usermin", tags=["usermin"])

Auth = Annotated[TokenPayload, Depends(require_super_admin)]


def _systemctl_active(unit: str) -> tuple[str, bool]:
    r = subprocess.run(
        ["systemctl", "is-active", unit], capture_output=True, text=True, timeout=10
    )
    status = (r.stdout or r.stderr or "unknown").strip()
    return status, status == "active"


def _read_config_kv(path: str) -> dict[str, str]:
    """Read a webmin/usermin key=value config file. Tolerant of missing
    files and unreadable lines."""
    out: dict[str, str] = {}
    try:
        with open(path) as f:
            for line in f:
                line = line.rstrip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, _, v = line.partition("=")
                out[k.strip()] = v.strip()
    except (OSError, PermissionError):
        pass
    return out


def _read_users_file(path: str) -> list[str]:
    """miniserv.users format: user:hash:flags. Returns just usernames."""
    out: list[str] = []
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                u = line.split(":", 1)[0].strip()
                if u:
                    out.append(u)
    except (OSError, PermissionError):
        pass
    return out


@router.get("")
def status(_: Auth):
    """Aggregate Usermin status + config snapshot."""
    svc_text, svc_active = _systemctl_active("usermin.service")

    miniserv = _read_config_kv("/etc/usermin/miniserv.conf")
    config = _read_config_kv("/etc/usermin/config")
    webmail_cfg = _read_config_kv("/etc/usermin/mailbox/config")

    allowed_users = _read_users_file("/etc/usermin/miniserv.users")

    port = miniserv.get("port") or "20000"
    ssl_keyfile = miniserv.get("keyfile")
    ssl_certfile = miniserv.get("certfile")
    ssl_enabled = (miniserv.get("ssl") or "").strip() == "1"

    return {
        "service": {
            "unit": "usermin.service",
            "active": svc_active,
            "status_text": svc_text,
        },
        "listen": {
            "port": port,
            "bind": miniserv.get("bind") or "0.0.0.0",
            "ssl": ssl_enabled,
            "ssl_keyfile": ssl_keyfile,
            "ssl_certfile": ssl_certfile,
            "ssl_certfile_exists": bool(ssl_certfile) and os.path.exists(ssl_certfile or ""),
        },
        "users": {
            "count": len(allowed_users),
            "sample": allowed_users[:25],
            "source": "/etc/usermin/miniserv.users",
        },
        "webmail": {
            "default_imap_server": webmail_cfg.get("default_server"),
            "default_imap_port": webmail_cfg.get("default_port"),
            "default_imap_ssl": webmail_cfg.get("default_ssl"),
            "from_address": webmail_cfg.get("from_addr"),
        },
        "ui_lang": config.get("lang") or None,
    }
