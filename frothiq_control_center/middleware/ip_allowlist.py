"""
IP allowlist middleware — default-deny.

Every request is checked against the merged IP allowlist:
  1. CC_ADMIN_IP_ALLOWLIST env var (bootstrap / override)
  2. safe_ips in portal_settings.json (legacy runtime config)
  3. cc_ip_allowlist database table (enrollment-flow approved IPs)

Empty merged list = deny all (unlike the old default-allow behaviour).
The allowlist is cached in Redis for 60 seconds (key: cc:ip_allowlist_cache)
and shared across all uvicorn workers.

Paths exempt from IP check (accessible from any IP):
  /api/v1/cc/auth/enroll/*    — enrollment submission
  /api/v1/cc/auth/approve-ip/ — admin approval link
  /api/v1/cc/settings/portal  — portal branding (unauthenticated)
  /health                     — load balancer probe
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
from pathlib import Path

from fastapi import Request
from fastapi.responses import JSONResponse
from sqlalchemy import select
from starlette.middleware.base import BaseHTTPMiddleware

from frothiq_control_center.config import get_settings

logger = logging.getLogger(__name__)

_SETTINGS_FILE = Path(
    os.environ.get("CC_PORTAL_SETTINGS_DIR", "/var/lib/frothiq/control-center")
) / "portal_settings.json"

_IP_CACHE_KEY = "cc:ip_allowlist_cache"
_IP_CACHE_TTL = 60  # seconds

# Loopback IPs — internal gateway and health-check calls are always allowed
_LOCALHOST_IPS = frozenset({"127.0.0.1", "::1"})

# Paths that bypass the IP check entirely
_PUBLIC_PREFIXES = (
    "/api/v1/cc/auth/enroll",       # enrollment flow (new IPs)
    "/api/v1/cc/auth/approve-ip",   # admin approval link
    "/api/v1/cc/auth/ip-status",    # Next.js middleware IP check
    "/api/v1/cc/settings/portal",   # portal branding
    "/api/v1/edge/",                # edge plugin endpoints — called from any WP site
    "/health",
)


def _load_portal_safe_ips() -> list[str]:
    try:
        if _SETTINGS_FILE.exists():
            data = json.loads(_SETTINGS_FILE.read_text())
            return [ip for ip in data.get("safe_ips", []) if ip]
    except Exception:
        pass
    return []


def _ip_in_allowlist(client_ip: str, allowlist: list[str]) -> bool:
    try:
        addr = ipaddress.ip_address(client_ip)
    except ValueError:
        logger.warning("Cannot parse client IP: %s", client_ip)
        return False

    for entry in allowlist:
        try:
            if "/" in entry:
                if addr in ipaddress.ip_network(entry, strict=False):
                    return True
            else:
                if addr == ipaddress.ip_address(entry):
                    return True
        except ValueError:
            logger.warning("Invalid allowlist entry: %s", entry)

    return False


async def build_allowlist(redis, db) -> list[str]:
    """Build the merged IP allowlist from all sources with Redis caching."""
    cached = None
    if redis:
        try:
            cached = await redis.get(_IP_CACHE_KEY)
        except Exception:
            pass

    if cached:
        return json.loads(cached if isinstance(cached, str) else cached.decode())

    settings = get_settings()
    env_ips = settings.admin_ip_allowlist_parsed
    portal_ips = _load_portal_safe_ips()
    db_ips = await _load_db_ips(db) if db else []
    allowlist = list({*env_ips, *portal_ips, *db_ips})

    if redis:
        try:
            await redis.setex(_IP_CACHE_KEY, _IP_CACHE_TTL, json.dumps(allowlist))
        except Exception:
            pass

    return allowlist


async def _load_db_ips(db) -> list[str]:
    """Query the cc_ip_allowlist table. Returns empty list on error."""
    try:
        from frothiq_control_center.models.enrollment import IPAllowlist
        result = await db.execute(select(IPAllowlist.ip))
        return [row[0] for row in result.all()]
    except Exception as exc:
        logger.warning("Failed to query cc_ip_allowlist: %s", exc)
        return []


class IPAllowlistMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Always let public paths through
        if any(request.url.path.startswith(p) for p in _PUBLIC_PREFIXES):
            return await call_next(request)

        client_ip = ""
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            client_ip = forwarded.split(",")[0].strip()
        elif request.client:
            client_ip = request.client.host

        # Always allow loopback — internal gateway and health-check calls
        if client_ip in _LOCALHOST_IPS:
            return await call_next(request)

        redis = getattr(request.state, "redis", None)
        db = getattr(request.state, "db", None)
        allowlist = await build_allowlist(redis, db)

        # Default deny — empty list = block all
        if not allowlist or not _ip_in_allowlist(client_ip, allowlist):
            logger.warning("Blocked %s → %s (not in allowlist)", client_ip, request.url.path)
            return JSONResponse(
                status_code=403,
                content={
                    "code": "ip_not_approved",
                    "detail": "Access denied: this IP is not in the approved access list.",
                    "enroll_url": "/enroll",
                },
            )

        return await call_next(request)
