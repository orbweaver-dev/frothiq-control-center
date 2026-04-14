"""
IP allowlist middleware — restricts /admin/* and sensitive endpoints
to a configurable list of CIDR blocks / IPs.

If CC_ADMIN_IP_ALLOWLIST is empty, all IPs are permitted (dev default).
In production, set this to your office/VPN CIDR ranges.
"""

from __future__ import annotations

import ipaddress
import logging

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from frothiq_control_center.config import get_settings

logger = logging.getLogger(__name__)

# Paths that require IP allowlist enforcement
_PROTECTED_PREFIXES = ("/api/v1/cc/auth/users", "/api/v1/cc/license", "/api/v1/cc/tenants")


def _ip_in_allowlist(client_ip: str, allowlist: list[str]) -> bool:
    """Return True if client_ip is within any network in allowlist."""
    if not allowlist:
        return True  # empty = allow all

    try:
        addr = ipaddress.ip_address(client_ip)
    except ValueError:
        logger.warning("Could not parse client IP: %s", client_ip)
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
            logger.warning("Invalid IP allowlist entry: %s", entry)

    return False


class IPAllowlistMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        settings = get_settings()
        allowlist = settings.admin_ip_allowlist_parsed

        if allowlist and any(request.url.path.startswith(p) for p in _PROTECTED_PREFIXES):
            client_ip = request.client.host if request.client else ""
            if not _ip_in_allowlist(client_ip, allowlist):
                logger.warning("Blocked request from %s to %s", client_ip, request.url.path)
                return JSONResponse(
                    status_code=403,
                    content={"detail": "Access denied: your IP is not in the admin allowlist"},
                )

        return await call_next(request)
