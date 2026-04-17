"""
Module-level slowapi Limiter — imported by routes that need rate limiting.

Configured with Redis storage so limits persist across workers/restarts.
The limiter is attached to app.state.limiter in main.py so slowapi's
_rate_limit_exceeded_handler can find it.
"""

from __future__ import annotations

from slowapi import Limiter
from slowapi.util import get_remote_address

from frothiq_control_center.config import get_settings

_settings = get_settings()

limiter = Limiter(
    key_func=get_remote_address,
    storage_uri=_settings.redis_url,
    default_limits=["300/minute"],
)
