"""
frothiq-core HTTP client — all communication with frothiq-core goes through here.

Features:
  - Signed service token auth (X-FrothIQ-Key + X-Service-Key)
  - Connection pooling via httpx.AsyncClient
  - Structured error handling + retries
  - Response caching via Redis (configurable TTL per endpoint)
  - Circuit-breaker style: marks core as degraded after repeated failures
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

import httpx

from frothiq_control_center.config import get_settings

logger = logging.getLogger(__name__)

# Endpoints that can be cached and their TTL in seconds
_CACHEABLE: dict[str, int] = {
    "/api/v2/defense/clusters/all": 30,
    "/api/v2/defense/status": 15,
    "/api/v2/policy/active": 30,
    "/api/v2/simulation/status": 60,
    "/api/v2/simulation/scenarios": 300,
    "/api/v1/get-rules": 60,
    "/api/v2/internal/health": 10,
}

_core_healthy: bool = True
_last_failure_ts: float = 0.0
_FAILURE_BACKOFF_SECONDS = 30


class CoreClientError(Exception):
    """Raised when frothiq-core returns an unexpected error."""

    def __init__(self, status_code: int, detail: str):
        self.status_code = status_code
        self.detail = detail
        super().__init__(f"frothiq-core error {status_code}: {detail}")


class CoreClient:
    """
    Async HTTP client for frothiq-core.

    Lifecycle:
      - Call startup() on app lifespan start
      - Call shutdown() on app lifespan end
    """

    def __init__(self) -> None:
        self._client: httpx.AsyncClient | None = None
        self._redis: Any = None  # set by startup()

    async def startup(self, redis_client: Any | None = None) -> None:
        settings = get_settings()
        self._client = httpx.AsyncClient(
            base_url=settings.core_base_url,
            timeout=settings.core_timeout_seconds,
            limits=httpx.Limits(max_connections=settings.core_max_connections),
            headers={
                "X-FrothIQ-Key": settings.core_service_api_key,
                "X-Service-Key": "frothiq-control-center",
                "Content-Type": "application/json",
            },
        )
        self._redis = redis_client
        logger.info("CoreClient started → %s", settings.core_base_url)

    async def shutdown(self) -> None:
        if self._client:
            await self._client.aclose()
            logger.info("CoreClient shut down")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _cache_key(self, path: str, params: dict | None) -> str:
        param_str = "&".join(f"{k}={v}" for k, v in sorted((params or {}).items()))
        return f"cc:core_cache:{path}:{param_str}"

    async def _get_cached(self, cache_key: str) -> str | None:
        if self._redis is None:
            return None
        try:
            return await self._redis.get(cache_key)
        except Exception:
            return None

    async def _set_cached(self, cache_key: str, value: str, ttl: int) -> None:
        if self._redis is None:
            return
        try:
            await self._redis.setex(cache_key, ttl, value)
        except Exception:
            pass

    def _mark_healthy(self) -> None:
        global _core_healthy, _last_failure_ts
        _core_healthy = True

    def _mark_unhealthy(self) -> None:
        global _core_healthy, _last_failure_ts
        _core_healthy = False
        _last_failure_ts = time.monotonic()
        logger.warning("frothiq-core marked as degraded")

    def is_healthy(self) -> bool:
        global _core_healthy, _last_failure_ts
        if not _core_healthy:
            if time.monotonic() - _last_failure_ts > _FAILURE_BACKOFF_SECONDS:
                _core_healthy = True  # allow retry after backoff
        return _core_healthy

    # ------------------------------------------------------------------
    # Public request methods
    # ------------------------------------------------------------------

    async def get(
        self,
        path: str,
        params: dict[str, Any] | None = None,
        tenant_api_key: str | None = None,
        bypass_cache: bool = False,
    ) -> dict[str, Any]:
        """
        GET request to frothiq-core.

        Args:
            path: API path, e.g. "/api/v2/defense/clusters/all"
            params: Query parameters
            tenant_api_key: If set, overrides the service key with a tenant key
                            (used to proxy tenant-scoped requests)
            bypass_cache: Force a fresh fetch even if cached
        """
        if not self._client:
            raise RuntimeError("CoreClient not started")

        # Cache check
        ttl = _CACHEABLE.get(path, 0)
        if ttl and not bypass_cache:
            ck = self._cache_key(path, params)
            cached = await self._get_cached(ck)
            if cached:
                import json
                return json.loads(cached)

        headers = {}
        if tenant_api_key:
            headers["X-FrothIQ-Key"] = tenant_api_key

        try:
            resp = await self._client.get(path, params=params, headers=headers)
            self._mark_healthy()
        except (httpx.ConnectError, httpx.TimeoutException) as exc:
            self._mark_unhealthy()
            raise CoreClientError(503, f"frothiq-core unreachable: {exc}") from exc

        if resp.status_code >= 400:
            detail = resp.text
            try:
                detail = resp.json().get("detail", detail)
            except Exception:
                pass
            raise CoreClientError(resp.status_code, detail)

        data = resp.json()

        # Store in cache
        if ttl and not bypass_cache:
            import json
            await self._set_cached(self._cache_key(path, params), json.dumps(data), ttl)

        return data

    async def post(
        self,
        path: str,
        body: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
        tenant_api_key: str | None = None,
    ) -> dict[str, Any]:
        """POST request to frothiq-core."""
        if not self._client:
            raise RuntimeError("CoreClient not started")

        headers = {}
        if tenant_api_key:
            headers["X-FrothIQ-Key"] = tenant_api_key

        try:
            resp = await self._client.post(path, json=body, params=params, headers=headers)
            self._mark_healthy()
        except (httpx.ConnectError, httpx.TimeoutException) as exc:
            self._mark_unhealthy()
            raise CoreClientError(503, f"frothiq-core unreachable: {exc}") from exc

        if resp.status_code >= 400:
            detail = resp.text
            try:
                detail = resp.json().get("detail", detail)
            except Exception:
                pass
            raise CoreClientError(resp.status_code, detail)

        return resp.json()

    async def health_check(self) -> dict[str, Any]:
        """Check frothiq-core health. Returns status dict even on failure."""
        try:
            data = await self.get("/api/v2/internal/health", bypass_cache=True)
            return {"status": "online", **data}
        except CoreClientError as exc:
            return {"status": "degraded", "detail": exc.detail}
        except Exception as exc:
            return {"status": "offline", "detail": str(exc)}


# Module-level singleton
core_client = CoreClient()
