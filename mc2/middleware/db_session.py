"""
Database session middleware — attaches an AsyncSession to request.state.db.
Also attaches the Redis client to request.state.redis.
"""

from __future__ import annotations

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request


class DBSessionMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, session_factory, redis_client=None):
        super().__init__(app)
        self._session_factory = session_factory
        self._redis = redis_client

    async def dispatch(self, request: Request, call_next):
        request.state.redis = self._redis

        async with self._session_factory() as session:
            request.state.db = session
            try:
                response = await call_next(request)
            except Exception:
                await session.rollback()
                raise
            finally:
                await session.close()

        return response
