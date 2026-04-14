"""
Redis client setup — cache + pub/sub clients.
"""

from __future__ import annotations

import logging

import redis.asyncio as aioredis

from frothiq_control_center.config import get_settings

logger = logging.getLogger(__name__)

_cache_client: aioredis.Redis | None = None
_pubsub_client: aioredis.Redis | None = None


def get_cache_client() -> aioredis.Redis:
    global _cache_client
    if _cache_client is None:
        settings = get_settings()
        _cache_client = aioredis.from_url(
            settings.redis_url,
            encoding="utf-8",
            decode_responses=True,
        )
    return _cache_client


def get_pubsub_client() -> aioredis.Redis:
    global _pubsub_client
    if _pubsub_client is None:
        settings = get_settings()
        _pubsub_client = aioredis.from_url(
            settings.redis_pubsub_url,
            encoding="utf-8",
            decode_responses=True,
        )
    return _pubsub_client


async def close_redis() -> None:
    global _cache_client, _pubsub_client
    if _cache_client:
        await _cache_client.aclose()
        logger.info("Redis cache client closed")
    if _pubsub_client:
        await _pubsub_client.aclose()
        logger.info("Redis pubsub client closed")
