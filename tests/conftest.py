"""
Pytest configuration and shared fixtures for FrothIQ Control Center tests.
"""

from __future__ import annotations

import asyncio
import json
import time
from typing import AsyncGenerator
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio
from fastapi.testclient import TestClient
from httpx import AsyncClient, ASGITransport

from frothiq_control_center.auth import (
    create_access_token,
    create_refresh_token,
    hash_password,
)


# ---------------------------------------------------------------------------
# Event loop
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def event_loop():
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


# ---------------------------------------------------------------------------
# Mock frothiq-core client
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_core_client():
    """Mock CoreClient so tests don't need a live frothiq-core."""
    with patch("frothiq_control_center.services.core_client.core_client") as mock:
        mock.get = AsyncMock(return_value={})
        mock.post = AsyncMock(return_value={})
        mock.health_check = AsyncMock(return_value={"status": "online", "version": "0.6.0"})
        mock.is_healthy = MagicMock(return_value=True)
        yield mock


# ---------------------------------------------------------------------------
# Mock database
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_db():
    """Mock async database session."""
    db = AsyncMock()
    db.execute = AsyncMock()
    db.commit = AsyncMock()
    db.rollback = AsyncMock()
    db.close = AsyncMock()
    db.add = MagicMock()
    db.refresh = AsyncMock()
    return db


# ---------------------------------------------------------------------------
# Mock Redis
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_redis():
    """Mock Redis client."""
    redis = AsyncMock()
    redis.get = AsyncMock(return_value=None)
    redis.setex = AsyncMock()
    redis.xadd = AsyncMock()
    redis.publish = AsyncMock()
    return redis


# ---------------------------------------------------------------------------
# Auth tokens for different roles
# ---------------------------------------------------------------------------

@pytest.fixture
def super_admin_token():
    return create_access_token("user-super-admin", "super_admin")


@pytest.fixture
def security_analyst_token():
    return create_access_token("user-security", "security_analyst")


@pytest.fixture
def billing_admin_token():
    return create_access_token("user-billing", "billing_admin")


@pytest.fixture
def read_only_token():
    return create_access_token("user-readonly", "read_only")


@pytest.fixture
def super_admin_headers(super_admin_token):
    return {"Authorization": f"Bearer {super_admin_token}"}


@pytest.fixture
def security_analyst_headers(security_analyst_token):
    return {"Authorization": f"Bearer {security_analyst_token}"}


@pytest.fixture
def billing_admin_headers(billing_admin_token):
    return {"Authorization": f"Bearer {billing_admin_token}"}


@pytest.fixture
def read_only_headers(read_only_token):
    return {"Authorization": f"Bearer {read_only_token}"}


# ---------------------------------------------------------------------------
# FastAPI test app
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_session_factory(mock_db):
    """Return a session factory that yields the mock db."""
    from contextlib import asynccontextmanager

    @asynccontextmanager
    async def _factory():
        yield mock_db

    return _factory


@pytest.fixture
def app(mock_db, mock_redis, mock_session_factory):
    """Create a test FastAPI app with mocked dependencies."""
    import os
    os.environ.setdefault("CC_SECRET_KEY", "test-secret-key-minimum-32-chars-long-yes")
    os.environ.setdefault("CC_DATABASE_URL", "sqlite+aiosqlite:///./test.db")
    os.environ.setdefault("CC_REDIS_URL", "redis://localhost:6379/15")
    os.environ.setdefault("CC_ENVIRONMENT", "development")
    os.environ.setdefault("CC_CORE_SERVICE_API_KEY", "test-service-key")

    from frothiq_control_center.config.settings import get_settings
    get_settings.cache_clear()

    from fastapi import FastAPI
    from fastapi.middleware.cors import CORSMiddleware
    from frothiq_control_center.api import api_router
    from frothiq_control_center.middleware import DBSessionMiddleware, IPAllowlistMiddleware
    from frothiq_control_center.websocket import ws_router

    test_app = FastAPI()
    test_app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
    test_app.add_middleware(IPAllowlistMiddleware)
    test_app.add_middleware(DBSessionMiddleware, session_factory=mock_session_factory, redis_client=mock_redis)
    test_app.include_router(api_router)
    test_app.include_router(ws_router)

    @test_app.get("/health")
    async def health():
        return {"status": "ok"}

    return test_app


@pytest_asyncio.fixture
async def client(app) -> AsyncGenerator[AsyncClient, None]:
    """Async HTTP test client."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


# ---------------------------------------------------------------------------
# Sample data fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def sample_cluster():
    return {
        "cluster_id": "cluster-abc123",
        "campaign_ids": ["camp-1", "camp-2", "camp-3"],
        "severity": "high",
        "action": "block_asn",
        "auto_apply_eligible": True,
        "campaign_count": 3,
        "tenant_hit_count": 5,
        "first_seen": "2024-01-01T00:00:00Z",
        "last_seen": "2024-01-15T12:00:00Z",
    }


@pytest.fixture
def sample_tenant():
    return {
        "tenant_id": "tenant-001",
        "plan": "pro",
        "rate_limit_rpm": 600,
        "max_sites": 10,
        "active_sites": 7,
        "block_score": 80,
        "features": {
            "defense_mesh": True,
            "policy_mesh": True,
            "simulation_engine": False,
        },
        "last_sync": "2024-01-15T10:00:00Z",
    }


@pytest.fixture
def sample_policy():
    return {
        "policy_id": "policy-xyz",
        "name": "Block High-Risk IPs",
        "version": 3,
        "status": "active",
        "tenant_count": 12,
        "created_at": "2024-01-01T00:00:00Z",
        "updated_at": "2024-01-10T08:00:00Z",
    }


@pytest.fixture
def sample_envelope():
    return {
        "version": "v1.2.3",
        "signature": "sha256:abcdef1234567890",
        "sections": {
            "rules": {"block_score": 80, "threshold": 100},
            "features": {"defense_mesh": True},
            "license": {"plan": "pro", "expires": "2025-01-01"},
        },
    }
