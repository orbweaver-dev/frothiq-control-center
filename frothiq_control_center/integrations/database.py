"""
Database setup — SQLAlchemy async engine + session factory.
"""

from __future__ import annotations

import logging

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from frothiq_control_center.config import get_settings
from frothiq_control_center.models.user import Base
# Import all models so Base.metadata has them registered before create_all()
import frothiq_control_center.models.edge     # noqa: F401
import frothiq_control_center.models.billing  # noqa: F401

logger = logging.getLogger(__name__)

_engine = None
_session_factory = None


def get_engine():
    global _engine
    if _engine is None:
        settings = get_settings()
        _engine = create_async_engine(
            settings.database_url,
            echo=settings.debug,
            pool_size=10,
            max_overflow=20,
            pool_pre_ping=True,
        )
    return _engine


def get_session_factory() -> async_sessionmaker[AsyncSession]:
    global _session_factory
    if _session_factory is None:
        _session_factory = async_sessionmaker(
            get_engine(),
            class_=AsyncSession,
            expire_on_commit=False,
        )
    return _session_factory


async def create_tables() -> None:
    """Create all tables if they don't exist. Idempotent (uses checkfirst=True)."""
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(lambda c: Base.metadata.create_all(c, checkfirst=True))
    logger.info("Database tables ready")


async def dispose_engine() -> None:
    engine = get_engine()
    await engine.dispose()
    logger.info("Database engine disposed")
