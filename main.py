"""
FrothIQ Control Center — standalone FastAPI application

Architecture:
  This is the central command authority for the FrothIQ security platform.
  It is completely decoupled from Frappe and communicates with frothiq-core
  exclusively via signed HTTP API calls.

Run:
  uvicorn main:app --host 0.0.0.0 --port 8002 --workers 2

Environment:
  See frothiq_control_center/config/settings.py for all CC_* variables.
"""

from __future__ import annotations

import asyncio
import logging
import sys

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from frothiq_control_center import __version__
from frothiq_control_center.api import api_router, edge_registration_router
from frothiq_control_center.config import get_settings
from frothiq_control_center.integrations import (
    close_redis,
    create_tables,
    dispose_engine,
    get_cache_client,
    get_pubsub_client,
    get_session_factory,
)
from frothiq_control_center.middleware import DBSessionMiddleware, IPAllowlistMiddleware, limiter
from frothiq_control_center.services.core_client import core_client
from frothiq_control_center.websocket import start_event_dispatcher, ws_router
from frothiq_control_center.reconciliation.reconciliation_scheduler import ReconciliationScheduler
from frothiq_control_center.predictive_sync.predictive_sync_orchestrator import PredictiveSyncScheduler
from frothiq_control_center.services.enforcement_engine import run_enforcement_loop
from frothiq_control_center.services.edge_outage_service import detect_offline_nodes

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    stream=sys.stdout,
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan — startup and shutdown."""
    settings = get_settings()
    logger.info("Starting FrothIQ Control Center v%s (%s)", __version__, settings.environment)

    # Initialize database
    await create_tables()

    # Seed default feature flags (idempotent — only sets if missing)
    await _seed_default_flags()

    # Initialize Redis
    cache = get_cache_client()
    pubsub = get_pubsub_client()

    # Start frothiq-core HTTP client
    await core_client.startup(redis_client=cache)

    # Start WebSocket event dispatcher (Redis pub/sub → WebSocket broadcast)
    dispatcher_task = asyncio.create_task(
        start_event_dispatcher(pubsub),
        name="event_dispatcher",
    )

    # Start reconciliation scheduler (drift detection + self-healing)
    recon_scheduler = ReconciliationScheduler()
    recon_task = asyncio.create_task(
        recon_scheduler.run(),
        name="reconciliation_scheduler",
    )

    # Start predictive sync scheduler (signal detection + contract pre-staging)
    predictive_scheduler = PredictiveSyncScheduler()
    predictive_task = asyncio.create_task(
        predictive_scheduler.run(),
        name="predictive_sync_scheduler",
    )

    # Start CIDR consolidation analyzer (runs every 6 hours)
    cidr_task = asyncio.create_task(
        _run_cidr_analyzer_loop(),
        name="cidr_analyzer",
    )

    # Start HTTP policy enforcement engine (runs every 60 seconds)
    enforcement_task = asyncio.create_task(
        run_enforcement_loop(cache),
        name="enforcement_engine",
    )

    # Start outage detector (runs every 5 minutes — checks for silent edge nodes)
    outage_task = asyncio.create_task(
        _run_outage_detector_loop(),
        name="outage_detector",
    )

    logger.info(
        "Control Center ready — core: %s | port: %d",
        settings.core_base_url,
        settings.port,
    )

    yield  # Application runs here

    # Shutdown
    logger.info("Shutting down FrothIQ Control Center")
    outage_task.cancel()
    enforcement_task.cancel()
    cidr_task.cancel()
    predictive_task.cancel()
    recon_task.cancel()
    dispatcher_task.cancel()
    try:
        await asyncio.gather(
            outage_task, enforcement_task, cidr_task, predictive_task, recon_task, dispatcher_task,
            return_exceptions=True,
        )
    except asyncio.CancelledError:
        pass

    await core_client.shutdown()
    await dispose_engine()
    await close_redis()
    logger.info("Shutdown complete")


async def _run_outage_detector_loop() -> None:
    """
    Background loop: scan edge nodes for missed heartbeats and open outage windows.
    Also closes windows for nodes that have since recovered.
    Runs every 5 minutes starting 90 seconds after startup.
    """
    from frothiq_control_center.integrations.database import get_session_factory as _gsf

    await asyncio.sleep(90)  # let nodes send their first heartbeat before checking
    interval = 300  # 5 minutes
    while True:
        try:
            factory = _gsf()
            await detect_offline_nodes(factory)
        except asyncio.CancelledError:
            break
        except Exception as exc:
            logger.error("outage_detector: loop error: %s", exc)
        await asyncio.sleep(interval)


async def _run_cidr_analyzer_loop() -> None:
    """
    Background loop: scan the live blacklist for CIDR consolidation opportunities.
    Runs at startup (after a short delay) then every 6 hours.
    """
    from frothiq_control_center.integrations.database import get_session_factory as _gsf
    from frothiq_control_center.services import cidr_analyzer

    # Wait for DB and nft to settle after startup
    await asyncio.sleep(60)

    interval = 6 * 3600  # 6 hours
    while True:
        try:
            factory = _gsf()
            async with factory() as session:
                result = await cidr_analyzer.run_scan(session)
                if result["new_recommendations"] > 0:
                    logger.info(
                        "cidr_analyzer: %d new recommendations (%d analyzed, %.2fs)",
                        result["new_recommendations"],
                        result["total_analyzed"],
                        result["elapsed_seconds"],
                    )
        except asyncio.CancelledError:
            break
        except Exception as exc:
            logger.error("cidr_analyzer: loop error: %s", exc)
        await asyncio.sleep(interval)


async def _seed_default_flags() -> None:
    """Ensure default feature flags exist in the database.

    Idempotent — only inserts a flag if it has never been set.
    All flags default to False/off so operators must explicitly enable enforcement.
    """
    import uuid
    from datetime import datetime, timezone

    from sqlalchemy import select

    from frothiq_control_center.integrations.database import get_session_factory as _gsf
    from frothiq_control_center.models.edge import FeatureFlag

    defaults = {
        "PLAN_ENFORCEMENT_ENABLED": (
            False,
            "When true, enforce plan limits and activate paywall injection. "
            "Default false — all features accessible regardless of plan.",
        ),
        "UPGRADE_SYSTEM_ENABLED": (
            False,
            "When true, show upgrade prompts and enable upgrade orchestration.",
        ),
        "REGISTRATION_ENABLED": (
            True,
            "When false, new edge node registrations are rejected.",
        ),
    }

    factory = _gsf()
    async with factory() as session:
        for flag_key, (default_value, description) in defaults.items():
            result = await session.execute(
                select(FeatureFlag).where(FeatureFlag.flag_key == flag_key)
            )
            if result.scalar_one_or_none() is None:
                session.add(
                    FeatureFlag(
                        id=str(uuid.uuid4()),
                        flag_key=flag_key,
                        flag_value=default_value,
                        description=description,
                        last_changed_by="system",
                        last_changed_at=datetime.now(timezone.utc).replace(tzinfo=None),
                    )
                )
                logger.info("feature_flag: seeded %s=%s", flag_key, default_value)
        await session.commit()


def create_app() -> FastAPI:
    settings = get_settings()

    app = FastAPI(
        title="FrothIQ Control Center",
        description=(
            "Central command authority for the FrothIQ security platform.\n\n"
            "**Roles:** super_admin · security_analyst · billing_admin · read_only\n\n"
            "**Auth:** JWT Bearer token — obtain via POST /api/v1/cc/auth/login"
        ),
        version=__version__,
        docs_url="/docs" if settings.environment != "production" else None,
        redoc_url="/redoc" if settings.environment != "production" else None,
        lifespan=lifespan,
    )

    # CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins_list,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-Service-Key"],
    )

    # Rate limiting (slowapi + Redis)
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

    # IP allowlist (admin endpoint protection)
    app.add_middleware(IPAllowlistMiddleware)

    # DB + Redis session injection
    session_factory = get_session_factory()
    cache = get_cache_client()
    app.add_middleware(DBSessionMiddleware, session_factory=session_factory, redis_client=cache)

    # API routes
    app.include_router(api_router)

    # Public edge registration (no JWT — accessible to all edge plugins)
    app.include_router(edge_registration_router)

    # WebSocket routes (not under /api/v1/cc prefix)
    app.include_router(ws_router)

    # Health endpoint (unauthenticated — for load balancer / k8s probes)
    @app.get("/health", tags=["health"])
    async def health():
        core_health = await core_client.health_check()
        return {
            "status": "ok",
            "version": __version__,
            "core": core_health.get("status", "unknown"),
        }

    # Global exception handler
    @app.exception_handler(Exception)
    async def unhandled_exception(request, exc):
        logger.error("Unhandled exception: %s", exc, exc_info=True)
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal server error"},
        )

    return app


app = create_app()

if __name__ == "__main__":
    import uvicorn

    settings = get_settings()
    uvicorn.run(
        "main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.environment == "development",
        log_level="info",
    )
