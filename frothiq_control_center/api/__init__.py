from fastapi import APIRouter

from .routes_auth import router as auth_router
from .routes_dashboard import router as dashboard_router
from .routes_defense import router as defense_router
from .routes_policy import router as policy_router
from .routes_license import router as license_router
from .routes_envelope import router as envelope_router
from .routes_monetization import router as monetization_router
from .routes_simulation import router as simulation_router
from .routes_flywheel import router as flywheel_router
from .routes_tenants import router as tenants_router
from .routes_audit import router as audit_router
from .routes_commands import router as commands_router
from .routes_edge import public_router as edge_public_router, protected_router as edge_protected_router

# All control center routes under /api/v1/cc/
api_router = APIRouter(prefix="/api/v1/cc")
api_router.include_router(auth_router)
api_router.include_router(dashboard_router)
api_router.include_router(defense_router)
api_router.include_router(policy_router)
api_router.include_router(license_router)
api_router.include_router(envelope_router)
api_router.include_router(monetization_router)
api_router.include_router(simulation_router)
api_router.include_router(flywheel_router)
api_router.include_router(tenants_router)
api_router.include_router(audit_router)
api_router.include_router(commands_router)
# Edge management routes (JWT protected, under /api/v1/cc/)
api_router.include_router(edge_protected_router)

# Public edge registration (no JWT — separate prefix /api/v1/edge/)
# This is mounted directly on the FastAPI app in main.py
edge_registration_router = edge_public_router

__all__ = ["api_router", "edge_registration_router"]
