"""
Pydantic request/response schemas for the Control Center API.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, EmailStr, Field


# ---------------------------------------------------------------------------
# Auth schemas
# ---------------------------------------------------------------------------

class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    role: str
    user_id: str
    full_name: str


class RefreshRequest(BaseModel):
    refresh_token: str


class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(min_length=12)
    full_name: str
    role: Literal["super_admin", "security_analyst", "billing_admin", "read_only"] = "read_only"
    ip_allowlist: str | None = None


class UserResponse(BaseModel):
    id: str
    email: str
    full_name: str
    role: str
    is_active: bool
    created_at: datetime
    last_login: datetime | None = None

    model_config = {"from_attributes": True}


class UserUpdate(BaseModel):
    full_name: str | None = None
    role: Literal["super_admin", "security_analyst", "billing_admin", "read_only"] | None = None
    is_active: bool | None = None
    ip_allowlist: str | None = None


# ---------------------------------------------------------------------------
# Dashboard / system health schemas
# ---------------------------------------------------------------------------

class SystemHealthResponse(BaseModel):
    core_status: Literal["online", "degraded", "offline"]
    core_version: str | None
    total_tenants: int
    active_tenants: int
    defense_clusters: int
    active_policies: int
    licenses_active: int
    licenses_suspended: int
    events_last_hour: int
    threat_level: Literal["low", "medium", "high", "critical"]
    instability_index: float
    revenue_pressure_index: float
    checked_at: datetime


# ---------------------------------------------------------------------------
# Defense Mesh schemas
# ---------------------------------------------------------------------------

class DefenseClusterSummary(BaseModel):
    cluster_id: str
    campaign_count: int
    tenant_hit_count: int
    severity: str
    action: str
    auto_apply_eligible: bool
    first_seen: datetime | None
    last_seen: datetime | None


class DefenseMeshOverview(BaseModel):
    total_clusters: int
    clusters: list[DefenseClusterSummary]
    engine_healthy: bool
    last_refresh: datetime | None


# ---------------------------------------------------------------------------
# Policy Mesh schemas
# ---------------------------------------------------------------------------

class PolicySummary(BaseModel):
    policy_id: str
    name: str
    version: int
    status: str
    tenant_count: int
    created_at: datetime | None
    updated_at: datetime | None


class PolicyMeshOverview(BaseModel):
    total_policies: int
    active_policies: int
    policies: list[PolicySummary]


# ---------------------------------------------------------------------------
# License schemas
# ---------------------------------------------------------------------------

class LicenseSummary(BaseModel):
    tenant_id: str
    plan: str
    status: Literal["active", "suspended", "expired", "trial"]
    max_sites: int
    active_sites: int
    last_sync: datetime | None
    sync_healthy: bool


class LicenseOverview(BaseModel):
    total: int
    active: int
    suspended: int
    expired: int
    tenants: list[LicenseSummary]


# ---------------------------------------------------------------------------
# Envelope schemas
# ---------------------------------------------------------------------------

class EnvelopeResponse(BaseModel):
    tenant_id: str
    envelope_version: str | None
    signature_valid: bool
    sections: dict[str, Any]
    fetched_at: datetime


class EnvelopeDiff(BaseModel):
    tenant_id: str
    from_version: str
    to_version: str
    changes: list[dict[str, Any]]
    generated_at: datetime


# ---------------------------------------------------------------------------
# Monetization schemas
# ---------------------------------------------------------------------------

class MonetizationOverview(BaseModel):
    total_tenants: int
    plan_breakdown: dict[str, int]
    upgrade_signals_last_7d: int
    paywall_hits_last_7d: int
    revenue_pressure_index: float
    top_upgrade_candidates: list[dict[str, Any]]


# ---------------------------------------------------------------------------
# Simulation schemas
# ---------------------------------------------------------------------------

class SimulationRunRequest(BaseModel):
    scenario_id: str
    tenant_id: str | None = None
    parameters: dict[str, Any] = Field(default_factory=dict)


class SimulationRunResponse(BaseModel):
    sim_id: str
    status: str
    scenario_id: str
    das_score: float | None = None
    dei_score: float | None = None
    pps_score: float | None = None
    started_at: datetime
    completed_at: datetime | None = None


class SimulationMetrics(BaseModel):
    das_avg: float
    dei_avg: float
    pps_avg: float
    das_trend: list[float]
    dei_trend: list[float]
    pps_trend: list[float]
    period_days: int


# ---------------------------------------------------------------------------
# Audit log schemas
# ---------------------------------------------------------------------------

class AuditLogEntry(BaseModel):
    id: str
    user_id: str | None
    user_email: str | None
    action: str
    resource: str | None
    detail: str | None
    ip_address: str | None
    status: str
    created_at: datetime

    model_config = {"from_attributes": True}


class AuditLogPage(BaseModel):
    total: int
    page: int
    page_size: int
    entries: list[AuditLogEntry]


# ---------------------------------------------------------------------------
# Tenant management schemas
# ---------------------------------------------------------------------------

class TenantAdminView(BaseModel):
    tenant_id: str
    plan: str
    rate_limit_rpm: int
    max_sites: int
    block_score: int
    features: dict[str, bool]


class TenantListResponse(BaseModel):
    total: int
    tenants: list[TenantAdminView]


# ---------------------------------------------------------------------------
# WebSocket event schemas
# ---------------------------------------------------------------------------

class WSEvent(BaseModel):
    event_type: str
    payload: dict[str, Any]
    tenant_id: str | None = None
    ts: float
