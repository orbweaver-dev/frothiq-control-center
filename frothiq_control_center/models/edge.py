"""
Edge Node + Tenant + Feature Flag + Threat Intelligence ORM models.

EdgeNode      — a self-registering plugin installation on a customer site
EdgeTenant    — auto-created tenant record for each unique registrant domain
FeatureFlag   — global platform control flags (e.g. PLAN_ENFORCEMENT_ENABLED)
ThreatReport  — community threat pool: IPs reported as blocked by edge nodes
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column
import json as _json

from .user import Base, _utcnow


class EdgeTenant(Base):
    """
    Auto-created on first edge registration for a given domain.
    One tenant per domain; plan defaults to 'free'.
    """
    __tablename__ = "edge_tenants"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    domain: Mapped[str] = mapped_column(String(253), unique=True, nullable=False, index=True)
    tenant_id: Mapped[str] = mapped_column(
        String(36), unique=True, nullable=False,
        default=lambda: str(uuid.uuid4()),
    )
    plan: Mapped[str] = mapped_column(String(32), nullable=False, default="free")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow, onupdate=_utcnow)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Registration gate: 'active' | 'revoked' | 'deregistered'
    # revoked      — domain permanently blocked from re-registering
    # deregistered — archived; re-registration allowed with matching contact_email
    registration_state: Mapped[str] = mapped_column(String(32), nullable=False, default="active")
    contact_email: Mapped[str | None] = mapped_column(String(254), nullable=True)
    deregistered_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    # JSON snapshot of plan/notes/flags at deregistration time, used on re-registration resync
    archived_data: Mapped[str | None] = mapped_column(Text, nullable=True)


class EdgeNode(Base):
    """
    Represents a single plugin installation on a customer site.
    Multiple nodes can share one EdgeTenant (same domain, multiple installs).
    """
    __tablename__ = "edge_nodes"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    edge_id: Mapped[str] = mapped_column(String(128), unique=True, nullable=False, index=True)
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    domain: Mapped[str] = mapped_column(String(253), nullable=False, index=True)
    platform: Mapped[str] = mapped_column(String(64), nullable=False)
    plugin_version: Mapped[str] = mapped_column(String(32), nullable=False)
    # Lifecycle state: REGISTERED → ACTIVE → SYNCED | DEGRADED | REVOKED
    state: Mapped[str] = mapped_column(String(32), nullable=False, default="REGISTERED")
    plan: Mapped[str] = mapped_column(String(32), nullable=False, default="free")
    registered_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_sync_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    registration_count: Mapped[int] = mapped_column(Integer, default=1)


class FeatureFlag(Base):
    """
    Global platform control flags — managed only via MC3 super_admin dashboard.
    All flags start as disabled (safe defaults).
    """
    __tablename__ = "feature_flags"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    flag_key: Mapped[str] = mapped_column(String(128), unique=True, nullable=False, index=True)
    flag_value: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    last_changed_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
    last_changed_by: Mapped[str | None] = mapped_column(String(255), nullable=True)


class ThreatReport(Base):
    """
    Community threat intelligence pool.

    Every time an edge node blocks an IP it reports the event here.
    IPs reported by multiple distinct tenants accumulate threat_score and
    are included in the /api/v1/edge/blocklist feed for all nodes.

    One row per (ip, tenant_id) pair — reports from the same tenant are
    consolidated (report_count incremented, last_seen updated).
    Cross-tenant reports raise tenant_count and boost threat_score.

    Score thresholds that qualify an IP for the community blocklist:
      threat_score >= 50   — enterprise tier
      threat_score >= 70   — pro tier
      threat_score >= 90   — free tier
    """
    __tablename__ = "threat_reports"
    __table_args__ = (
        UniqueConstraint("ip", "tenant_id", name="uq_threat_ip_tenant"),
    )

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    ip: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    edge_id: Mapped[str] = mapped_column(String(128), nullable=False)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False, default="blocked_local")
    severity: Mapped[str] = mapped_column(String(16), nullable=False, default="high")
    reason: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    report_count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    # Computed on write — count of distinct tenants that have reported this IP
    tenant_count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    # threat_score: raised as more tenants confirm the IP (0–100)
    threat_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
