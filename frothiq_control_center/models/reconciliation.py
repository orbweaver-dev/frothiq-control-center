"""
Reconciliation ORM models.

ReconciliationAuditLog — append-only audit trail (30-day retention)
EdgeAckRecord          — tracks edge plugin acknowledgements per contract version
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, Float, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from .user import Base, _utcnow


class ReconciliationAuditLog(Base):
    """
    Append-only audit trail for all reconciliation events.
    Rows are NEVER updated — only inserted and eventually pruned after 30 days.
    """
    __tablename__ = "reconciliation_audit_log"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    tenant_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)

    # Event classification
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)   # drift_detected, reconciled, deferred, edge_ack, error
    drift_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    severity: Mapped[str | None] = mapped_column(String(16), nullable=True)  # LOW, MEDIUM, HIGH, CRITICAL

    # State snapshots (JSON serialised)
    mc3_state_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    erp_state_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    edge_state_json: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Result
    action_taken: Mapped[str | None] = mapped_column(Text, nullable=True)   # human-readable description
    result: Mapped[str | None] = mapped_column(String(32), nullable=True)   # success, deferred, failed, skipped
    error_detail: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Version tracking
    before_version: Mapped[int | None] = mapped_column(Integer, nullable=True)
    after_version: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # Timing
    detected_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow, index=True)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    duration_ms: Mapped[float | None] = mapped_column(Float, nullable=True)

    __table_args__ = (
        Index("ix_recon_audit_tenant_detected", "tenant_id", "detected_at"),
        Index("ix_recon_audit_event_type", "event_type"),
    )


class EdgeAckRecord(Base):
    """
    Tracks edge plugin acknowledgements of FederationContract pushes.
    One row per (tenant_id, edge_id) — upserted on each ACK.
    """
    __tablename__ = "edge_ack_records"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    tenant_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    edge_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)

    # Contract version the edge last acknowledged
    last_ack_version: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    # Version we most recently pushed (may be ahead of last_ack_version if ACK not yet received)
    last_pushed_version: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    # Metrics
    ack_latency_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    retry_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    push_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    # Timestamps
    last_pushed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_ack_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=_utcnow, onupdate=_utcnow
    )

    # Status: synced | pending | retrying | failed | offline
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="pending")

    __table_args__ = (
        Index("ix_edge_ack_tenant_edge", "tenant_id", "edge_id", unique=True),
    )
