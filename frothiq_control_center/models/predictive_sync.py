"""
Predictive Sync ORM models.

PredictiveSignalRecord — one row per (tenant_id, signal_type); upserted
StagedContractRecord   — one row per tenant_id (latest staged contract); upserted
PredictionRecord       — append-only accuracy history, one row per prediction attempt
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, Float, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from .user import Base, _utcnow


class PredictiveSignalRecord(Base):
    """
    Most recent occurrence of each signal type per tenant.
    Row is upserted — only the latest signal instance is kept here.
    History flows through PredictionRecord.
    """
    __tablename__ = "predictive_signals"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    tenant_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    signal_type: Mapped[str] = mapped_column(String(64), nullable=False)

    # Prediction metadata
    confidence_score: Mapped[float] = mapped_column(Float, nullable=False)
    expected_transition_from: Mapped[str | None] = mapped_column(String(32), nullable=True)
    expected_transition_to: Mapped[str | None] = mapped_column(String(32), nullable=True)
    expected_window_start: Mapped[float | None] = mapped_column(Float, nullable=True)   # unix ts
    expected_window_end: Mapped[float | None] = mapped_column(Float, nullable=True)     # unix ts

    # Source data that produced this signal (JSON)
    source_data_json: Mapped[str | None] = mapped_column(Text, nullable=True)

    detected_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    processed: Mapped[int] = mapped_column(Integer, nullable=False, default=0)  # 0=pending, 1=acted, 2=expired

    __table_args__ = (
        Index("ix_signal_tenant_type", "tenant_id", "signal_type", unique=True),
    )


class StagedContractRecord(Base):
    """
    A pre-computed FederationContract waiting for ERPNext confirmation.
    One row per tenant — upserted on each new prediction.
    Discarded (status → 'discarded') on mismatch; activated on confirmation.
    """
    __tablename__ = "staged_contracts"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    tenant_id: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)

    # Predicted state (JSON serialised ProjectedState)
    predicted_state_json: Mapped[str] = mapped_column(Text, nullable=False)

    # Contract payload (JSON — what gets sent to edge)
    contract_json: Mapped[str] = mapped_column(Text, nullable=False)

    confidence_score: Mapped[float] = mapped_column(Float, nullable=False)
    predicted_from: Mapped[str] = mapped_column(String(32), nullable=False)
    predicted_to: Mapped[str] = mapped_column(String(32), nullable=False)
    contract_version: Mapped[int] = mapped_column(Integer, nullable=False)

    # Lifecycle timestamps
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
    activation_timestamp: Mapped[float] = mapped_column(Float, nullable=False)   # unix ts
    valid_until: Mapped[float] = mapped_column(Float, nullable=False)             # unix ts (hard TTL)

    # Status: pending | dispatched | activated | confirmed | discarded | expired
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="pending")
    activated_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    activation_mode: Mapped[str | None] = mapped_column(String(32), nullable=True)  # confirmed | auto | none

    # Edge dispatch tracking (JSON list of edge_ids notified)
    dispatched_to_json: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Accuracy outcome (set by confirmation_listener)
    outcome: Mapped[str | None] = mapped_column(String(32), nullable=True)  # correct | incorrect | timeout | discarded
    outcome_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    erp_confirmed_state: Mapped[str | None] = mapped_column(String(32), nullable=True)


class PredictionRecord(Base):
    """
    Append-only record of each prediction attempt and its outcome.
    Used by prediction_accuracy_tracker for metrics.
    """
    __tablename__ = "prediction_records"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    tenant_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    signal_type: Mapped[str] = mapped_column(String(64), nullable=False)
    predicted_to: Mapped[str] = mapped_column(String(32), nullable=False)
    confidence_score: Mapped[float] = mapped_column(Float, nullable=False)

    # Outcome fields (filled in by confirmation_listener)
    outcome: Mapped[str | None] = mapped_column(String(32), nullable=True)  # correct | incorrect | timeout | cancelled
    confirmed_state: Mapped[str | None] = mapped_column(String(32), nullable=True)
    latency_saved_ms: Mapped[float | None] = mapped_column(Float, nullable=True)

    predicted_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow, index=True)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    __table_args__ = (
        Index("ix_prediction_tenant_at", "tenant_id", "predicted_at"),
    )
