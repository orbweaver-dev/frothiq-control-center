"""
Tenant billing state — SQLAlchemy async ORM model.

Persists the authoritative subscription state pulled from ERPNext.
This is the durable fallback when Redis cache is unavailable.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, Float, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from .user import Base, _utcnow


class TenantBillingState(Base):
    """
    One row per tenant — upserted whenever a billing sync event arrives
    (webhook or periodic pull). Monotonic state_version prevents rollback.
    """
    __tablename__ = "tenant_billing_state"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    tenant_id: Mapped[str] = mapped_column(
        String(64), unique=True, nullable=False, index=True
    )

    # ---------------------------------------------------------------------------
    # Subscription state
    # ---------------------------------------------------------------------------
    subscription_status: Mapped[str] = mapped_column(
        String(32), nullable=False, default="trial"
    )
    plan: Mapped[str] = mapped_column(String(32), nullable=False, default="free")
    effective_plan: Mapped[str] = mapped_column(String(32), nullable=False, default="free")
    enforcement_mode: Mapped[str] = mapped_column(
        String(32), nullable=False, default="alert_only"
    )

    # ---------------------------------------------------------------------------
    # Stripe / ERPNext references (read-only, never mutated here)
    # ---------------------------------------------------------------------------
    stripe_customer_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    erpnext_customer: Mapped[str | None] = mapped_column(String(140), nullable=True)
    erpnext_subscription: Mapped[str | None] = mapped_column(String(140), nullable=True)

    # ---------------------------------------------------------------------------
    # Grace / expiry
    # ---------------------------------------------------------------------------
    expiry: Mapped[float | None] = mapped_column(Float, nullable=True)
    grace_until: Mapped[float | None] = mapped_column(Float, nullable=True)

    # ---------------------------------------------------------------------------
    # Features / limits serialised as JSON strings
    # ---------------------------------------------------------------------------
    features_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    limits_json: Mapped[str | None] = mapped_column(Text, nullable=True)

    # ---------------------------------------------------------------------------
    # Monotonic version counter — incremented on every valid state update
    # ---------------------------------------------------------------------------
    state_version: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    # ---------------------------------------------------------------------------
    # Sync metadata
    # ---------------------------------------------------------------------------
    last_updated: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    source: Mapped[str] = mapped_column(String(32), nullable=False, default="fallback")

    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=_utcnow, onupdate=_utcnow
    )
