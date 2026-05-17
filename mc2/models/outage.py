"""
EdgeOutageEvent — tracks site outage windows per edge node.

Two sources populate this table:
  1. Plugin-reported  — plugin detects it caused an outage (e.g. bad .htaccess block)
     and POSTs to /api/v1/edge/outage immediately after self-healing.
  2. MC3-detected     — background loop notices a node has missed heartbeats beyond
     the degraded (10 min) or offline (30 min) threshold and opens a window itself.

Windows are closed automatically when:
  - The plugin self-heals and reports (auto_resolved=True)
  - The node sends a heartbeat and an open window exists (outage_service.close_outage)
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from .user import Base, _utcnow


class EdgeOutageEvent(Base):
    __tablename__ = "edge_outage_events"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    edge_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    domain: Mapped[str] = mapped_column(String(253), nullable=False, index=True)
    # block_rule_lockout | heartbeat_miss_degraded | heartbeat_miss_offline | plugin_error
    outage_type: Mapped[str] = mapped_column(String(64), nullable=False)
    cause: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    cause_detail: Mapped[str] = mapped_column(Text, nullable=False, default="")
    started_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=_utcnow, index=True)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    # seconds between started_at and resolved_at; null while open
    duration_sec: Mapped[int | None] = mapped_column(Integer, nullable=True)
    auto_resolved: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    # low | medium | high | critical
    severity: Mapped[str] = mapped_column(String(20), nullable=False, default="high")
    # True while no resolved_at exists
    is_open: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, index=True)
    alert_sent: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    # ERPNext Issue name created for this outage (e.g. "ISS-2026-00042")
    frappe_ticket_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
