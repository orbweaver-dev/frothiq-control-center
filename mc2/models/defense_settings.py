"""
FrothIQ Defense Settings models — IP list, port rules, settings store, audit.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, Enum, Float, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from .user import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


class FrothiqIPEntry(Base):
    __tablename__ = "frothiq_ip_list"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    ip: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    label: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    list_type: Mapped[str] = mapped_column(
        Enum("whitelist", "blacklist", name="ip_list_type"), nullable=False, default="whitelist"
    )
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
    created_by: Mapped[str] = mapped_column(String(255), nullable=False, default="")


class FrothiqPortRule(Base):
    __tablename__ = "frothiq_port_rules"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    protocol: Mapped[str] = mapped_column(
        Enum("tcp", "udp", "both", name="port_protocol"), nullable=False, default="tcp"
    )
    action: Mapped[str] = mapped_column(
        Enum("accept", "drop", name="port_action"), nullable=False, default="accept"
    )
    description: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
    created_by: Mapped[str] = mapped_column(String(255), nullable=False, default="")


class FrothiqNftSetting(Base):
    """Key-value config store for LFD, validation, and decommission settings."""

    __tablename__ = "frothiq_nft_settings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    category: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    key: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    value: Mapped[str] = mapped_column(Text, nullable=False, default="")
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow, onupdate=_utcnow)
    updated_by: Mapped[str] = mapped_column(String(255), nullable=False, default="")


class FrothiqNftAudit(Base):
    """Defense-specific audit trail separate from the global CC audit log."""

    __tablename__ = "frothiq_nft_audit"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_email: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    action: Mapped[str] = mapped_column(String(255), nullable=False)
    category: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow, index=True)


class FrothiqCidrRecommendation(Base):
    """
    A CIDR consolidation recommendation produced by the background analyzer.

    Each row represents one suggested CIDR block that could replace multiple
    individual IP entries in the blacklist.  Status transitions:
      pending  → applied   (operator accepted and nft applied)
      pending  → dismissed (operator rejected)
    """

    __tablename__ = "frothiq_cidr_recommendations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    cidr: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    prefix_len: Mapped[int] = mapped_column(Integer, nullable=False)
    covered_ips: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    covered_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    total_in_subnet: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    density_pct: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    entries_saved: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    status: Mapped[str] = mapped_column(
        Enum("pending", "applied", "dismissed", name="cidr_rec_status"),
        nullable=False, default="pending", index=True,
    )
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow, index=True)
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    reviewed_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
