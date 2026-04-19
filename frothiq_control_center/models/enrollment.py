"""
IP allowlist + enrollment pending models.
"""

import uuid
from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, String, Text

from frothiq_control_center.models.user import Base


class IPAllowlist(Base):
    """Approved IPs permitted to access MC³."""

    __tablename__ = "cc_ip_allowlist"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    ip = Column(String(45), nullable=False, unique=True, index=True)  # IPv4 or IPv6
    user_email = Column(String(255), nullable=False)
    approved_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    notes = Column(Text, nullable=True)


class IPEnrollmentPending(Base):
    """One-time enrollment tokens awaiting admin approval."""

    __tablename__ = "cc_ip_enrollment_pending"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    # SHA-256 hex of the raw token sent in the approval email link
    token_hash = Column(String(64), nullable=False, unique=True, index=True)
    ip = Column(String(45), nullable=False, index=True)
    user_email = Column(String(255), nullable=False)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)
    used = Column(Boolean, nullable=False, default=False)
