"""
TeleOps — multi-tenant telephony registry.

Every routing table carries a SyncMixin so MC3 and per-site orbweaver_pbx can
edit the same record bidirectionally. Locks + history (Phase C) prevent
collisions and enable revert; they're separate tables added in a later phase.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
	Boolean,
	DateTime,
	Float,
	ForeignKey,
	Integer,
	String,
	Text,
	UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from mc3.security.encryption import EncryptedText

from .user import Base, _utcnow


# ─────────────────────────────────────────────────────────────────────────────
# Sync mixin — shared by every routing table that's editable from both surfaces.
# ─────────────────────────────────────────────────────────────────────────────


class SyncMixin:
	uid: Mapped[str] = mapped_column(
		String(36), primary_key=True, default=lambda: str(uuid.uuid4())
	)
	version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
	last_modified_at: Mapped[datetime] = mapped_column(
		DateTime, default=_utcnow, onupdate=_utcnow, nullable=False
	)
	last_modified_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
	last_modified_surface: Mapped[str | None] = mapped_column(String(64), nullable=True)
	mc3_synced_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
	origin_site_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
	created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow, nullable=False)


# ─────────────────────────────────────────────────────────────────────────────
# Sites — the tenants/businesses TeleOps manages telephony for.
# ─────────────────────────────────────────────────────────────────────────────


class TeleopsSite(Base, SyncMixin):
	__tablename__ = "teleops_sites"

	slug: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
	name: Mapped[str] = mapped_column(String(255), nullable=False)
	business_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
	frappe_site_url: Mapped[str | None] = mapped_column(String(255), nullable=True)
	has_orbweaver_pbx: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

	# Auth credentials for the bidirectional sync channel.
	# api_key_id: opaque identifier MC3 sends in the request (so the site can look up the matching secret)
	# api_key_hashed: SHA-256 of the secret the site expects from MC3 (constant-time compare)
	# hmac_secret: ENCRYPTED — the shared secret for Site→MC3 signed payloads
	sync_api_key_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
	sync_api_key_hashed: Mapped[str | None] = mapped_column(String(64), nullable=True)
	sync_hmac_secret: Mapped[str | None] = mapped_column(EncryptedText, nullable=True)

	notes: Mapped[str | None] = mapped_column(Text, nullable=True)


# ─────────────────────────────────────────────────────────────────────────────
# VOIP Accounts — Twilio master + subaccounts (eventually other carriers).
# ─────────────────────────────────────────────────────────────────────────────


class TeleopsVoipAccount(Base, SyncMixin):
	__tablename__ = "teleops_voip_accounts"

	provider: Mapped[str] = mapped_column(String(32), nullable=False, default="twilio")
	account_sid: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
	parent_account_sid: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
	friendly_name: Mapped[str] = mapped_column(String(255), nullable=False)

	# Sensitive credentials
	auth_token: Mapped[str | None] = mapped_column(EncryptedText, nullable=True)
	api_key_sid: Mapped[str | None] = mapped_column(String(64), nullable=True)
	api_key_secret: Mapped[str | None] = mapped_column(EncryptedText, nullable=True)
	default_twiml_app_sid: Mapped[str | None] = mapped_column(String(64), nullable=True)

	is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
	notes: Mapped[str | None] = mapped_column(Text, nullable=True)


# ─────────────────────────────────────────────────────────────────────────────
# Phone Numbers — E.164 registry, the primary collision-prevention layer.
# ─────────────────────────────────────────────────────────────────────────────


class TeleopsPhoneNumber(Base, SyncMixin):
	__tablename__ = "teleops_phone_numbers"

	e164: Mapped[str] = mapped_column(String(32), unique=True, nullable=False, index=True)
	voip_account_uid: Mapped[str] = mapped_column(
		String(36), ForeignKey("teleops_voip_accounts.uid"), nullable=False, index=True
	)
	site_uid: Mapped[str | None] = mapped_column(
		String(36), ForeignKey("teleops_sites.uid"), nullable=True, index=True
	)

	friendly_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
	country: Mapped[str | None] = mapped_column(String(2), nullable=True)
	# JSON: {voice: true, sms: true, mms: false, fax: false}
	capabilities_json: Mapped[str | None] = mapped_column(Text, nullable=True)
	status: Mapped[str] = mapped_column(String(16), nullable=False, default="Active")

	# Twilio-side wiring (the carrier-of-record values)
	voice_url: Mapped[str | None] = mapped_column(String(512), nullable=True)
	voice_method: Mapped[str] = mapped_column(String(8), default="POST", nullable=False)
	status_callback: Mapped[str | None] = mapped_column(String(512), nullable=True)
	status_callback_method: Mapped[str] = mapped_column(String(8), default="POST", nullable=False)
	sms_url: Mapped[str | None] = mapped_column(String(512), nullable=True)
	sms_method: Mapped[str] = mapped_column(String(8), default="POST", nullable=False)
	twiml_app_sid: Mapped[str | None] = mapped_column(String(64), nullable=True)

	monthly_cost_usd: Mapped[float | None] = mapped_column(Float, nullable=True)
	date_acquired: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
	notes: Mapped[str | None] = mapped_column(Text, nullable=True)


# ─────────────────────────────────────────────────────────────────────────────
# Extensions — cross-site reservation. Site-scoped uniqueness on ext_number.
# ─────────────────────────────────────────────────────────────────────────────


class TeleopsExtension(Base, SyncMixin):
	__tablename__ = "teleops_extensions"
	__table_args__ = (
		UniqueConstraint("site_uid", "ext_number", name="uq_teleops_ext_per_site"),
	)

	site_uid: Mapped[str] = mapped_column(
		String(36), ForeignKey("teleops_sites.uid"), nullable=False, index=True
	)
	ext_number: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
	display_name: Mapped[str] = mapped_column(String(255), nullable=False)
	frappe_user_email: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
	voicemail_uid: Mapped[str | None] = mapped_column(
		String(36), ForeignKey("teleops_voicemails.uid"), nullable=True
	)
	presence: Mapped[str] = mapped_column(String(16), default="Offline", nullable=False)
	notes: Mapped[str | None] = mapped_column(Text, nullable=True)


# ─────────────────────────────────────────────────────────────────────────────
# Voicemail mailboxes.
# ─────────────────────────────────────────────────────────────────────────────


class TeleopsVoicemail(Base, SyncMixin):
	__tablename__ = "teleops_voicemails"

	site_uid: Mapped[str] = mapped_column(
		String(36), ForeignKey("teleops_sites.uid"), nullable=False, index=True
	)
	name: Mapped[str] = mapped_column(String(255), nullable=False)
	greeting_url: Mapped[str | None] = mapped_column(String(512), nullable=True)
	greeting_text: Mapped[str | None] = mapped_column(Text, nullable=True)
	notify_email: Mapped[str | None] = mapped_column(String(255), nullable=True)
	transcription_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)


# ─────────────────────────────────────────────────────────────────────────────
# IVR Menus + options.
# ─────────────────────────────────────────────────────────────────────────────


class TeleopsIvrMenu(Base, SyncMixin):
	__tablename__ = "teleops_ivr_menus"

	site_uid: Mapped[str] = mapped_column(
		String(36), ForeignKey("teleops_sites.uid"), nullable=False, index=True
	)
	name: Mapped[str] = mapped_column(String(255), nullable=False)
	greeting_url: Mapped[str | None] = mapped_column(String(512), nullable=True)
	greeting_text: Mapped[str | None] = mapped_column(Text, nullable=True)
	timeout_sec: Mapped[int] = mapped_column(Integer, default=5, nullable=False)
	retries: Mapped[int] = mapped_column(Integer, default=3, nullable=False)
	on_invalid_target_type: Mapped[str | None] = mapped_column(String(32), nullable=True)
	on_invalid_target_uid: Mapped[str | None] = mapped_column(String(36), nullable=True)


class TeleopsIvrOption(Base, SyncMixin):
	__tablename__ = "teleops_ivr_options"
	__table_args__ = (
		UniqueConstraint("ivr_menu_uid", "digit", name="uq_teleops_ivropt_digit"),
	)

	ivr_menu_uid: Mapped[str] = mapped_column(
		String(36), ForeignKey("teleops_ivr_menus.uid"), nullable=False, index=True
	)
	digit: Mapped[str] = mapped_column(String(2), nullable=False)
	label: Mapped[str | None] = mapped_column(String(255), nullable=True)
	target_type: Mapped[str] = mapped_column(String(32), nullable=False)
	target_uid: Mapped[str] = mapped_column(String(36), nullable=False)


# ─────────────────────────────────────────────────────────────────────────────
# Ring Groups.
# ─────────────────────────────────────────────────────────────────────────────


class TeleopsRingGroup(Base, SyncMixin):
	__tablename__ = "teleops_ring_groups"

	site_uid: Mapped[str] = mapped_column(
		String(36), ForeignKey("teleops_sites.uid"), nullable=False, index=True
	)
	name: Mapped[str] = mapped_column(String(255), nullable=False)
	strategy: Mapped[str] = mapped_column(String(16), default="simultaneous", nullable=False)
	ring_seconds: Mapped[int] = mapped_column(Integer, default=25, nullable=False)
	# JSON array of extension uids (order matters for sequential strategy)
	members_json: Mapped[str | None] = mapped_column(Text, nullable=True)
	on_no_answer_target_type: Mapped[str | None] = mapped_column(String(32), nullable=True)
	on_no_answer_target_uid: Mapped[str | None] = mapped_column(String(36), nullable=True)


# ─────────────────────────────────────────────────────────────────────────────
# Time Rules.
# ─────────────────────────────────────────────────────────────────────────────


class TeleopsTimeRule(Base, SyncMixin):
	__tablename__ = "teleops_time_rules"

	site_uid: Mapped[str] = mapped_column(
		String(36), ForeignKey("teleops_sites.uid"), nullable=False, index=True
	)
	name: Mapped[str] = mapped_column(String(255), nullable=False)
	timezone: Mapped[str] = mapped_column(String(64), default="UTC", nullable=False)
	# JSON: weekday hours + holiday dates
	rule_json: Mapped[str | None] = mapped_column(Text, nullable=True)
	in_hours_target_type: Mapped[str | None] = mapped_column(String(32), nullable=True)
	in_hours_target_uid: Mapped[str | None] = mapped_column(String(36), nullable=True)
	out_of_hours_target_type: Mapped[str | None] = mapped_column(String(32), nullable=True)
	out_of_hours_target_uid: Mapped[str | None] = mapped_column(String(36), nullable=True)


# ─────────────────────────────────────────────────────────────────────────────
# Call Queues (TaskRouter-backed).
# ─────────────────────────────────────────────────────────────────────────────


class TeleopsCallQueue(Base, SyncMixin):
	__tablename__ = "teleops_call_queues"

	site_uid: Mapped[str] = mapped_column(
		String(36), ForeignKey("teleops_sites.uid"), nullable=False, index=True
	)
	name: Mapped[str] = mapped_column(String(255), nullable=False)
	twilio_workflow_sid: Mapped[str | None] = mapped_column(String(64), nullable=True)
	hold_music_url: Mapped[str | None] = mapped_column(String(512), nullable=True)
	max_wait_seconds: Mapped[int] = mapped_column(Integer, default=600, nullable=False)
	on_overflow_target_type: Mapped[str | None] = mapped_column(String(32), nullable=True)
	on_overflow_target_uid: Mapped[str | None] = mapped_column(String(36), nullable=True)


# ─────────────────────────────────────────────────────────────────────────────
# Routes — the Routing Designer canvas. Each row is one directed edge.
# Node positions stored per-(site_uid, source_uid) pair.
# ─────────────────────────────────────────────────────────────────────────────


class TeleopsRoute(Base, SyncMixin):
	__tablename__ = "teleops_routes"

	site_uid: Mapped[str] = mapped_column(
		String(36), ForeignKey("teleops_sites.uid"), nullable=False, index=True
	)
	source_type: Mapped[str] = mapped_column(String(32), nullable=False)
	source_uid: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
	target_type: Mapped[str] = mapped_column(String(32), nullable=False)
	target_uid: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
	label: Mapped[str | None] = mapped_column(String(128), nullable=True)
	# Canvas position of the SOURCE node (target's position is wherever it lives elsewhere)
	source_position_x: Mapped[float | None] = mapped_column(Float, nullable=True)
	source_position_y: Mapped[float | None] = mapped_column(Float, nullable=True)
