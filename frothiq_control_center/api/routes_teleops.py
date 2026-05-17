"""
TeleOps — multi-tenant telephony console.

Phase A.2: skeleton + DB tables.
Phase A.3: VOIP Accounts + Phone Numbers CRUD + Import-from-Twilio.

The trust layer (locks/sync/history — Phase C) and the visual Routing Designer
(Phase B) plug into these CRUD endpoints later — they don't replace them.
"""

from __future__ import annotations

import asyncio
import base64
import json
from datetime import datetime
from typing import Annotated

import httpx
from fastapi import APIRouter, Body, Depends, HTTPException, Path
from pydantic import BaseModel, Field
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError

from frothiq_control_center.auth import TokenPayload, require_super_admin
from frothiq_control_center.integrations.database import get_session_factory
from frothiq_control_center.models.teleops import (
	TeleopsCallQueue,
	TeleopsExtension,
	TeleopsIvrMenu,
	TeleopsIvrOption,
	TeleopsPhoneNumber,
	TeleopsRingGroup,
	TeleopsRoute,
	TeleopsSite,
	TeleopsTimeRule,
	TeleopsVoicemail,
	TeleopsVoipAccount,
)


router = APIRouter(prefix="/teleops", tags=["teleops"])
Auth = Annotated[TokenPayload, Depends(require_super_admin)]


# ─────────────────────────────────────────────────────────────────────────────
# Health
# ─────────────────────────────────────────────────────────────────────────────


@router.get("/health")
async def teleops_health(user: Auth) -> dict:
	"""Verify the router is wired up + the DB tables exist."""
	session_factory = get_session_factory()
	tables: dict[str, int] = {}
	async with session_factory() as session:
		for model in (
			TeleopsSite,
			TeleopsVoipAccount,
			TeleopsPhoneNumber,
			TeleopsExtension,
			TeleopsVoicemail,
			TeleopsIvrMenu,
			TeleopsIvrOption,
			TeleopsRingGroup,
			TeleopsTimeRule,
			TeleopsCallQueue,
			TeleopsRoute,
		):
			row = await session.execute(text(f"SELECT COUNT(*) FROM {model.__tablename__}"))
			tables[model.__tablename__] = int(row.scalar() or 0)
	return {
		"status": "ok",
		"as_of": datetime.utcnow().isoformat() + "Z",
		"viewer": user.email,
		"tables": tables,
	}


# ═════════════════════════════════════════════════════════════════════════════
# VOIP ACCOUNTS
# ═════════════════════════════════════════════════════════════════════════════


class VoipAccountIn(BaseModel):
	provider: str = "twilio"
	account_sid: str = Field(..., min_length=8, max_length=64)
	parent_account_sid: str | None = None
	friendly_name: str = Field(..., min_length=1, max_length=255)
	auth_token: str | None = None
	api_key_sid: str | None = None
	api_key_secret: str | None = None
	default_twiml_app_sid: str | None = None
	is_active: bool = True
	notes: str | None = None


class VoipAccountPatch(BaseModel):
	provider: str | None = None
	parent_account_sid: str | None = None
	friendly_name: str | None = None
	auth_token: str | None = None
	api_key_sid: str | None = None
	api_key_secret: str | None = None
	default_twiml_app_sid: str | None = None
	is_active: bool | None = None
	notes: str | None = None


def _voip_to_out(v: TeleopsVoipAccount) -> dict:
	"""Serialize a VOIP Account. Never returns the encrypted secrets — only
	booleans indicating whether they're set."""
	return {
		"uid": v.uid,
		"provider": v.provider,
		"account_sid": v.account_sid,
		"parent_account_sid": v.parent_account_sid,
		"friendly_name": v.friendly_name,
		"has_auth_token": bool(v.auth_token),
		"api_key_sid": v.api_key_sid,
		"has_api_key_secret": bool(v.api_key_secret),
		"default_twiml_app_sid": v.default_twiml_app_sid,
		"is_active": v.is_active,
		"notes": v.notes,
		"version": v.version,
		"last_modified_at": v.last_modified_at.isoformat() if v.last_modified_at else None,
		"last_modified_by": v.last_modified_by,
		"last_modified_surface": v.last_modified_surface,
		"created_at": v.created_at.isoformat() if v.created_at else None,
	}


@router.get("/voip-accounts")
async def list_voip_accounts(user: Auth) -> dict:
	factory = get_session_factory()
	async with factory() as session:
		rows = (
			await session.execute(
				select(TeleopsVoipAccount).order_by(TeleopsVoipAccount.friendly_name)
			)
		).scalars().all()
		return {"accounts": [_voip_to_out(r) for r in rows], "count": len(rows)}


@router.post("/voip-accounts", status_code=201)
async def create_voip_account(payload: VoipAccountIn, user: Auth) -> dict:
	factory = get_session_factory()
	async with factory() as session:
		acc = TeleopsVoipAccount(
			provider=payload.provider,
			account_sid=payload.account_sid,
			parent_account_sid=payload.parent_account_sid,
			friendly_name=payload.friendly_name,
			auth_token=payload.auth_token,
			api_key_sid=payload.api_key_sid,
			api_key_secret=payload.api_key_secret,
			default_twiml_app_sid=payload.default_twiml_app_sid,
			is_active=payload.is_active,
			notes=payload.notes,
			last_modified_by=user.email,
			last_modified_surface="mc3",
		)
		session.add(acc)
		try:
			await session.commit()
		except IntegrityError:
			raise HTTPException(status_code=409, detail=f"Account SID already exists: {payload.account_sid}")
		await session.refresh(acc)
		return _voip_to_out(acc)


@router.get("/voip-accounts/{uid}")
async def get_voip_account(uid: Annotated[str, Path()], user: Auth) -> dict:
	factory = get_session_factory()
	async with factory() as session:
		acc = await session.get(TeleopsVoipAccount, uid)
		if not acc:
			raise HTTPException(status_code=404, detail="VOIP Account not found")
		return _voip_to_out(acc)


@router.patch("/voip-accounts/{uid}")
async def update_voip_account(uid: Annotated[str, Path()], payload: VoipAccountPatch, user: Auth) -> dict:
	factory = get_session_factory()
	async with factory() as session:
		acc = await session.get(TeleopsVoipAccount, uid)
		if not acc:
			raise HTTPException(status_code=404, detail="VOIP Account not found")
		for field, value in payload.model_dump(exclude_unset=True).items():
			setattr(acc, field, value)
		acc.version = (acc.version or 0) + 1
		acc.last_modified_by = user.email
		acc.last_modified_surface = "mc3"
		await session.commit()
		await session.refresh(acc)
		return _voip_to_out(acc)


@router.delete("/voip-accounts/{uid}")
async def delete_voip_account(uid: Annotated[str, Path()], user: Auth) -> dict:
	factory = get_session_factory()
	async with factory() as session:
		acc = await session.get(TeleopsVoipAccount, uid)
		if not acc:
			raise HTTPException(status_code=404, detail="VOIP Account not found")
		# Block deletion if numbers are still attached
		count = (await session.execute(
			select(TeleopsPhoneNumber).where(TeleopsPhoneNumber.voip_account_uid == uid).limit(1)
		)).scalar_one_or_none()
		if count is not None:
			raise HTTPException(
				status_code=409,
				detail="Cannot delete VOIP Account while phone numbers are attached. Reassign or delete the numbers first.",
			)
		await session.delete(acc)
		await session.commit()
		return {"deleted": uid}


# ═════════════════════════════════════════════════════════════════════════════
# IMPORT FROM TWILIO
# ═════════════════════════════════════════════════════════════════════════════


async def _twilio_get(account_sid: str, auth_token: str, path: str) -> dict:
	"""Authenticated GET to Twilio REST API."""
	url = f"https://api.twilio.com/2010-04-01/Accounts/{account_sid}{path}"
	creds = base64.b64encode(f"{account_sid}:{auth_token}".encode()).decode("ascii")
	async with httpx.AsyncClient(timeout=20.0) as client:
		resp = await client.get(url, headers={"Authorization": f"Basic {creds}"})
		if resp.status_code == 401:
			raise HTTPException(status_code=400, detail="Twilio rejected the auth token")
		if resp.status_code >= 400:
			raise HTTPException(status_code=502, detail=f"Twilio API error {resp.status_code}: {resp.text[:200]}")
		return resp.json()


@router.post("/voip-accounts/{uid}/import-from-twilio")
async def import_from_twilio(uid: Annotated[str, Path()], user: Auth) -> dict:
	"""Pull all IncomingPhoneNumbers from Twilio into the registry.

	Existing E.164 numbers are skipped (idempotent). Returns counts so the UI
	can render a summary toast.
	"""
	factory = get_session_factory()
	async with factory() as session:
		acc = await session.get(TeleopsVoipAccount, uid)
		if not acc:
			raise HTTPException(status_code=404, detail="VOIP Account not found")
		if acc.provider != "twilio":
			raise HTTPException(status_code=400, detail=f"Import not supported for provider: {acc.provider}")
		if not acc.auth_token:
			raise HTTPException(status_code=400, detail="Auth token required on the VOIP Account to import")

		# Page through Twilio's list endpoint
		imported = 0
		skipped = 0
		next_page = "/IncomingPhoneNumbers.json?PageSize=100"
		while next_page:
			# Twilio returns next_page_uri as a relative path under /2010-04-01;
			# strip the API version prefix if present so _twilio_get can reattach it
			path = next_page
			if path.startswith("/2010-04-01"):
				path = path[len("/2010-04-01"):]
			# Strip the leading /Accounts/<sid> if Twilio echoed it
			acct_prefix = f"/Accounts/{acc.account_sid}"
			if path.startswith(acct_prefix):
				path = path[len(acct_prefix):]
			data = await _twilio_get(acc.account_sid, acc.auth_token, path)

			for pn in data.get("incoming_phone_numbers", []):
				e164 = pn.get("phone_number")
				if not e164:
					continue
				existing = (await session.execute(
					select(TeleopsPhoneNumber).where(TeleopsPhoneNumber.e164 == e164)
				)).scalar_one_or_none()
				if existing:
					skipped += 1
					continue
				caps = pn.get("capabilities") or {}
				date_created = pn.get("date_created")
				try:
					date_acquired = (
						datetime.strptime(date_created, "%a, %d %b %Y %H:%M:%S %z").replace(tzinfo=None)
						if date_created else None
					)
				except (ValueError, TypeError):
					date_acquired = None

				session.add(TeleopsPhoneNumber(
					e164=e164,
					voip_account_uid=acc.uid,
					friendly_name=pn.get("friendly_name"),
					country=pn.get("iso_country") or pn.get("address_requirements") if False else pn.get("iso_country"),
					capabilities_json=json.dumps({
						"voice": bool(caps.get("voice")),
						"sms": bool(caps.get("sms")),
						"mms": bool(caps.get("mms")),
						"fax": bool(caps.get("fax")),
					}),
					status="Active",
					voice_url=pn.get("voice_url") or None,
					voice_method=pn.get("voice_method") or "POST",
					status_callback=pn.get("status_callback") or None,
					status_callback_method=pn.get("status_callback_method") or "POST",
					sms_url=pn.get("sms_url") or None,
					sms_method=pn.get("sms_method") or "POST",
					twiml_app_sid=pn.get("voice_application_sid") or None,
					date_acquired=date_acquired,
					last_modified_by=user.email,
					last_modified_surface="mc3:import",
				))
				imported += 1

			next_page = data.get("next_page_uri")

		await session.commit()
		return {
			"imported": imported,
			"skipped_already_existing": skipped,
			"total": imported + skipped,
			"voip_account_uid": acc.uid,
		}


# ═════════════════════════════════════════════════════════════════════════════
# PHONE NUMBERS
# ═════════════════════════════════════════════════════════════════════════════


class PhoneNumberIn(BaseModel):
	e164: str = Field(..., min_length=8, max_length=32)
	voip_account_uid: str
	site_uid: str | None = None
	friendly_name: str | None = None
	country: str | None = Field(None, max_length=2)
	capabilities_json: str | None = None
	status: str = "Active"
	voice_url: str | None = None
	voice_method: str = "POST"
	status_callback: str | None = None
	status_callback_method: str = "POST"
	sms_url: str | None = None
	sms_method: str = "POST"
	twiml_app_sid: str | None = None
	monthly_cost_usd: float | None = None
	notes: str | None = None


class PhoneNumberPatch(BaseModel):
	voip_account_uid: str | None = None
	site_uid: str | None = None
	friendly_name: str | None = None
	country: str | None = Field(None, max_length=2)
	capabilities_json: str | None = None
	status: str | None = None
	voice_url: str | None = None
	voice_method: str | None = None
	status_callback: str | None = None
	status_callback_method: str | None = None
	sms_url: str | None = None
	sms_method: str | None = None
	twiml_app_sid: str | None = None
	monthly_cost_usd: float | None = None
	notes: str | None = None


def _pn_to_out(p: TeleopsPhoneNumber) -> dict:
	return {
		"uid": p.uid,
		"e164": p.e164,
		"voip_account_uid": p.voip_account_uid,
		"site_uid": p.site_uid,
		"friendly_name": p.friendly_name,
		"country": p.country,
		"capabilities_json": p.capabilities_json,
		"status": p.status,
		"voice_url": p.voice_url,
		"voice_method": p.voice_method,
		"status_callback": p.status_callback,
		"status_callback_method": p.status_callback_method,
		"sms_url": p.sms_url,
		"sms_method": p.sms_method,
		"twiml_app_sid": p.twiml_app_sid,
		"monthly_cost_usd": p.monthly_cost_usd,
		"date_acquired": p.date_acquired.isoformat() if p.date_acquired else None,
		"notes": p.notes,
		"version": p.version,
		"last_modified_at": p.last_modified_at.isoformat() if p.last_modified_at else None,
		"last_modified_by": p.last_modified_by,
		"last_modified_surface": p.last_modified_surface,
		"created_at": p.created_at.isoformat() if p.created_at else None,
	}


@router.get("/phone-numbers")
async def list_phone_numbers(user: Auth, voip_account_uid: str | None = None, site_uid: str | None = None) -> dict:
	factory = get_session_factory()
	async with factory() as session:
		stmt = select(TeleopsPhoneNumber).order_by(TeleopsPhoneNumber.e164)
		if voip_account_uid:
			stmt = stmt.where(TeleopsPhoneNumber.voip_account_uid == voip_account_uid)
		if site_uid:
			stmt = stmt.where(TeleopsPhoneNumber.site_uid == site_uid)
		rows = (await session.execute(stmt)).scalars().all()
		return {"numbers": [_pn_to_out(r) for r in rows], "count": len(rows)}


@router.post("/phone-numbers", status_code=201)
async def create_phone_number(payload: PhoneNumberIn, user: Auth) -> dict:
	factory = get_session_factory()
	async with factory() as session:
		# Validate FK
		acc = await session.get(TeleopsVoipAccount, payload.voip_account_uid)
		if not acc:
			raise HTTPException(status_code=400, detail="voip_account_uid does not exist")
		if payload.site_uid:
			site = await session.get(TeleopsSite, payload.site_uid)
			if not site:
				raise HTTPException(status_code=400, detail="site_uid does not exist")

		pn = TeleopsPhoneNumber(
			**payload.model_dump(),
			last_modified_by=user.email,
			last_modified_surface="mc3",
		)
		session.add(pn)
		try:
			await session.commit()
		except IntegrityError:
			raise HTTPException(status_code=409, detail=f"Phone number already exists: {payload.e164}")
		await session.refresh(pn)
		return _pn_to_out(pn)


@router.get("/phone-numbers/{uid}")
async def get_phone_number(uid: Annotated[str, Path()], user: Auth) -> dict:
	factory = get_session_factory()
	async with factory() as session:
		pn = await session.get(TeleopsPhoneNumber, uid)
		if not pn:
			raise HTTPException(status_code=404, detail="Phone Number not found")
		return _pn_to_out(pn)


@router.patch("/phone-numbers/{uid}")
async def update_phone_number(uid: Annotated[str, Path()], payload: PhoneNumberPatch, user: Auth) -> dict:
	factory = get_session_factory()
	async with factory() as session:
		pn = await session.get(TeleopsPhoneNumber, uid)
		if not pn:
			raise HTTPException(status_code=404, detail="Phone Number not found")
		updates = payload.model_dump(exclude_unset=True)
		# Validate FKs if changing
		if "voip_account_uid" in updates and updates["voip_account_uid"]:
			if not await session.get(TeleopsVoipAccount, updates["voip_account_uid"]):
				raise HTTPException(status_code=400, detail="voip_account_uid does not exist")
		if "site_uid" in updates and updates["site_uid"]:
			if not await session.get(TeleopsSite, updates["site_uid"]):
				raise HTTPException(status_code=400, detail="site_uid does not exist")
		for field, value in updates.items():
			setattr(pn, field, value)
		pn.version = (pn.version or 0) + 1
		pn.last_modified_by = user.email
		pn.last_modified_surface = "mc3"
		await session.commit()
		await session.refresh(pn)
		return _pn_to_out(pn)


@router.delete("/phone-numbers/{uid}")
async def delete_phone_number(uid: Annotated[str, Path()], user: Auth) -> dict:
	factory = get_session_factory()
	async with factory() as session:
		pn = await session.get(TeleopsPhoneNumber, uid)
		if not pn:
			raise HTTPException(status_code=404, detail="Phone Number not found")
		await session.delete(pn)
		await session.commit()
		return {"deleted": uid}


# ═════════════════════════════════════════════════════════════════════════════
# SITES (minimal CRUD — used as FK target for phone numbers + extensions)
# ═════════════════════════════════════════════════════════════════════════════


class SiteIn(BaseModel):
	slug: str = Field(..., min_length=1, max_length=64)
	name: str = Field(..., min_length=1, max_length=255)
	business_name: str | None = None
	frappe_site_url: str | None = None
	has_orbweaver_pbx: bool = False
	notes: str | None = None


class SitePatch(BaseModel):
	name: str | None = None
	business_name: str | None = None
	frappe_site_url: str | None = None
	has_orbweaver_pbx: bool | None = None
	notes: str | None = None


def _site_to_out(s: TeleopsSite) -> dict:
	return {
		"uid": s.uid,
		"slug": s.slug,
		"name": s.name,
		"business_name": s.business_name,
		"frappe_site_url": s.frappe_site_url,
		"has_orbweaver_pbx": s.has_orbweaver_pbx,
		"sync_api_key_id": s.sync_api_key_id,
		"has_sync_secret": bool(s.sync_hmac_secret),
		"notes": s.notes,
		"version": s.version,
		"last_modified_at": s.last_modified_at.isoformat() if s.last_modified_at else None,
		"last_modified_by": s.last_modified_by,
		"created_at": s.created_at.isoformat() if s.created_at else None,
	}


@router.get("/sites")
async def list_sites(user: Auth) -> dict:
	factory = get_session_factory()
	async with factory() as session:
		rows = (await session.execute(select(TeleopsSite).order_by(TeleopsSite.name))).scalars().all()
		return {"sites": [_site_to_out(r) for r in rows], "count": len(rows)}


@router.post("/sites", status_code=201)
async def create_site(payload: SiteIn, user: Auth) -> dict:
	factory = get_session_factory()
	async with factory() as session:
		s = TeleopsSite(
			**payload.model_dump(),
			last_modified_by=user.email,
			last_modified_surface="mc3",
		)
		session.add(s)
		try:
			await session.commit()
		except IntegrityError:
			raise HTTPException(status_code=409, detail=f"Site slug already exists: {payload.slug}")
		await session.refresh(s)
		return _site_to_out(s)


@router.get("/sites/{uid}")
async def get_site(uid: Annotated[str, Path()], user: Auth) -> dict:
	factory = get_session_factory()
	async with factory() as session:
		s = await session.get(TeleopsSite, uid)
		if not s:
			raise HTTPException(status_code=404, detail="Site not found")
		return _site_to_out(s)


@router.patch("/sites/{uid}")
async def update_site(uid: Annotated[str, Path()], payload: SitePatch, user: Auth) -> dict:
	factory = get_session_factory()
	async with factory() as session:
		s = await session.get(TeleopsSite, uid)
		if not s:
			raise HTTPException(status_code=404, detail="Site not found")
		for field, value in payload.model_dump(exclude_unset=True).items():
			setattr(s, field, value)
		s.version = (s.version or 0) + 1
		s.last_modified_by = user.email
		s.last_modified_surface = "mc3"
		await session.commit()
		await session.refresh(s)
		return _site_to_out(s)


@router.delete("/sites/{uid}")
async def delete_site(uid: Annotated[str, Path()], user: Auth) -> dict:
	factory = get_session_factory()
	async with factory() as session:
		s = await session.get(TeleopsSite, uid)
		if not s:
			raise HTTPException(status_code=404, detail="Site not found")
		# Refuse if any phone numbers or extensions still reference this site
		pn_ref = (await session.execute(
			select(TeleopsPhoneNumber).where(TeleopsPhoneNumber.site_uid == uid).limit(1)
		)).scalar_one_or_none()
		if pn_ref is not None:
			raise HTTPException(status_code=409, detail="Site has phone numbers attached; reassign or remove them first")
		ext_ref = (await session.execute(
			select(TeleopsExtension).where(TeleopsExtension.site_uid == uid).limit(1)
		)).scalar_one_or_none()
		if ext_ref is not None:
			raise HTTPException(status_code=409, detail="Site has extensions attached; remove them first")
		await session.delete(s)
		await session.commit()
		return {"deleted": uid}


# ═════════════════════════════════════════════════════════════════════════════
# PHASE A.4 — Extensions, Voicemails, IVR Menus + Options,
#             Ring Groups, Time Rules, Call Queues
# ═════════════════════════════════════════════════════════════════════════════


def _bump_version(obj, user_email: str) -> None:
	"""Common version-bump applied on every PATCH to keep sync metadata correct."""
	obj.version = (obj.version or 0) + 1
	obj.last_modified_by = user_email
	obj.last_modified_surface = "mc3"


async def _require_site(session, site_uid: str) -> None:
	if not await session.get(TeleopsSite, site_uid):
		raise HTTPException(status_code=400, detail="site_uid does not exist")


# ═════════════════════════════════════════════════════════════════════════════
# VOICEMAILS (defined BEFORE Extensions because Extension.voicemail_uid is FK to it)
# ═════════════════════════════════════════════════════════════════════════════


class VoicemailIn(BaseModel):
	site_uid: str
	name: str = Field(..., min_length=1, max_length=255)
	greeting_url: str | None = None
	greeting_text: str | None = None
	notify_email: str | None = None
	transcription_enabled: bool = True


class VoicemailPatch(BaseModel):
	site_uid: str | None = None
	name: str | None = None
	greeting_url: str | None = None
	greeting_text: str | None = None
	notify_email: str | None = None
	transcription_enabled: bool | None = None


def _vm_to_out(v: TeleopsVoicemail) -> dict:
	return {
		"uid": v.uid,
		"site_uid": v.site_uid,
		"name": v.name,
		"greeting_url": v.greeting_url,
		"greeting_text": v.greeting_text,
		"notify_email": v.notify_email,
		"transcription_enabled": v.transcription_enabled,
		"version": v.version,
		"last_modified_at": v.last_modified_at.isoformat() if v.last_modified_at else None,
		"last_modified_by": v.last_modified_by,
		"created_at": v.created_at.isoformat() if v.created_at else None,
	}


@router.get("/voicemails")
async def list_voicemails(user: Auth, site_uid: str | None = None) -> dict:
	async with get_session_factory()() as session:
		stmt = select(TeleopsVoicemail).order_by(TeleopsVoicemail.name)
		if site_uid:
			stmt = stmt.where(TeleopsVoicemail.site_uid == site_uid)
		rows = (await session.execute(stmt)).scalars().all()
		return {"voicemails": [_vm_to_out(r) for r in rows], "count": len(rows)}


@router.post("/voicemails", status_code=201)
async def create_voicemail(payload: VoicemailIn, user: Auth) -> dict:
	async with get_session_factory()() as session:
		await _require_site(session, payload.site_uid)
		vm = TeleopsVoicemail(
			**payload.model_dump(),
			last_modified_by=user.email,
			last_modified_surface="mc3",
		)
		session.add(vm)
		await session.commit()
		await session.refresh(vm)
		return _vm_to_out(vm)


@router.get("/voicemails/{uid}")
async def get_voicemail(uid: Annotated[str, Path()], user: Auth) -> dict:
	async with get_session_factory()() as session:
		vm = await session.get(TeleopsVoicemail, uid)
		if not vm:
			raise HTTPException(status_code=404, detail="Voicemail not found")
		return _vm_to_out(vm)


@router.patch("/voicemails/{uid}")
async def update_voicemail(uid: Annotated[str, Path()], payload: VoicemailPatch, user: Auth) -> dict:
	async with get_session_factory()() as session:
		vm = await session.get(TeleopsVoicemail, uid)
		if not vm:
			raise HTTPException(status_code=404, detail="Voicemail not found")
		updates = payload.model_dump(exclude_unset=True)
		if "site_uid" in updates and updates["site_uid"]:
			await _require_site(session, updates["site_uid"])
		for k, v in updates.items():
			setattr(vm, k, v)
		_bump_version(vm, user.email)
		await session.commit()
		await session.refresh(vm)
		return _vm_to_out(vm)


@router.delete("/voicemails/{uid}")
async def delete_voicemail(uid: Annotated[str, Path()], user: Auth) -> dict:
	async with get_session_factory()() as session:
		vm = await session.get(TeleopsVoicemail, uid)
		if not vm:
			raise HTTPException(status_code=404, detail="Voicemail not found")
		# Block delete if any Extension references this voicemail
		ref = (await session.execute(
			select(TeleopsExtension).where(TeleopsExtension.voicemail_uid == uid).limit(1)
		)).scalar_one_or_none()
		if ref:
			raise HTTPException(status_code=409, detail="Voicemail attached to extension(s); reassign first")
		await session.delete(vm)
		await session.commit()
		return {"deleted": uid}


# ═════════════════════════════════════════════════════════════════════════════
# EXTENSIONS
# ═════════════════════════════════════════════════════════════════════════════


class ExtensionIn(BaseModel):
	site_uid: str
	ext_number: str = Field(..., min_length=1, max_length=16)
	display_name: str = Field(..., min_length=1, max_length=255)
	frappe_user_email: str | None = None
	voicemail_uid: str | None = None
	presence: str = "Offline"
	notes: str | None = None


class ExtensionPatch(BaseModel):
	display_name: str | None = None
	frappe_user_email: str | None = None
	voicemail_uid: str | None = None
	presence: str | None = None
	notes: str | None = None


def _ext_to_out(e: TeleopsExtension) -> dict:
	return {
		"uid": e.uid,
		"site_uid": e.site_uid,
		"ext_number": e.ext_number,
		"display_name": e.display_name,
		"frappe_user_email": e.frappe_user_email,
		"voicemail_uid": e.voicemail_uid,
		"presence": e.presence,
		"notes": e.notes,
		"version": e.version,
		"last_modified_at": e.last_modified_at.isoformat() if e.last_modified_at else None,
		"last_modified_by": e.last_modified_by,
		"created_at": e.created_at.isoformat() if e.created_at else None,
	}


@router.get("/extensions")
async def list_extensions(user: Auth, site_uid: str | None = None) -> dict:
	async with get_session_factory()() as session:
		stmt = select(TeleopsExtension).order_by(TeleopsExtension.site_uid, TeleopsExtension.ext_number)
		if site_uid:
			stmt = stmt.where(TeleopsExtension.site_uid == site_uid)
		rows = (await session.execute(stmt)).scalars().all()
		return {"extensions": [_ext_to_out(r) for r in rows], "count": len(rows)}


@router.post("/extensions", status_code=201)
async def create_extension(payload: ExtensionIn, user: Auth) -> dict:
	async with get_session_factory()() as session:
		await _require_site(session, payload.site_uid)
		if payload.voicemail_uid and not await session.get(TeleopsVoicemail, payload.voicemail_uid):
			raise HTTPException(status_code=400, detail="voicemail_uid does not exist")
		ext = TeleopsExtension(
			**payload.model_dump(),
			last_modified_by=user.email,
			last_modified_surface="mc3",
		)
		session.add(ext)
		try:
			await session.commit()
		except IntegrityError:
			raise HTTPException(status_code=409, detail=f"Extension {payload.ext_number} already exists on this site")
		await session.refresh(ext)
		return _ext_to_out(ext)


@router.get("/extensions/{uid}")
async def get_extension(uid: Annotated[str, Path()], user: Auth) -> dict:
	async with get_session_factory()() as session:
		ext = await session.get(TeleopsExtension, uid)
		if not ext:
			raise HTTPException(status_code=404, detail="Extension not found")
		return _ext_to_out(ext)


@router.patch("/extensions/{uid}")
async def update_extension(uid: Annotated[str, Path()], payload: ExtensionPatch, user: Auth) -> dict:
	async with get_session_factory()() as session:
		ext = await session.get(TeleopsExtension, uid)
		if not ext:
			raise HTTPException(status_code=404, detail="Extension not found")
		updates = payload.model_dump(exclude_unset=True)
		if "voicemail_uid" in updates and updates["voicemail_uid"]:
			if not await session.get(TeleopsVoicemail, updates["voicemail_uid"]):
				raise HTTPException(status_code=400, detail="voicemail_uid does not exist")
		for k, v in updates.items():
			setattr(ext, k, v)
		_bump_version(ext, user.email)
		await session.commit()
		await session.refresh(ext)
		return _ext_to_out(ext)


@router.delete("/extensions/{uid}")
async def delete_extension(uid: Annotated[str, Path()], user: Auth) -> dict:
	async with get_session_factory()() as session:
		ext = await session.get(TeleopsExtension, uid)
		if not ext:
			raise HTTPException(status_code=404, detail="Extension not found")
		await session.delete(ext)
		await session.commit()
		return {"deleted": uid}


# ═════════════════════════════════════════════════════════════════════════════
# IVR MENUS
# ═════════════════════════════════════════════════════════════════════════════


class IvrMenuIn(BaseModel):
	site_uid: str
	name: str = Field(..., min_length=1, max_length=255)
	greeting_url: str | None = None
	greeting_text: str | None = None
	timeout_sec: int = 5
	retries: int = 3
	on_invalid_target_type: str | None = None
	on_invalid_target_uid: str | None = None


class IvrMenuPatch(BaseModel):
	name: str | None = None
	greeting_url: str | None = None
	greeting_text: str | None = None
	timeout_sec: int | None = None
	retries: int | None = None
	on_invalid_target_type: str | None = None
	on_invalid_target_uid: str | None = None


def _ivr_to_out(m: TeleopsIvrMenu) -> dict:
	return {
		"uid": m.uid,
		"site_uid": m.site_uid,
		"name": m.name,
		"greeting_url": m.greeting_url,
		"greeting_text": m.greeting_text,
		"timeout_sec": m.timeout_sec,
		"retries": m.retries,
		"on_invalid_target_type": m.on_invalid_target_type,
		"on_invalid_target_uid": m.on_invalid_target_uid,
		"version": m.version,
		"last_modified_at": m.last_modified_at.isoformat() if m.last_modified_at else None,
		"last_modified_by": m.last_modified_by,
		"created_at": m.created_at.isoformat() if m.created_at else None,
	}


@router.get("/ivr-menus")
async def list_ivr_menus(user: Auth, site_uid: str | None = None) -> dict:
	async with get_session_factory()() as session:
		stmt = select(TeleopsIvrMenu).order_by(TeleopsIvrMenu.name)
		if site_uid:
			stmt = stmt.where(TeleopsIvrMenu.site_uid == site_uid)
		rows = (await session.execute(stmt)).scalars().all()
		return {"ivr_menus": [_ivr_to_out(r) for r in rows], "count": len(rows)}


@router.post("/ivr-menus", status_code=201)
async def create_ivr_menu(payload: IvrMenuIn, user: Auth) -> dict:
	async with get_session_factory()() as session:
		await _require_site(session, payload.site_uid)
		m = TeleopsIvrMenu(**payload.model_dump(), last_modified_by=user.email, last_modified_surface="mc3")
		session.add(m)
		await session.commit()
		await session.refresh(m)
		return _ivr_to_out(m)


@router.get("/ivr-menus/{uid}")
async def get_ivr_menu(uid: Annotated[str, Path()], user: Auth) -> dict:
	async with get_session_factory()() as session:
		m = await session.get(TeleopsIvrMenu, uid)
		if not m:
			raise HTTPException(status_code=404, detail="IVR Menu not found")
		return _ivr_to_out(m)


@router.patch("/ivr-menus/{uid}")
async def update_ivr_menu(uid: Annotated[str, Path()], payload: IvrMenuPatch, user: Auth) -> dict:
	async with get_session_factory()() as session:
		m = await session.get(TeleopsIvrMenu, uid)
		if not m:
			raise HTTPException(status_code=404, detail="IVR Menu not found")
		for k, v in payload.model_dump(exclude_unset=True).items():
			setattr(m, k, v)
		_bump_version(m, user.email)
		await session.commit()
		await session.refresh(m)
		return _ivr_to_out(m)


@router.delete("/ivr-menus/{uid}")
async def delete_ivr_menu(uid: Annotated[str, Path()], user: Auth) -> dict:
	async with get_session_factory()() as session:
		m = await session.get(TeleopsIvrMenu, uid)
		if not m:
			raise HTTPException(status_code=404, detail="IVR Menu not found")
		# Cascade: delete options first
		opts = (await session.execute(select(TeleopsIvrOption).where(TeleopsIvrOption.ivr_menu_uid == uid))).scalars().all()
		for o in opts:
			await session.delete(o)
		await session.delete(m)
		await session.commit()
		return {"deleted": uid, "cascaded_options": len(opts)}


# ═════════════════════════════════════════════════════════════════════════════
# IVR OPTIONS
# ═════════════════════════════════════════════════════════════════════════════


class IvrOptionIn(BaseModel):
	ivr_menu_uid: str
	digit: str = Field(..., min_length=1, max_length=2)
	label: str | None = None
	target_type: str
	target_uid: str


class IvrOptionPatch(BaseModel):
	digit: str | None = None
	label: str | None = None
	target_type: str | None = None
	target_uid: str | None = None


def _opt_to_out(o: TeleopsIvrOption) -> dict:
	return {
		"uid": o.uid,
		"ivr_menu_uid": o.ivr_menu_uid,
		"digit": o.digit,
		"label": o.label,
		"target_type": o.target_type,
		"target_uid": o.target_uid,
		"version": o.version,
		"last_modified_at": o.last_modified_at.isoformat() if o.last_modified_at else None,
		"last_modified_by": o.last_modified_by,
		"created_at": o.created_at.isoformat() if o.created_at else None,
	}


@router.get("/ivr-options")
async def list_ivr_options(user: Auth, ivr_menu_uid: str | None = None) -> dict:
	async with get_session_factory()() as session:
		stmt = select(TeleopsIvrOption).order_by(TeleopsIvrOption.digit)
		if ivr_menu_uid:
			stmt = stmt.where(TeleopsIvrOption.ivr_menu_uid == ivr_menu_uid)
		rows = (await session.execute(stmt)).scalars().all()
		return {"options": [_opt_to_out(r) for r in rows], "count": len(rows)}


@router.post("/ivr-options", status_code=201)
async def create_ivr_option(payload: IvrOptionIn, user: Auth) -> dict:
	async with get_session_factory()() as session:
		if not await session.get(TeleopsIvrMenu, payload.ivr_menu_uid):
			raise HTTPException(status_code=400, detail="ivr_menu_uid does not exist")
		o = TeleopsIvrOption(**payload.model_dump(), last_modified_by=user.email, last_modified_surface="mc3")
		session.add(o)
		try:
			await session.commit()
		except IntegrityError:
			raise HTTPException(status_code=409, detail=f"Digit {payload.digit} already mapped on this IVR menu")
		await session.refresh(o)
		return _opt_to_out(o)


@router.get("/ivr-options/{uid}")
async def get_ivr_option(uid: Annotated[str, Path()], user: Auth) -> dict:
	async with get_session_factory()() as session:
		o = await session.get(TeleopsIvrOption, uid)
		if not o:
			raise HTTPException(status_code=404, detail="IVR Option not found")
		return _opt_to_out(o)


@router.patch("/ivr-options/{uid}")
async def update_ivr_option(uid: Annotated[str, Path()], payload: IvrOptionPatch, user: Auth) -> dict:
	async with get_session_factory()() as session:
		o = await session.get(TeleopsIvrOption, uid)
		if not o:
			raise HTTPException(status_code=404, detail="IVR Option not found")
		for k, v in payload.model_dump(exclude_unset=True).items():
			setattr(o, k, v)
		_bump_version(o, user.email)
		await session.commit()
		await session.refresh(o)
		return _opt_to_out(o)


@router.delete("/ivr-options/{uid}")
async def delete_ivr_option(uid: Annotated[str, Path()], user: Auth) -> dict:
	async with get_session_factory()() as session:
		o = await session.get(TeleopsIvrOption, uid)
		if not o:
			raise HTTPException(status_code=404, detail="IVR Option not found")
		await session.delete(o)
		await session.commit()
		return {"deleted": uid}


# ═════════════════════════════════════════════════════════════════════════════
# RING GROUPS
# ═════════════════════════════════════════════════════════════════════════════


class RingGroupIn(BaseModel):
	site_uid: str
	name: str = Field(..., min_length=1, max_length=255)
	strategy: str = "simultaneous"
	ring_seconds: int = 25
	members_json: str | None = None
	on_no_answer_target_type: str | None = None
	on_no_answer_target_uid: str | None = None


class RingGroupPatch(BaseModel):
	name: str | None = None
	strategy: str | None = None
	ring_seconds: int | None = None
	members_json: str | None = None
	on_no_answer_target_type: str | None = None
	on_no_answer_target_uid: str | None = None


def _rg_to_out(rg: TeleopsRingGroup) -> dict:
	return {
		"uid": rg.uid,
		"site_uid": rg.site_uid,
		"name": rg.name,
		"strategy": rg.strategy,
		"ring_seconds": rg.ring_seconds,
		"members_json": rg.members_json,
		"on_no_answer_target_type": rg.on_no_answer_target_type,
		"on_no_answer_target_uid": rg.on_no_answer_target_uid,
		"version": rg.version,
		"last_modified_at": rg.last_modified_at.isoformat() if rg.last_modified_at else None,
		"last_modified_by": rg.last_modified_by,
		"created_at": rg.created_at.isoformat() if rg.created_at else None,
	}


@router.get("/ring-groups")
async def list_ring_groups(user: Auth, site_uid: str | None = None) -> dict:
	async with get_session_factory()() as session:
		stmt = select(TeleopsRingGroup).order_by(TeleopsRingGroup.name)
		if site_uid:
			stmt = stmt.where(TeleopsRingGroup.site_uid == site_uid)
		rows = (await session.execute(stmt)).scalars().all()
		return {"ring_groups": [_rg_to_out(r) for r in rows], "count": len(rows)}


@router.post("/ring-groups", status_code=201)
async def create_ring_group(payload: RingGroupIn, user: Auth) -> dict:
	async with get_session_factory()() as session:
		await _require_site(session, payload.site_uid)
		rg = TeleopsRingGroup(**payload.model_dump(), last_modified_by=user.email, last_modified_surface="mc3")
		session.add(rg)
		await session.commit()
		await session.refresh(rg)
		return _rg_to_out(rg)


@router.get("/ring-groups/{uid}")
async def get_ring_group(uid: Annotated[str, Path()], user: Auth) -> dict:
	async with get_session_factory()() as session:
		rg = await session.get(TeleopsRingGroup, uid)
		if not rg:
			raise HTTPException(status_code=404, detail="Ring Group not found")
		return _rg_to_out(rg)


@router.patch("/ring-groups/{uid}")
async def update_ring_group(uid: Annotated[str, Path()], payload: RingGroupPatch, user: Auth) -> dict:
	async with get_session_factory()() as session:
		rg = await session.get(TeleopsRingGroup, uid)
		if not rg:
			raise HTTPException(status_code=404, detail="Ring Group not found")
		for k, v in payload.model_dump(exclude_unset=True).items():
			setattr(rg, k, v)
		_bump_version(rg, user.email)
		await session.commit()
		await session.refresh(rg)
		return _rg_to_out(rg)


@router.delete("/ring-groups/{uid}")
async def delete_ring_group(uid: Annotated[str, Path()], user: Auth) -> dict:
	async with get_session_factory()() as session:
		rg = await session.get(TeleopsRingGroup, uid)
		if not rg:
			raise HTTPException(status_code=404, detail="Ring Group not found")
		await session.delete(rg)
		await session.commit()
		return {"deleted": uid}


# ═════════════════════════════════════════════════════════════════════════════
# TIME RULES
# ═════════════════════════════════════════════════════════════════════════════


class TimeRuleIn(BaseModel):
	site_uid: str
	name: str = Field(..., min_length=1, max_length=255)
	timezone: str = "UTC"
	rule_json: str | None = None
	in_hours_target_type: str | None = None
	in_hours_target_uid: str | None = None
	out_of_hours_target_type: str | None = None
	out_of_hours_target_uid: str | None = None


class TimeRulePatch(BaseModel):
	name: str | None = None
	timezone: str | None = None
	rule_json: str | None = None
	in_hours_target_type: str | None = None
	in_hours_target_uid: str | None = None
	out_of_hours_target_type: str | None = None
	out_of_hours_target_uid: str | None = None


def _tr_to_out(t: TeleopsTimeRule) -> dict:
	return {
		"uid": t.uid,
		"site_uid": t.site_uid,
		"name": t.name,
		"timezone": t.timezone,
		"rule_json": t.rule_json,
		"in_hours_target_type": t.in_hours_target_type,
		"in_hours_target_uid": t.in_hours_target_uid,
		"out_of_hours_target_type": t.out_of_hours_target_type,
		"out_of_hours_target_uid": t.out_of_hours_target_uid,
		"version": t.version,
		"last_modified_at": t.last_modified_at.isoformat() if t.last_modified_at else None,
		"last_modified_by": t.last_modified_by,
		"created_at": t.created_at.isoformat() if t.created_at else None,
	}


@router.get("/time-rules")
async def list_time_rules(user: Auth, site_uid: str | None = None) -> dict:
	async with get_session_factory()() as session:
		stmt = select(TeleopsTimeRule).order_by(TeleopsTimeRule.name)
		if site_uid:
			stmt = stmt.where(TeleopsTimeRule.site_uid == site_uid)
		rows = (await session.execute(stmt)).scalars().all()
		return {"time_rules": [_tr_to_out(r) for r in rows], "count": len(rows)}


@router.post("/time-rules", status_code=201)
async def create_time_rule(payload: TimeRuleIn, user: Auth) -> dict:
	async with get_session_factory()() as session:
		await _require_site(session, payload.site_uid)
		t = TeleopsTimeRule(**payload.model_dump(), last_modified_by=user.email, last_modified_surface="mc3")
		session.add(t)
		await session.commit()
		await session.refresh(t)
		return _tr_to_out(t)


@router.get("/time-rules/{uid}")
async def get_time_rule(uid: Annotated[str, Path()], user: Auth) -> dict:
	async with get_session_factory()() as session:
		t = await session.get(TeleopsTimeRule, uid)
		if not t:
			raise HTTPException(status_code=404, detail="Time Rule not found")
		return _tr_to_out(t)


@router.patch("/time-rules/{uid}")
async def update_time_rule(uid: Annotated[str, Path()], payload: TimeRulePatch, user: Auth) -> dict:
	async with get_session_factory()() as session:
		t = await session.get(TeleopsTimeRule, uid)
		if not t:
			raise HTTPException(status_code=404, detail="Time Rule not found")
		for k, v in payload.model_dump(exclude_unset=True).items():
			setattr(t, k, v)
		_bump_version(t, user.email)
		await session.commit()
		await session.refresh(t)
		return _tr_to_out(t)


@router.delete("/time-rules/{uid}")
async def delete_time_rule(uid: Annotated[str, Path()], user: Auth) -> dict:
	async with get_session_factory()() as session:
		t = await session.get(TeleopsTimeRule, uid)
		if not t:
			raise HTTPException(status_code=404, detail="Time Rule not found")
		await session.delete(t)
		await session.commit()
		return {"deleted": uid}


# ═════════════════════════════════════════════════════════════════════════════
# CALL QUEUES
# ═════════════════════════════════════════════════════════════════════════════


class CallQueueIn(BaseModel):
	site_uid: str
	name: str = Field(..., min_length=1, max_length=255)
	twilio_workflow_sid: str | None = None
	hold_music_url: str | None = None
	max_wait_seconds: int = 600
	on_overflow_target_type: str | None = None
	on_overflow_target_uid: str | None = None


class CallQueuePatch(BaseModel):
	name: str | None = None
	twilio_workflow_sid: str | None = None
	hold_music_url: str | None = None
	max_wait_seconds: int | None = None
	on_overflow_target_type: str | None = None
	on_overflow_target_uid: str | None = None


def _cq_to_out(q: TeleopsCallQueue) -> dict:
	return {
		"uid": q.uid,
		"site_uid": q.site_uid,
		"name": q.name,
		"twilio_workflow_sid": q.twilio_workflow_sid,
		"hold_music_url": q.hold_music_url,
		"max_wait_seconds": q.max_wait_seconds,
		"on_overflow_target_type": q.on_overflow_target_type,
		"on_overflow_target_uid": q.on_overflow_target_uid,
		"version": q.version,
		"last_modified_at": q.last_modified_at.isoformat() if q.last_modified_at else None,
		"last_modified_by": q.last_modified_by,
		"created_at": q.created_at.isoformat() if q.created_at else None,
	}


@router.get("/call-queues")
async def list_call_queues(user: Auth, site_uid: str | None = None) -> dict:
	async with get_session_factory()() as session:
		stmt = select(TeleopsCallQueue).order_by(TeleopsCallQueue.name)
		if site_uid:
			stmt = stmt.where(TeleopsCallQueue.site_uid == site_uid)
		rows = (await session.execute(stmt)).scalars().all()
		return {"call_queues": [_cq_to_out(r) for r in rows], "count": len(rows)}


@router.post("/call-queues", status_code=201)
async def create_call_queue(payload: CallQueueIn, user: Auth) -> dict:
	async with get_session_factory()() as session:
		await _require_site(session, payload.site_uid)
		q = TeleopsCallQueue(**payload.model_dump(), last_modified_by=user.email, last_modified_surface="mc3")
		session.add(q)
		await session.commit()
		await session.refresh(q)
		return _cq_to_out(q)


@router.get("/call-queues/{uid}")
async def get_call_queue(uid: Annotated[str, Path()], user: Auth) -> dict:
	async with get_session_factory()() as session:
		q = await session.get(TeleopsCallQueue, uid)
		if not q:
			raise HTTPException(status_code=404, detail="Call Queue not found")
		return _cq_to_out(q)


@router.patch("/call-queues/{uid}")
async def update_call_queue(uid: Annotated[str, Path()], payload: CallQueuePatch, user: Auth) -> dict:
	async with get_session_factory()() as session:
		q = await session.get(TeleopsCallQueue, uid)
		if not q:
			raise HTTPException(status_code=404, detail="Call Queue not found")
		for k, v in payload.model_dump(exclude_unset=True).items():
			setattr(q, k, v)
		_bump_version(q, user.email)
		await session.commit()
		await session.refresh(q)
		return _cq_to_out(q)


@router.delete("/call-queues/{uid}")
async def delete_call_queue(uid: Annotated[str, Path()], user: Auth) -> dict:
	async with get_session_factory()() as session:
		q = await session.get(TeleopsCallQueue, uid)
		if not q:
			raise HTTPException(status_code=404, detail="Call Queue not found")
		await session.delete(q)
		await session.commit()
		return {"deleted": uid}
