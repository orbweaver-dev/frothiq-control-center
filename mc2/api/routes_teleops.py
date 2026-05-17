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

from mc2.auth import TokenPayload, require_super_admin
from mc2.integrations.database import get_session_factory
from mc2.models.teleops import (
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
			last_modified_surface="mc2",
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
		acc.last_modified_surface = "mc2"
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
					last_modified_surface="mc2:import",
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
			last_modified_surface="mc2",
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
		pn.last_modified_surface = "mc2"
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
			last_modified_surface="mc2",
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
		s.last_modified_surface = "mc2"
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
	obj.last_modified_surface = "mc2"


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
			last_modified_surface="mc2",
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
			last_modified_surface="mc2",
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
		m = TeleopsIvrMenu(**payload.model_dump(), last_modified_by=user.email, last_modified_surface="mc2")
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
		o = TeleopsIvrOption(**payload.model_dump(), last_modified_by=user.email, last_modified_surface="mc2")
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
		rg = TeleopsRingGroup(**payload.model_dump(), last_modified_by=user.email, last_modified_surface="mc2")
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
		t = TeleopsTimeRule(**payload.model_dump(), last_modified_by=user.email, last_modified_surface="mc2")
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
		q = TeleopsCallQueue(**payload.model_dump(), last_modified_by=user.email, last_modified_surface="mc2")
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


# ═════════════════════════════════════════════════════════════════════════════
# PHASE B — Routing Designer (canvas state + apply to Twilio)
# ═════════════════════════════════════════════════════════════════════════════

from mc2.models.teleops import TeleopsNodePosition


class _NodeOut(BaseModel):
	uid: str
	node_type: str
	label: str
	x: float
	y: float
	data: dict


class _EdgeOut(BaseModel):
	uid: str
	source_uid: str
	target_uid: str
	source_type: str
	target_type: str
	label: str | None


@router.get("/routing-graph")
async def get_routing_graph(user: Auth, site_uid: str) -> dict:
	"""Return all routing primitives for a site as a node graph + edges.

	Used by the Routing Designer canvas to bootstrap the visualization.
	"""
	async with get_session_factory()() as session:
		# Verify site
		site = await session.get(TeleopsSite, site_uid)
		if not site:
			raise HTTPException(status_code=404, detail="Site not found")

		nodes: list[dict] = []

		# Phone numbers (entry points)
		pns = (await session.execute(
			select(TeleopsPhoneNumber).where(TeleopsPhoneNumber.site_uid == site_uid)
		)).scalars().all()
		for p in pns:
			nodes.append({
				"uid": p.uid, "node_type": "phone_number",
				"label": p.friendly_name or p.e164,
				"x": 0.0, "y": 0.0,
				"data": {"e164": p.e164, "status": p.status, "voice_url": p.voice_url},
			})

		# Extensions (terminal)
		exts = (await session.execute(
			select(TeleopsExtension).where(TeleopsExtension.site_uid == site_uid)
		)).scalars().all()
		for e in exts:
			nodes.append({
				"uid": e.uid, "node_type": "extension",
				"label": f"Ext {e.ext_number}",
				"x": 0.0, "y": 0.0,
				"data": {"ext_number": e.ext_number, "display_name": e.display_name, "presence": e.presence},
			})

		# Voicemails (terminal)
		vms = (await session.execute(
			select(TeleopsVoicemail).where(TeleopsVoicemail.site_uid == site_uid)
		)).scalars().all()
		for v in vms:
			nodes.append({
				"uid": v.uid, "node_type": "voicemail",
				"label": v.name, "x": 0.0, "y": 0.0,
				"data": {"name": v.name, "transcription_enabled": v.transcription_enabled},
			})

		# IVR Menus
		menus = (await session.execute(
			select(TeleopsIvrMenu).where(TeleopsIvrMenu.site_uid == site_uid)
		)).scalars().all()
		for m in menus:
			nodes.append({
				"uid": m.uid, "node_type": "ivr_menu",
				"label": m.name, "x": 0.0, "y": 0.0,
				"data": {"timeout_sec": m.timeout_sec, "retries": m.retries},
			})

		# Ring Groups
		rgs = (await session.execute(
			select(TeleopsRingGroup).where(TeleopsRingGroup.site_uid == site_uid)
		)).scalars().all()
		for rg in rgs:
			nodes.append({
				"uid": rg.uid, "node_type": "ring_group",
				"label": rg.name, "x": 0.0, "y": 0.0,
				"data": {"strategy": rg.strategy, "ring_seconds": rg.ring_seconds},
			})

		# Time Rules
		trs = (await session.execute(
			select(TeleopsTimeRule).where(TeleopsTimeRule.site_uid == site_uid)
		)).scalars().all()
		for t in trs:
			nodes.append({
				"uid": t.uid, "node_type": "time_rule",
				"label": t.name, "x": 0.0, "y": 0.0,
				"data": {"timezone": t.timezone},
			})

		# Call Queues
		cqs = (await session.execute(
			select(TeleopsCallQueue).where(TeleopsCallQueue.site_uid == site_uid)
		)).scalars().all()
		for cq in cqs:
			nodes.append({
				"uid": cq.uid, "node_type": "call_queue",
				"label": cq.name, "x": 0.0, "y": 0.0,
				"data": {"max_wait_seconds": cq.max_wait_seconds},
			})

		# Overlay saved positions
		positions = (await session.execute(
			select(TeleopsNodePosition).where(TeleopsNodePosition.site_uid == site_uid)
		)).scalars().all()
		pos_by_node = {p.node_uid: (p.x, p.y) for p in positions}
		for n in nodes:
			if n["uid"] in pos_by_node:
				n["x"], n["y"] = pos_by_node[n["uid"]]

		# Edges from teleops_routes
		edges_rows = (await session.execute(
			select(TeleopsRoute).where(TeleopsRoute.site_uid == site_uid)
		)).scalars().all()
		edges = [{
			"uid": r.uid,
			"source_uid": r.source_uid,
			"target_uid": r.target_uid,
			"source_type": r.source_type,
			"target_type": r.target_type,
			"label": r.label,
		} for r in edges_rows]

		return {
			"site_uid": site_uid,
			"site_name": site.name,
			"nodes": nodes,
			"edges": edges,
			"counts": {"nodes": len(nodes), "edges": len(edges)},
		}


class _NodePositionIn(BaseModel):
	node_uid: str
	node_type: str
	x: float
	y: float


class _EdgeIn(BaseModel):
	source_uid: str
	source_type: str
	target_uid: str
	target_type: str
	label: str | None = None


class _RoutingGraphIn(BaseModel):
	site_uid: str
	positions: list[_NodePositionIn]
	edges: list[_EdgeIn]
	# Replace mode: if true, edges are fully replaced for this site.
	# If false, edges are upserted only (no deletions).
	replace_edges: bool = True


@router.post("/routing-graph")
async def save_routing_graph(payload: _RoutingGraphIn, user: Auth) -> dict:
	"""Persist canvas state: upserts node positions, optionally replaces edges."""
	async with get_session_factory()() as session:
		site = await session.get(TeleopsSite, payload.site_uid)
		if not site:
			raise HTTPException(status_code=404, detail="Site not found")

		# Upsert positions
		existing_pos = (await session.execute(
			select(TeleopsNodePosition).where(TeleopsNodePosition.site_uid == payload.site_uid)
		)).scalars().all()
		pos_by_node = {p.node_uid: p for p in existing_pos}

		pos_updated = 0
		pos_created = 0
		for p in payload.positions:
			if p.node_uid in pos_by_node:
				obj = pos_by_node[p.node_uid]
				obj.x = p.x
				obj.y = p.y
				_bump_version(obj, user.email)
				pos_updated += 1
			else:
				session.add(TeleopsNodePosition(
					site_uid=payload.site_uid,
					node_type=p.node_type,
					node_uid=p.node_uid,
					x=p.x, y=p.y,
					last_modified_by=user.email,
					last_modified_surface="mc2",
				))
				pos_created += 1

		# Edges
		edges_created = 0
		edges_kept = 0
		edges_deleted = 0
		if payload.replace_edges:
			# Delete existing edges for site
			to_del = (await session.execute(
				select(TeleopsRoute).where(TeleopsRoute.site_uid == payload.site_uid)
			)).scalars().all()
			for r in to_del:
				await session.delete(r)
				edges_deleted += 1
			# Insert all incoming
			for e in payload.edges:
				session.add(TeleopsRoute(
					site_uid=payload.site_uid,
					source_type=e.source_type,
					source_uid=e.source_uid,
					target_type=e.target_type,
					target_uid=e.target_uid,
					label=e.label,
					last_modified_by=user.email,
					last_modified_surface="mc2",
				))
				edges_created += 1
		else:
			# Upsert mode: keep existing, only add new
			existing = (await session.execute(
				select(TeleopsRoute).where(TeleopsRoute.site_uid == payload.site_uid)
			)).scalars().all()
			existing_keys = {(r.source_uid, r.target_uid) for r in existing}
			edges_kept = len(existing)
			for e in payload.edges:
				if (e.source_uid, e.target_uid) not in existing_keys:
					session.add(TeleopsRoute(
						site_uid=payload.site_uid,
						source_type=e.source_type,
						source_uid=e.source_uid,
						target_type=e.target_type,
						target_uid=e.target_uid,
						label=e.label,
						last_modified_by=user.email,
						last_modified_surface="mc2",
					))
					edges_created += 1

		await session.commit()
		return {
			"positions": {"created": pos_created, "updated": pos_updated},
			"edges": {"created": edges_created, "kept": edges_kept, "deleted": edges_deleted},
		}


@router.post("/validate-routing")
async def validate_routing(user: Auth, site_uid: str) -> dict:
	"""Run validation checks on the saved routing for a site.

	Returns warnings + errors. Does not modify anything.
	"""
	async with get_session_factory()() as session:
		site = await session.get(TeleopsSite, site_uid)
		if not site:
			raise HTTPException(status_code=404, detail="Site not found")

		edges = (await session.execute(
			select(TeleopsRoute).where(TeleopsRoute.site_uid == site_uid)
		)).scalars().all()

		# Build adjacency
		adj: dict[str, list[str]] = {}
		for e in edges:
			adj.setdefault(e.source_uid, []).append(e.target_uid)

		warnings: list[str] = []
		errors: list[str] = []

		# Cycle detection (DFS)
		WHITE, GRAY, BLACK = 0, 1, 2
		color: dict[str, int] = {n: WHITE for n in adj}

		def visit(n: str, path: list[str]) -> bool:
			if color.get(n, WHITE) == GRAY:
				cycle_start = path.index(n) if n in path else 0
				errors.append("Cycle detected: " + " → ".join(path[cycle_start:] + [n]))
				return True
			if color.get(n, WHITE) == BLACK:
				return False
			color[n] = GRAY
			path.append(n)
			for nb in adj.get(n, []):
				if visit(nb, path):
					pass
			path.pop()
			color[n] = BLACK
			return False

		for n in list(adj.keys()):
			if color.get(n, WHITE) == WHITE:
				visit(n, [])

		# Orphan check: phone numbers without outbound edges
		pns = (await session.execute(
			select(TeleopsPhoneNumber).where(TeleopsPhoneNumber.site_uid == site_uid)
		)).scalars().all()
		for p in pns:
			if p.uid not in adj:
				warnings.append(f"Phone number {p.e164} has no outbound route — calls to this number will hit the default voice URL")

		# Missing target check: edges pointing at non-existent nodes
		all_uids: set[str] = set()
		for tbl in (TeleopsPhoneNumber, TeleopsExtension, TeleopsVoicemail, TeleopsIvrMenu, TeleopsRingGroup, TeleopsTimeRule, TeleopsCallQueue):
			rows = (await session.execute(select(tbl).where(tbl.site_uid == site_uid))).scalars().all()
			for r in rows:
				all_uids.add(r.uid)
		for e in edges:
			if e.target_uid not in all_uids:
				errors.append(f"Edge {e.source_type}→{e.target_type} target {e.target_uid[:8]}… not found")

		return {
			"site_uid": site_uid,
			"ok": len(errors) == 0,
			"errors": errors,
			"warnings": warnings,
			"counts": {"edges": len(edges), "nodes": len(all_uids)},
		}


# Apply-to-Twilio is a Phase B.2 stub: it rewrites the voice_url of any
# Phone Number whose outbound edge points at an Extension|IVR|RingGroup|etc.
# Inbound webhook URLs are built off the OrbWeaver_PBX site that owns the
# extension. For now this is a placeholder that returns a plan, not changes.
@router.post("/apply-routing")
async def apply_routing(user: Auth, site_uid: str, dry_run: bool = True) -> dict:
	"""Generate a plan of what would change on Twilio if this routing were applied.

	With dry_run=true (default), no changes are made — just the plan is returned.
	With dry_run=false, would update Twilio (not implemented yet — Phase B.2 deferred).
	"""
	async with get_session_factory()() as session:
		site = await session.get(TeleopsSite, site_uid)
		if not site:
			raise HTTPException(status_code=404, detail="Site not found")

		pns = (await session.execute(
			select(TeleopsPhoneNumber).where(TeleopsPhoneNumber.site_uid == site_uid)
		)).scalars().all()
		edges = (await session.execute(
			select(TeleopsRoute).where(TeleopsRoute.site_uid == site_uid)
		)).scalars().all()
		edges_by_source = {}
		for e in edges:
			edges_by_source.setdefault(e.source_uid, []).append(e)

		plan: list[dict] = []
		for p in pns:
			target_voice_url = None
			if site.frappe_site_url and site.has_orbweaver_pbx:
				# Convention: per-site orbweaver_pbx handles the inbound webhook
				target_voice_url = f"{site.frappe_site_url.rstrip('/')}/api/method/orbweaver_pbx.api.voice.inbound"
			plan.append({
				"phone_number": p.e164,
				"current_voice_url": p.voice_url,
				"target_voice_url": target_voice_url,
				"changes_needed": (target_voice_url is not None and target_voice_url != p.voice_url),
				"outbound_edges": len(edges_by_source.get(p.uid, [])),
			})

		return {
			"site_uid": site_uid,
			"dry_run": dry_run,
			"plan": plan,
			"note": "Apply-to-Twilio is not yet implemented; this endpoint currently only returns a plan. Phase B.2 wires up Twilio API writes.",
		}


# ═════════════════════════════════════════════════════════════════════════════
# PHASE C — Trust layer (Locks + Sync ingest + History/Revert)
# ═════════════════════════════════════════════════════════════════════════════

import hmac as _hmac
import hashlib
from datetime import timedelta as _td
from mc2.models.teleops import TeleopsRecordLock, TeleopsRecordHistory


_LOCK_TTL_MINUTES = 15
_LOCK_HEARTBEAT_EXTEND_MINUTES = 15


def _now() -> datetime:
	return datetime.utcnow()


# ── LOCKS ────────────────────────────────────────────────────────────────────

class _LockAcquireIn(BaseModel):
	uid: str
	surface: str = "mc2"


def _lock_to_out(L: TeleopsRecordLock) -> dict:
	return {
		"uid": L.uid,
		"locked_by_user": L.locked_by_user,
		"locked_by_surface": L.locked_by_surface,
		"locked_at": L.locked_at.isoformat(),
		"expires_at": L.expires_at.isoformat(),
		"last_heartbeat_at": L.last_heartbeat_at.isoformat(),
	}


@router.post("/locks/acquire")
async def lock_acquire(payload: _LockAcquireIn, user: Auth) -> dict:
	async with get_session_factory()() as session:
		L = await session.get(TeleopsRecordLock, payload.uid)
		now = _now()
		if L and L.expires_at > now:
			# Held by someone — refuse unless it's the SAME user reacquiring
			if L.locked_by_user != user.email or L.locked_by_surface != payload.surface:
				raise HTTPException(status_code=409, detail={
					"reason": "locked_by_other",
					"lock": _lock_to_out(L),
				})
			# Same user — refresh expiry (heartbeat semantics)
			L.last_heartbeat_at = now
			L.expires_at = now + _td(minutes=_LOCK_TTL_MINUTES)
			await session.commit()
			return {"ok": True, "lock": _lock_to_out(L), "reacquired": True}

		if L:
			# Expired — overwrite
			L.locked_by_user = user.email
			L.locked_by_surface = payload.surface
			L.locked_at = now
			L.last_heartbeat_at = now
			L.expires_at = now + _td(minutes=_LOCK_TTL_MINUTES)
		else:
			L = TeleopsRecordLock(
				uid=payload.uid,
				locked_by_user=user.email,
				locked_by_surface=payload.surface,
				locked_at=now,
				last_heartbeat_at=now,
				expires_at=now + _td(minutes=_LOCK_TTL_MINUTES),
			)
			session.add(L)
		await session.commit()
		return {"ok": True, "lock": _lock_to_out(L), "reacquired": False}


@router.post("/locks/heartbeat")
async def lock_heartbeat(payload: _LockAcquireIn, user: Auth) -> dict:
	async with get_session_factory()() as session:
		L = await session.get(TeleopsRecordLock, payload.uid)
		if not L:
			raise HTTPException(status_code=404, detail="No lock to heartbeat")
		if L.locked_by_user != user.email:
			raise HTTPException(status_code=403, detail="Lock held by another user")
		L.last_heartbeat_at = _now()
		L.expires_at = _now() + _td(minutes=_LOCK_HEARTBEAT_EXTEND_MINUTES)
		await session.commit()
		return {"ok": True, "lock": _lock_to_out(L)}


@router.post("/locks/release")
async def lock_release(payload: _LockAcquireIn, user: Auth) -> dict:
	async with get_session_factory()() as session:
		L = await session.get(TeleopsRecordLock, payload.uid)
		if not L:
			return {"ok": True, "already_released": True}
		if L.locked_by_user != user.email:
			raise HTTPException(status_code=403, detail="Lock held by another user; use /locks/force-release")
		await session.delete(L)
		await session.commit()
		return {"ok": True}


@router.get("/locks/state")
async def lock_state(user: Auth, uid: str) -> dict:
	async with get_session_factory()() as session:
		L = await session.get(TeleopsRecordLock, uid)
		if not L or L.expires_at < _now():
			return {"locked": False}
		return {"locked": True, "lock": _lock_to_out(L)}


@router.post("/locks/force-release")
async def lock_force_release(payload: _LockAcquireIn, user: Auth) -> dict:
	"""super_admin only (already gated by Auth dep). Writes a history note."""
	async with get_session_factory()() as session:
		L = await session.get(TeleopsRecordLock, payload.uid)
		if not L:
			return {"ok": True, "already_released": True}
		prev = _lock_to_out(L)
		await session.delete(L)
		# Write force-release entry to history
		session.add(TeleopsRecordHistory(
			record_uid=payload.uid,
			record_type="(unknown)",
			version_after=0,
			change_type="force_unlock",
			changed_by=user.email,
			surface="mc2",
			change_summary=f"force-released lock held by {prev['locked_by_user']} ({prev['locked_by_surface']})",
		))
		await session.commit()
		return {"ok": True, "force_released_from": prev}


# ── SYNC INGEST (Site → MC²) ─────────────────────────────────────────────────

class _SyncIngestIn(BaseModel):
	uid: str
	record_type: str
	version: int
	data: dict
	last_modified_at: str | None = None
	last_modified_by: str | None = None
	surface: str = "site"


@router.post("/sync/ingest")
async def sync_ingest(payload: _SyncIngestIn, user: Auth) -> dict:
	"""Receive a push from a per-site orbweaver_pbx. Writes a history row +
	updates the corresponding MC² record (currently logs only; full upsert
	per record_type is wired up alongside Phase D)."""
	async with get_session_factory()() as session:
		import json as _json
		session.add(TeleopsRecordHistory(
			record_uid=payload.uid,
			record_type=payload.record_type,
			version_after=payload.version,
			change_type="update",
			changed_by=payload.last_modified_by or user.email,
			surface=payload.surface,
			payload_after=_json.dumps(payload.data, default=str),
			change_summary=f"sync ingest from {payload.surface}",
		))
		# Update mc3_synced_at on the corresponding record. For Phase C we only
		# acknowledge — Phase D's per-record dispatcher applies the data.
		await session.commit()
		return {"ok": True, "received": True}


# ── HISTORY / REVERT ─────────────────────────────────────────────────────────


def _hist_to_out(h: TeleopsRecordHistory) -> dict:
	return {
		"id": h.id,
		"record_uid": h.record_uid,
		"record_type": h.record_type,
		"version_after": h.version_after,
		"change_type": h.change_type,
		"changed_at": h.changed_at.isoformat() if h.changed_at else None,
		"changed_by": h.changed_by,
		"surface": h.surface,
		"change_summary": h.change_summary,
		"parent_history_id": h.parent_history_id,
		"has_payload": bool(h.payload_after),
	}


@router.get("/history")
async def history_list(user: Auth, uid: str | None = None, limit: int = 100) -> dict:
	async with get_session_factory()() as session:
		stmt = select(TeleopsRecordHistory).order_by(TeleopsRecordHistory.changed_at.desc()).limit(min(limit, 500))
		if uid:
			stmt = stmt.where(TeleopsRecordHistory.record_uid == uid)
		rows = (await session.execute(stmt)).scalars().all()
		return {"history": [_hist_to_out(h) for h in rows], "count": len(rows)}


@router.get("/history/{id}")
async def history_get(id: Annotated[str, Path()], user: Auth) -> dict:
	async with get_session_factory()() as session:
		h = await session.get(TeleopsRecordHistory, id)
		if not h:
			raise HTTPException(status_code=404, detail="History entry not found")
		out = _hist_to_out(h)
		out["payload_before"] = h.payload_before
		out["payload_after"] = h.payload_after
		out["lock_uid"] = h.lock_uid
		return out


@router.post("/history/{id}/revert")
async def history_revert(id: Annotated[str, Path()], user: Auth) -> dict:
	"""Apply payload_before of a history entry as the new state of the record.
	Writes a new history row of change_type='restore' with parent_history_id."""
	async with get_session_factory()() as session:
		h = await session.get(TeleopsRecordHistory, id)
		if not h:
			raise HTTPException(status_code=404, detail="History entry not found")
		if not h.payload_before:
			raise HTTPException(status_code=400, detail="No payload_before to revert to")
		# Write a restore-marker history entry. The actual record application is
		# the responsibility of the per-record dispatcher (paired with Phase D).
		session.add(TeleopsRecordHistory(
			record_uid=h.record_uid,
			record_type=h.record_type,
			version_after=h.version_after + 1,
			change_type="restore",
			changed_by=user.email,
			surface="mc2",
			payload_after=h.payload_before,
			change_summary=f"reverted to history entry {h.id[:8]}",
			parent_history_id=h.id,
		))
		await session.commit()
		return {"ok": True, "restored_from": h.id, "note": "Restore queued — per-record application is handled by the Phase D dispatcher"}


# ═════════════════════════════════════════════════════════════════════════════
# PHASE E — Call Logs (CDR) + Billing rollups
# ═════════════════════════════════════════════════════════════════════════════

from mc2.models.teleops import TeleopsCallLog


def _cdr_to_out(c: TeleopsCallLog) -> dict:
	return {
		"twilio_call_sid": c.twilio_call_sid,
		"voip_account_uid": c.voip_account_uid,
		"phone_number_uid": c.phone_number_uid,
		"site_uid": c.site_uid,
		"direction": c.direction,
		"status": c.status,
		"from_number": c.from_number,
		"to_number": c.to_number,
		"duration_seconds": c.duration_seconds,
		"cost_usd": c.cost_usd,
		"started_at": c.started_at.isoformat() if c.started_at else None,
		"ended_at": c.ended_at.isoformat() if c.ended_at else None,
	}


@router.post("/cdr/refresh")
async def cdr_refresh(user: Auth, voip_account_uid: str, days: int = 7) -> dict:
	"""Pull recent calls from Twilio's API and upsert into teleops_call_logs."""
	async with get_session_factory()() as session:
		acc = await session.get(TeleopsVoipAccount, voip_account_uid)
		if not acc:
			raise HTTPException(status_code=404, detail="VOIP Account not found")
		if acc.provider != "twilio":
			raise HTTPException(status_code=400, detail=f"CDR refresh not supported for provider {acc.provider}")
		if not acc.auth_token:
			raise HTTPException(status_code=400, detail="auth_token required to pull CDR")

		# Build StartTime>=N days ago filter for Twilio
		from datetime import timezone as _tz
		start_after = datetime.utcnow() - _td(days=max(1, min(days, 90)))
		start_str = start_after.strftime("%Y-%m-%d")
		path = f"/Calls.json?StartTime%3E={start_str}&PageSize=100"

		# E.164 → phone_number_uid lookup
		pns = (await session.execute(
			select(TeleopsPhoneNumber).where(TeleopsPhoneNumber.voip_account_uid == voip_account_uid)
		)).scalars().all()
		pn_by_e164 = {p.e164: p for p in pns}

		imported = 0
		updated = 0
		while path:
			data = await _twilio_get(acc.account_sid, acc.auth_token, path)
			for call in data.get("calls", []):
				sid = call.get("sid")
				if not sid:
					continue
				existing = await session.get(TeleopsCallLog, sid)
				direction = (call.get("direction") or "").replace("-", "_")
				direction = "inbound" if direction.startswith("inbound") else "outbound" if direction.startswith("outbound") else direction or "unknown"
				from_n = call.get("from")
				to_n = call.get("to")
				matched_pn = pn_by_e164.get(from_n) or pn_by_e164.get(to_n)
				started_at = None
				ended_at = None
				try:
					if call.get("start_time"):
						started_at = datetime.strptime(call["start_time"], "%a, %d %b %Y %H:%M:%S %z").replace(tzinfo=None)
					if call.get("end_time"):
						ended_at = datetime.strptime(call["end_time"], "%a, %d %b %Y %H:%M:%S %z").replace(tzinfo=None)
				except (ValueError, TypeError):
					pass
				price_raw = call.get("price")
				cost_usd = None
				try:
					if price_raw is not None:
						cost_usd = abs(float(price_raw))
				except (ValueError, TypeError):
					pass

				if existing:
					existing.status = call.get("status") or existing.status
					existing.duration_seconds = int(call.get("duration") or 0) or existing.duration_seconds
					existing.cost_usd = cost_usd if cost_usd is not None else existing.cost_usd
					existing.ended_at = ended_at or existing.ended_at
					updated += 1
				else:
					session.add(TeleopsCallLog(
						twilio_call_sid=sid,
						voip_account_uid=acc.uid,
						phone_number_uid=matched_pn.uid if matched_pn else None,
						site_uid=matched_pn.site_uid if matched_pn else None,
						direction=direction,
						status=call.get("status") or "unknown",
						from_number=from_n,
						to_number=to_n,
						duration_seconds=int(call.get("duration") or 0) or None,
						cost_usd=cost_usd,
						started_at=started_at,
						ended_at=ended_at,
					))
					imported += 1

			next_uri = data.get("next_page_uri")
			if next_uri and next_uri.startswith("/2010-04-01"):
				next_uri = next_uri[len("/2010-04-01"):]
			acct_prefix = f"/Accounts/{acc.account_sid}"
			if next_uri and next_uri.startswith(acct_prefix):
				next_uri = next_uri[len(acct_prefix):]
			path = next_uri or None

		await session.commit()
		return {"imported": imported, "updated": updated, "days_pulled": days}


@router.get("/cdr")
async def cdr_list(
	user: Auth,
	site_uid: str | None = None,
	voip_account_uid: str | None = None,
	direction: str | None = None,
	limit: int = 200,
) -> dict:
	async with get_session_factory()() as session:
		stmt = select(TeleopsCallLog).order_by(TeleopsCallLog.started_at.desc()).limit(min(limit, 1000))
		if site_uid:
			stmt = stmt.where(TeleopsCallLog.site_uid == site_uid)
		if voip_account_uid:
			stmt = stmt.where(TeleopsCallLog.voip_account_uid == voip_account_uid)
		if direction:
			stmt = stmt.where(TeleopsCallLog.direction == direction)
		rows = (await session.execute(stmt)).scalars().all()
		return {"calls": [_cdr_to_out(c) for c in rows], "count": len(rows)}


@router.get("/billing/rollup")
async def billing_rollup(user: Auth, year: int, month: int) -> dict:
	"""Aggregate teleops_call_logs cost by site + voip_account + phone number for a given month."""
	from sqlalchemy import func
	from datetime import date as _date
	if not (1 <= month <= 12):
		raise HTTPException(status_code=400, detail="month must be 1-12")
	start = datetime(year, month, 1)
	end = datetime(year + (month // 12), (month % 12) + 1, 1)

	async with get_session_factory()() as session:
		# By site
		by_site_q = select(
			TeleopsCallLog.site_uid,
			func.count(TeleopsCallLog.twilio_call_sid).label("calls"),
			func.coalesce(func.sum(TeleopsCallLog.duration_seconds), 0).label("seconds"),
			func.coalesce(func.sum(TeleopsCallLog.cost_usd), 0.0).label("cost"),
		).where(
			TeleopsCallLog.started_at >= start, TeleopsCallLog.started_at < end
		).group_by(TeleopsCallLog.site_uid)
		by_site = [{"site_uid": r[0], "calls": int(r[1]), "seconds": int(r[2]), "cost_usd": float(r[3])} for r in (await session.execute(by_site_q)).all()]

		# By account
		by_acc_q = select(
			TeleopsCallLog.voip_account_uid,
			func.count(TeleopsCallLog.twilio_call_sid).label("calls"),
			func.coalesce(func.sum(TeleopsCallLog.cost_usd), 0.0).label("cost"),
		).where(
			TeleopsCallLog.started_at >= start, TeleopsCallLog.started_at < end
		).group_by(TeleopsCallLog.voip_account_uid)
		by_account = [{"voip_account_uid": r[0], "calls": int(r[1]), "cost_usd": float(r[2])} for r in (await session.execute(by_acc_q)).all()]

		# By phone number
		by_pn_q = select(
			TeleopsCallLog.phone_number_uid,
			func.count(TeleopsCallLog.twilio_call_sid).label("calls"),
			func.coalesce(func.sum(TeleopsCallLog.cost_usd), 0.0).label("cost"),
		).where(
			TeleopsCallLog.started_at >= start, TeleopsCallLog.started_at < end
		).group_by(TeleopsCallLog.phone_number_uid)
		by_number = [{"phone_number_uid": r[0], "calls": int(r[1]), "cost_usd": float(r[2])} for r in (await session.execute(by_pn_q)).all()]

		# Totals
		total_q = select(
			func.count(TeleopsCallLog.twilio_call_sid),
			func.coalesce(func.sum(TeleopsCallLog.duration_seconds), 0),
			func.coalesce(func.sum(TeleopsCallLog.cost_usd), 0.0),
		).where(TeleopsCallLog.started_at >= start, TeleopsCallLog.started_at < end)
		total_row = (await session.execute(total_q)).one()
		totals = {"calls": int(total_row[0]), "seconds": int(total_row[1]), "cost_usd": float(total_row[2])}

		return {
			"year": year, "month": month,
			"window": {"start": start.isoformat(), "end": end.isoformat()},
			"totals": totals,
			"by_site": by_site, "by_account": by_account, "by_number": by_number,
		}


# ═════════════════════════════════════════════════════════════════════════════
# PHASE F — Twilio Provisioning Automation
# ═════════════════════════════════════════════════════════════════════════════


async def _twilio_post(account_sid: str, auth_token: str, path: str, form: dict) -> dict:
	"""Authenticated POST to Twilio REST API with form-encoded body."""
	url = f"https://api.twilio.com/2010-04-01/Accounts/{account_sid}{path}"
	creds = base64.b64encode(f"{account_sid}:{auth_token}".encode()).decode("ascii")
	async with httpx.AsyncClient(timeout=30.0) as client:
		resp = await client.post(
			url,
			headers={"Authorization": f"Basic {creds}", "Content-Type": "application/x-www-form-urlencoded"},
			data=form,
		)
		if resp.status_code == 401:
			raise HTTPException(status_code=400, detail="Twilio rejected the auth token")
		if resp.status_code >= 400:
			raise HTTPException(status_code=502, detail=f"Twilio API error {resp.status_code}: {resp.text[:300]}")
		return resp.json()


class _SubaccountIn(BaseModel):
	friendly_name: str


@router.post("/twilio/{voip_account_uid}/subaccount")
async def twilio_create_subaccount(voip_account_uid: Annotated[str, Path()], payload: _SubaccountIn, user: Auth) -> dict:
	"""Create a Twilio Subaccount under the given (master) account, and register
	it as a new VOIP Account in MC² with parent_account_sid set."""
	async with get_session_factory()() as session:
		acc = await session.get(TeleopsVoipAccount, voip_account_uid)
		if not acc:
			raise HTTPException(status_code=404, detail="VOIP Account not found")
		if acc.parent_account_sid:
			raise HTTPException(status_code=400, detail="Cannot create a Subaccount under another Subaccount")
		if not acc.auth_token:
			raise HTTPException(status_code=400, detail="auth_token required")

		data = await _twilio_post(acc.account_sid, acc.auth_token, ".json".replace(".", ".json", 0) and "/../Accounts.json", {"FriendlyName": payload.friendly_name}) if False else None
		# Twilio: POST /2010-04-01/Accounts.json (NOT under master) — special endpoint
		# We have to make a non-Account-prefixed call. Inline that:
		url = "https://api.twilio.com/2010-04-01/Accounts.json"
		creds = base64.b64encode(f"{acc.account_sid}:{acc.auth_token}".encode()).decode("ascii")
		async with httpx.AsyncClient(timeout=30.0) as client:
			resp = await client.post(url, headers={"Authorization": f"Basic {creds}"}, data={"FriendlyName": payload.friendly_name})
		if resp.status_code >= 400:
			raise HTTPException(status_code=502, detail=f"Twilio API {resp.status_code}: {resp.text[:200]}")
		data = resp.json()

		new_sid = data["sid"]
		new_token = data.get("auth_token")
		# Register subaccount in MC²
		sub = TeleopsVoipAccount(
			provider="twilio",
			account_sid=new_sid,
			parent_account_sid=acc.account_sid,
			friendly_name=payload.friendly_name,
			auth_token=new_token,
			is_active=True,
			last_modified_by=user.email,
			last_modified_surface="mc2",
		)
		session.add(sub)
		await session.commit()
		await session.refresh(sub)
		return {"created": True, "voip_account": _voip_to_out(sub)}


class _TwimlAppIn(BaseModel):
	friendly_name: str
	voice_url: str | None = None
	voice_method: str = "POST"
	status_callback: str | None = None


@router.post("/twilio/{voip_account_uid}/twiml-app")
async def twilio_create_twiml_app(voip_account_uid: Annotated[str, Path()], payload: _TwimlAppIn, user: Auth) -> dict:
	async with get_session_factory()() as session:
		acc = await session.get(TeleopsVoipAccount, voip_account_uid)
		if not acc:
			raise HTTPException(status_code=404, detail="VOIP Account not found")
		if not acc.auth_token:
			raise HTTPException(status_code=400, detail="auth_token required")
		form = {"FriendlyName": payload.friendly_name, "VoiceMethod": payload.voice_method}
		if payload.voice_url:
			form["VoiceUrl"] = payload.voice_url
		if payload.status_callback:
			form["StatusCallback"] = payload.status_callback
		data = await _twilio_post(acc.account_sid, acc.auth_token, "/Applications.json", form)
		return {"created": True, "twiml_app_sid": data["sid"], "friendly_name": data["friendly_name"]}


@router.get("/twilio/{voip_account_uid}/available-numbers")
async def twilio_available_numbers(
	voip_account_uid: Annotated[str, Path()],
	user: Auth,
	country: str = "US",
	area_code: str | None = None,
	contains: str | None = None,
	limit: int = 20,
) -> dict:
	async with get_session_factory()() as session:
		acc = await session.get(TeleopsVoipAccount, voip_account_uid)
		if not acc:
			raise HTTPException(status_code=404, detail="VOIP Account not found")
		if not acc.auth_token:
			raise HTTPException(status_code=400, detail="auth_token required")
		params = {"PageSize": min(limit, 30)}
		if area_code:
			params["AreaCode"] = area_code
		if contains:
			params["Contains"] = contains
		from urllib.parse import urlencode
		qs = urlencode(params)
		data = await _twilio_get(acc.account_sid, acc.auth_token, f"/AvailablePhoneNumbers/{country}/Local.json?{qs}")
		return {"country": country, "available": data.get("available_phone_numbers", [])}


class _BuyNumberIn(BaseModel):
	phone_number: str
	friendly_name: str | None = None


@router.post("/twilio/{voip_account_uid}/buy-number")
async def twilio_buy_number(voip_account_uid: Annotated[str, Path()], payload: _BuyNumberIn, user: Auth) -> dict:
	async with get_session_factory()() as session:
		acc = await session.get(TeleopsVoipAccount, voip_account_uid)
		if not acc:
			raise HTTPException(status_code=404, detail="VOIP Account not found")
		if not acc.auth_token:
			raise HTTPException(status_code=400, detail="auth_token required")
		form = {"PhoneNumber": payload.phone_number}
		if payload.friendly_name:
			form["FriendlyName"] = payload.friendly_name
		data = await _twilio_post(acc.account_sid, acc.auth_token, "/IncomingPhoneNumbers.json", form)
		# Register in MC²
		pn = TeleopsPhoneNumber(
			e164=data["phone_number"],
			voip_account_uid=acc.uid,
			friendly_name=data.get("friendly_name"),
			country=data.get("iso_country") or "US",
			status="Active",
			voice_method="POST",
			status_callback_method="POST",
			sms_method="POST",
			last_modified_by=user.email,
			last_modified_surface="mc2:purchase",
		)
		session.add(pn)
		await session.commit()
		await session.refresh(pn)
		return {"purchased": True, "phone_number": _pn_to_out(pn)}


class _TransferNumberIn(BaseModel):
	target_voip_account_uid: str


@router.post("/phone-numbers/{phone_uid}/transfer")
async def twilio_transfer_number(phone_uid: Annotated[str, Path()], payload: _TransferNumberIn, user: Auth) -> dict:
	"""Transfer a number between Twilio (sub)accounts. Free operation."""
	async with get_session_factory()() as session:
		pn = await session.get(TeleopsPhoneNumber, phone_uid)
		if not pn:
			raise HTTPException(status_code=404, detail="Phone Number not found")
		src = await session.get(TeleopsVoipAccount, pn.voip_account_uid)
		dst = await session.get(TeleopsVoipAccount, payload.target_voip_account_uid)
		if not src or not dst:
			raise HTTPException(status_code=400, detail="source or destination account not found")
		if not src.auth_token:
			raise HTTPException(status_code=400, detail="source account requires auth_token")
		# Find Twilio's PN sid by looking up the number
		data = await _twilio_get(src.account_sid, src.auth_token, f"/IncomingPhoneNumbers.json?PhoneNumber={pn.e164}")
		nums = data.get("incoming_phone_numbers", [])
		if not nums:
			raise HTTPException(status_code=404, detail=f"Number {pn.e164} not found on source account")
		twilio_pn_sid = nums[0]["sid"]
		await _twilio_post(src.account_sid, src.auth_token, f"/IncomingPhoneNumbers/{twilio_pn_sid}.json", {"AccountSid": dst.account_sid})
		# Update MC² record
		pn.voip_account_uid = dst.uid
		_bump_version(pn, user.email)
		await session.commit()
		return {"transferred": True, "from": src.friendly_name, "to": dst.friendly_name}
