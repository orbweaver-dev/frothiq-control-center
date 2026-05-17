"""
Field-level encryption for sensitive DB columns (Twilio auth tokens, API key
secrets, per-site API keys for MC3 ⇄ orbweaver_pbx sync).

Key derivation: Fernet key = base64(SHA-256(settings.secret_key || domain-tag)).
Rotating the secret_key invalidates ciphertext — operators must dump+re-encrypt
if that happens.
"""

from __future__ import annotations

import base64
import hashlib
from functools import lru_cache

from cryptography.fernet import Fernet
from sqlalchemy import Text
from sqlalchemy.types import TypeDecorator


_DOMAIN_TAG = b"teleops-encryption-v1"


@lru_cache(maxsize=1)
def _fernet() -> Fernet:
	from mc3.config import get_settings

	seed = get_settings().secret_key.encode("utf-8")
	key = base64.urlsafe_b64encode(hashlib.sha256(seed + _DOMAIN_TAG).digest())
	return Fernet(key)


class EncryptedText(TypeDecorator):
	"""Transparent Fernet encryption for a Text column.

	Stored as base64-encoded ciphertext; readable only via the column accessor
	(which decrypts on load). NULL values pass through unchanged.
	"""

	impl = Text
	cache_ok = True

	def process_bind_param(self, value, dialect):  # type: ignore[override]
		if value is None:
			return None
		if not isinstance(value, str):
			raise TypeError(f"EncryptedText requires str, got {type(value).__name__}")
		return _fernet().encrypt(value.encode("utf-8")).decode("ascii")

	def process_result_value(self, value, dialect):  # type: ignore[override]
		if value is None:
			return None
		return _fernet().decrypt(value.encode("ascii")).decode("utf-8")
