"""
Storage account CRUD routes.

GET    /storage/accounts             — list (secrets redacted)
GET    /storage/accounts/{name}      — get one (secret redacted)
POST   /storage/accounts             — create or update
PUT    /storage/accounts/{name}      — update (name in path)
DELETE /storage/accounts/{name}      — delete
POST   /storage/accounts/{name}/test — verify creds by calling list_buckets()

Read endpoints: require_read_only.
Write/delete:   require_super_admin.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from botocore.exceptions import BotoCoreError, ClientError
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from mc3.auth import require_read_only, require_super_admin
from mc3.services.storage_account_service import (
    delete_account,
    get_account,
    load_accounts,
    redact,
    s3_client,
    upsert_account,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/storage/accounts", tags=["storage-accounts"])

_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")


class AccountPayload(BaseModel):
    name: str = Field(..., min_length=1, max_length=64)
    label: str = Field("", max_length=128)
    provider: str = Field("s3", max_length=32)
    endpoint_url: str = Field(..., min_length=8, max_length=512)
    region: str = Field("us-east-1", max_length=64)
    access_key: str = Field(..., min_length=4, max_length=256)
    secret_key: str = Field(..., min_length=4, max_length=256)
    default_bucket: str = Field("", max_length=255)


class AccountUpdate(BaseModel):
    label: str | None = Field(None, max_length=128)
    provider: str | None = Field(None, max_length=32)
    endpoint_url: str | None = Field(None, min_length=8, max_length=512)
    region: str | None = Field(None, max_length=64)
    access_key: str | None = Field(None, min_length=4, max_length=256)
    secret_key: str | None = Field(None, min_length=4, max_length=256)
    default_bucket: str | None = Field(None, max_length=255)


def _validate_name(name: str) -> None:
    if not _NAME_RE.match(name):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "account name must be lowercase alphanumeric, may contain "
                "hyphens/underscores, 1-64 chars, starting with a letter/digit"
            ),
        )


@router.get("")
async def list_accounts(_=Depends(require_read_only)) -> dict[str, Any]:
    accounts = load_accounts()
    return {
        "total": len(accounts),
        "accounts": [redact(a) for a in accounts],
    }


@router.get("/{name}")
async def get_one(name: str, _=Depends(require_read_only)) -> dict[str, Any]:
    _validate_name(name)
    account = get_account(name)
    if account is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="account not found")
    return redact(account)


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_account(payload: AccountPayload, _=Depends(require_super_admin)) -> dict[str, Any]:
    _validate_name(payload.name)
    stored = upsert_account(payload.model_dump())
    logger.info("storage account created: %s (%s)", stored["name"], stored.get("provider"))
    return redact(stored)


@router.put("/{name}")
async def update_account(
    name: str, payload: AccountUpdate, _=Depends(require_super_admin)
) -> dict[str, Any]:
    _validate_name(name)
    existing = get_account(name)
    if existing is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="account not found")
    changes = {k: v for k, v in payload.model_dump().items() if v is not None}
    merged = {**existing, **changes, "name": name}
    stored = upsert_account(merged)
    logger.info("storage account updated: %s", name)
    return redact(stored)


@router.delete("/{name}")
async def remove_account(name: str, _=Depends(require_super_admin)) -> dict[str, bool]:
    _validate_name(name)
    if not delete_account(name):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="account not found")
    logger.info("storage account deleted: %s", name)
    return {"ok": True}


@router.post("/{name}/test")
async def test_account(name: str, _=Depends(require_super_admin)) -> dict[str, Any]:
    """Verify credentials by calling list_buckets(); returns bucket names on success."""
    _validate_name(name)
    account = get_account(name)
    if account is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="account not found")
    try:
        async with s3_client(account) as s3:
            resp = await s3.list_buckets()
            buckets = [b["Name"] for b in resp.get("Buckets", [])]
        return {"ok": True, "buckets": buckets}
    except (ClientError, BotoCoreError) as exc:
        return {"ok": False, "error": str(exc)}
