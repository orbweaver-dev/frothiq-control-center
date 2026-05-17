"""
Storage account service — manages S3-compatible storage account configurations.

Accounts live in /etc/frothiq/storage-accounts.json with 0640 frothiq:frothiq.
Each account holds the connection info needed to talk to an S3-compatible
endpoint: Vultr, AWS, Backblaze B2, MinIO, Wasabi, etc.

Provides:
  - load_accounts() / save_accounts()      — JSON persistence
  - get_account(name)                      — lookup one account
  - upsert_account(...)                    — create or update
  - delete_account(name)                   — remove
  - s3_client(account)                     — async context manager yielding
                                              a boto3 S3 client bound to the
                                              account's endpoint + credentials
  - redact(account)                        — strip secret_key for safe display

JSON shape:
{
  "accounts": [
    {
      "name": "nextcloud-data",
      "label": "Vultr — nextcloud-data",
      "provider": "vultr",
      "endpoint_url": "https://ewr1.vultrobjects.com",
      "region": "us-east-1",
      "access_key": "...",
      "secret_key": "...",
      "default_bucket": "nextcloud-data"
    }
  ]
}
"""

from __future__ import annotations

import json
import logging
import os
import stat
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, AsyncIterator

from aiobotocore.session import get_session

logger = logging.getLogger(__name__)

_CONFIG_PATH = Path(
    os.environ.get("CC_STORAGE_ACCOUNTS_PATH", "/etc/frothiq/storage-accounts.json")
)

# Fields that must be present on every account
_REQUIRED = ("name", "endpoint_url", "access_key", "secret_key")
# Fields safe to return in API responses (everything except secret_key)
_REDACTED_FIELDS = ("secret_key",)


def _empty_config() -> dict[str, Any]:
    return {"accounts": []}


def load_accounts() -> list[dict[str, Any]]:
    """Read all accounts from the JSON config; returns [] if file is missing."""
    if not _CONFIG_PATH.exists():
        return []
    try:
        with _CONFIG_PATH.open() as f:
            data = json.load(f)
        return data.get("accounts", [])
    except (json.JSONDecodeError, OSError) as exc:
        logger.error("storage-accounts.json unreadable: %s", exc)
        return []


def save_accounts(accounts: list[dict[str, Any]]) -> None:
    """Atomically write accounts to the JSON config; chmod 0640."""
    _CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp = _CONFIG_PATH.with_suffix(".tmp")
    with tmp.open("w") as f:
        json.dump({"accounts": accounts}, f, indent=2, sort_keys=True)
    os.chmod(tmp, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP)  # 0640
    tmp.replace(_CONFIG_PATH)


def get_account(name: str) -> dict[str, Any] | None:
    for a in load_accounts():
        if a.get("name") == name:
            return a
    return None


def upsert_account(account: dict[str, Any]) -> dict[str, Any]:
    """Create or update an account by `name`. Returns the stored account."""
    for f in _REQUIRED:
        if not account.get(f):
            raise ValueError(f"missing required field: {f}")
    accounts = load_accounts()
    for i, existing in enumerate(accounts):
        if existing.get("name") == account["name"]:
            merged = {**existing, **account}
            accounts[i] = merged
            save_accounts(accounts)
            return merged
    accounts.append(account)
    save_accounts(accounts)
    return account


def delete_account(name: str) -> bool:
    accounts = load_accounts()
    new = [a for a in accounts if a.get("name") != name]
    if len(new) == len(accounts):
        return False
    save_accounts(new)
    return True


def redact(account: dict[str, Any]) -> dict[str, Any]:
    """Return a copy with secret_key replaced by a placeholder."""
    safe = dict(account)
    for f in _REDACTED_FIELDS:
        if safe.get(f):
            safe[f] = "***"
    return safe


@asynccontextmanager
async def s3_client(account: dict[str, Any]) -> AsyncIterator[Any]:
    """
    Async context manager yielding an aiobotocore S3 client bound to
    the given account's endpoint and credentials.

    Usage:
        async with s3_client(account) as s3:
            await s3.list_buckets()
    """
    session = get_session()
    async with session.create_client(
        "s3",
        endpoint_url=account["endpoint_url"],
        region_name=account.get("region", "us-east-1"),
        aws_access_key_id=account["access_key"],
        aws_secret_access_key=account["secret_key"],
    ) as client:
        yield client
