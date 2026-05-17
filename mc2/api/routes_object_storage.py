"""
Object-storage file operations — list, download, upload, delete, folders.

All paths are scoped to an {account} (S3-compatible config) and a {bucket}.
The "folder" abstraction is purely a UI convention: keys ending in `/` with
zero bytes act as visible folder markers; `delimiter=/` in list_objects
groups by folder.

Endpoints:
  GET    /storage/{account}/buckets
  GET    /storage/{account}/{bucket}/objects?prefix=&continuation_token=
  GET    /storage/{account}/{bucket}/object?key=                   — download (stream)
  PUT    /storage/{account}/{bucket}/object?key=                   — multipart upload
  DELETE /storage/{account}/{bucket}/object?key=                   — delete single
  POST   /storage/{account}/{bucket}/folder?prefix=                — create folder marker
  DELETE /storage/{account}/{bucket}/folder?prefix=                — recursive folder delete

Read: require_read_only. Mutate: require_super_admin.
"""

from __future__ import annotations

import logging
import re
from typing import Any
from urllib.parse import quote

from botocore.exceptions import BotoCoreError, ClientError
from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile, status
from fastapi.responses import StreamingResponse

from mc3.auth import require_read_only, require_super_admin
from mc3.services.storage_account_service import (
    get_account,
    s3_client,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/storage", tags=["object-storage"])

_BUCKET_RE = re.compile(r"^[a-z0-9][a-z0-9.\-]{1,62}$")
_ACCOUNT_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")


def _resolve_account(name: str) -> dict[str, Any]:
    if not _ACCOUNT_RE.match(name):
        raise HTTPException(status_code=400, detail="invalid account name")
    account = get_account(name)
    if account is None:
        raise HTTPException(status_code=404, detail=f"account not found: {name}")
    return account


def _validate_bucket(bucket: str) -> None:
    if not _BUCKET_RE.match(bucket):
        raise HTTPException(status_code=400, detail="invalid bucket name")


def _validate_key(key: str) -> None:
    if not key or len(key) > 1024:
        raise HTTPException(status_code=400, detail="invalid key length")
    if "\0" in key or key.startswith("/"):
        raise HTTPException(status_code=400, detail="invalid key characters")


@router.get("/{account}/buckets")
async def list_buckets(account: str, _=Depends(require_read_only)) -> dict[str, Any]:
    acc = _resolve_account(account)
    try:
        async with s3_client(acc) as s3:
            resp = await s3.list_buckets()
        return {
            "buckets": [
                {"name": b["Name"], "creation_date": b["CreationDate"].isoformat()}
                for b in resp.get("Buckets", [])
            ],
        }
    except (ClientError, BotoCoreError) as exc:
        raise HTTPException(status_code=502, detail=f"S3 error: {exc}")


@router.get("/{account}/{bucket}/objects")
async def list_objects(
    account: str,
    bucket: str,
    prefix: str = Query("", max_length=1024),
    continuation_token: str | None = Query(None, max_length=2048),
    max_keys: int = Query(1000, ge=1, le=1000),
    _=Depends(require_read_only),
) -> dict[str, Any]:
    """List objects in `bucket` under `prefix`. Folders are returned as `CommonPrefixes`."""
    acc = _resolve_account(account)
    _validate_bucket(bucket)
    params: dict[str, Any] = {
        "Bucket": bucket,
        "Prefix": prefix,
        "Delimiter": "/",
        "MaxKeys": max_keys,
    }
    if continuation_token:
        params["ContinuationToken"] = continuation_token

    try:
        async with s3_client(acc) as s3:
            resp = await s3.list_objects_v2(**params)
    except (ClientError, BotoCoreError) as exc:
        raise HTTPException(status_code=502, detail=f"S3 error: {exc}")

    objects = []
    for o in resp.get("Contents", []):
        # Skip the prefix marker itself (zero-byte folder placeholder)
        if o["Key"] == prefix and o["Size"] == 0 and prefix.endswith("/"):
            continue
        objects.append(
            {
                "key": o["Key"],
                "size": o["Size"],
                "last_modified": o["LastModified"].isoformat(),
                "etag": o.get("ETag", "").strip('"'),
            }
        )
    folders = [
        {"prefix": p["Prefix"]} for p in resp.get("CommonPrefixes", [])
    ]
    return {
        "prefix": prefix,
        "objects": objects,
        "folders": folders,
        "is_truncated": resp.get("IsTruncated", False),
        "next_continuation_token": resp.get("NextContinuationToken"),
    }


@router.get("/{account}/{bucket}/object")
async def download_object(
    account: str,
    bucket: str,
    key: str = Query(..., max_length=1024),
    _=Depends(require_read_only),
):
    acc = _resolve_account(account)
    _validate_bucket(bucket)
    _validate_key(key)

    session_cm = s3_client(acc)
    s3 = await session_cm.__aenter__()
    try:
        try:
            resp = await s3.get_object(Bucket=bucket, Key=key)
        except ClientError as exc:
            await session_cm.__aexit__(None, None, None)
            code = exc.response.get("Error", {}).get("Code", "")
            if code in ("NoSuchKey", "404"):
                raise HTTPException(status_code=404, detail="object not found")
            raise HTTPException(status_code=502, detail=f"S3 error: {exc}")

        body = resp["Body"]
        content_type = resp.get("ContentType", "application/octet-stream")
        content_length = resp.get("ContentLength")
        filename = key.rsplit("/", 1)[-1] or "download"

        async def stream():
            try:
                async for chunk in body.iter_chunks(chunk_size=64 * 1024):
                    yield chunk
            finally:
                await session_cm.__aexit__(None, None, None)

        headers = {
            "Content-Disposition": f'attachment; filename="{quote(filename)}"',
        }
        if content_length is not None:
            headers["Content-Length"] = str(content_length)
        return StreamingResponse(stream(), media_type=content_type, headers=headers)
    except HTTPException:
        raise
    except Exception:
        await session_cm.__aexit__(None, None, None)
        raise


@router.put("/{account}/{bucket}/object", status_code=status.HTTP_201_CREATED)
async def upload_object(
    account: str,
    bucket: str,
    key: str = Query(..., max_length=1024),
    file: UploadFile = File(...),
    _=Depends(require_super_admin),
) -> dict[str, Any]:
    acc = _resolve_account(account)
    _validate_bucket(bucket)
    _validate_key(key)
    body = await file.read()
    try:
        async with s3_client(acc) as s3:
            await s3.put_object(
                Bucket=bucket,
                Key=key,
                Body=body,
                ContentType=file.content_type or "application/octet-stream",
            )
    except (ClientError, BotoCoreError) as exc:
        raise HTTPException(status_code=502, detail=f"S3 error: {exc}")
    return {"key": key, "size": len(body)}


@router.delete("/{account}/{bucket}/object")
async def delete_one_object(
    account: str,
    bucket: str,
    key: str = Query(..., max_length=1024),
    _=Depends(require_super_admin),
) -> dict[str, Any]:
    acc = _resolve_account(account)
    _validate_bucket(bucket)
    _validate_key(key)
    try:
        async with s3_client(acc) as s3:
            await s3.delete_object(Bucket=bucket, Key=key)
    except (ClientError, BotoCoreError) as exc:
        raise HTTPException(status_code=502, detail=f"S3 error: {exc}")
    return {"key": key, "deleted": True}


@router.post("/{account}/{bucket}/folder", status_code=status.HTTP_201_CREATED)
async def create_folder(
    account: str,
    bucket: str,
    prefix: str = Query(..., min_length=1, max_length=1024),
    _=Depends(require_super_admin),
) -> dict[str, Any]:
    acc = _resolve_account(account)
    _validate_bucket(bucket)
    if not prefix.endswith("/"):
        prefix = prefix + "/"
    _validate_key(prefix)
    try:
        async with s3_client(acc) as s3:
            await s3.put_object(Bucket=bucket, Key=prefix, Body=b"")
    except (ClientError, BotoCoreError) as exc:
        raise HTTPException(status_code=502, detail=f"S3 error: {exc}")
    return {"prefix": prefix}


@router.delete("/{account}/{bucket}/folder", status_code=status.HTTP_200_OK)
async def delete_folder_recursive(
    account: str,
    bucket: str,
    prefix: str = Query(..., min_length=1, max_length=1024),
    _=Depends(require_super_admin),
) -> dict[str, Any]:
    """Recursively delete every object under `prefix`. Returns count of objects deleted."""
    acc = _resolve_account(account)
    _validate_bucket(bucket)
    if not prefix.endswith("/"):
        prefix = prefix + "/"
    _validate_key(prefix)

    deleted = 0
    try:
        async with s3_client(acc) as s3:
            continuation: str | None = None
            while True:
                kwargs: dict[str, Any] = {
                    "Bucket": bucket,
                    "Prefix": prefix,
                    "MaxKeys": 1000,
                }
                if continuation:
                    kwargs["ContinuationToken"] = continuation
                page = await s3.list_objects_v2(**kwargs)
                contents = page.get("Contents", [])
                if contents:
                    await s3.delete_objects(
                        Bucket=bucket,
                        Delete={"Objects": [{"Key": o["Key"]} for o in contents]},
                    )
                    deleted += len(contents)
                if not page.get("IsTruncated"):
                    break
                continuation = page.get("NextContinuationToken")
    except (ClientError, BotoCoreError) as exc:
        raise HTTPException(status_code=502, detail=f"S3 error: {exc}")

    return {"prefix": prefix, "deleted": deleted}
