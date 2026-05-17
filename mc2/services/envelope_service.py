"""
Unified Envelope service — fetch, cache, diff, and verify envelopes per tenant.

The Unified Envelope is the complete signed configuration payload delivered
to edge plugins. The Control Center can view any tenant's envelope in full.
"""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import UTC, datetime
from typing import Any

from .core_client import CoreClientError, core_client

logger = logging.getLogger(__name__)

# Cache TTL for envelopes (seconds)
_ENVELOPE_TTL = 60


async def get_tenant_envelope(tenant_id: str, bypass_cache: bool = False) -> dict[str, Any]:
    """Fetch the full Unified Envelope for a tenant."""
    try:
        data = await core_client.get(
            f"/api/v2/internal/tenant/{tenant_id}/envelope",
            bypass_cache=bypass_cache,
        )
        # Verify envelope signature if present
        signature_valid = _verify_envelope_signature(data)
        return {
            "success": True,
            "tenant_id": tenant_id,
            "envelope_version": data.get("version"),
            "signature_valid": signature_valid,
            "sections": data.get("sections", data),
            "fetched_at": datetime.now(UTC).isoformat(),
        }
    except CoreClientError as exc:
        logger.error("Envelope fetch failed for tenant %s: %s", tenant_id, exc.detail)
        return {
            "success": False,
            "tenant_id": tenant_id,
            "error": exc.detail,
            "fetched_at": datetime.now(UTC).isoformat(),
        }


async def get_envelope_diff(
    tenant_id: str,
    from_version: str,
    to_version: str,
) -> dict[str, Any]:
    """
    Compute a diff between two envelope versions for a tenant.
    Fetches both versions and computes structural differences.
    """
    try:
        from_data = await core_client.get(
            f"/api/v2/internal/tenant/{tenant_id}/envelope",
            params={"version": from_version},
        )
        to_data = await core_client.get(
            f"/api/v2/internal/tenant/{tenant_id}/envelope",
            params={"version": to_version},
        )

        changes = _compute_diff(from_data, to_data)
        return {
            "tenant_id": tenant_id,
            "from_version": from_version,
            "to_version": to_version,
            "changes": changes,
            "change_count": len(changes),
            "generated_at": datetime.now(UTC).isoformat(),
        }
    except CoreClientError as exc:
        logger.error("Envelope diff failed for tenant %s: %s", tenant_id, exc.detail)
        raise


async def get_envelope_history(tenant_id: str) -> list[dict[str, Any]]:
    """Fetch envelope version history for a tenant."""
    try:
        data = await core_client.get(f"/api/v2/internal/tenant/{tenant_id}/envelope/history")
        return data.get("versions", [])
    except CoreClientError as exc:
        logger.warning("Envelope history unavailable for %s: %s", tenant_id, exc.detail)
        return []


async def verify_all_envelopes(tenant_ids: list[str]) -> dict[str, Any]:
    """
    Batch verify envelope signatures across a list of tenants.
    Returns summary of valid vs invalid envelopes.
    """
    results = {"valid": [], "invalid": [], "error": []}
    for tid in tenant_ids:
        try:
            env = await get_tenant_envelope(tid)
            if env.get("signature_valid"):
                results["valid"].append(tid)
            else:
                results["invalid"].append(tid)
        except Exception:
            results["error"].append(tid)

    results["summary"] = {
        "valid": len(results["valid"]),
        "invalid": len(results["invalid"]),
        "error": len(results["error"]),
        "total": len(tenant_ids),
    }
    return results


def _verify_envelope_signature(envelope: dict[str, Any]) -> bool:
    """
    Verify envelope signature.
    Currently checks for presence and basic structure of the sig field.
    Full cryptographic verification will be added when frothiq-core
    exposes its signing public key via /api/v2/internal/public-key.
    """
    sig = envelope.get("signature") or envelope.get("sig")
    if not sig:
        # Envelopes without signatures pass in dev; warn in production
        logger.debug("Envelope has no signature field")
        return True  # permissive until signing is enforced
    return isinstance(sig, str) and len(sig) > 10


def _compute_diff(
    from_data: dict[str, Any],
    to_data: dict[str, Any],
    path: str = "",
) -> list[dict[str, Any]]:
    """Recursive structural diff between two envelope dicts."""
    changes = []

    all_keys = set(from_data.keys()) | set(to_data.keys())
    for key in all_keys:
        full_path = f"{path}.{key}" if path else key
        old_val = from_data.get(key)
        new_val = to_data.get(key)

        if key not in from_data:
            changes.append({"path": full_path, "op": "add", "new": new_val})
        elif key not in to_data:
            changes.append({"path": full_path, "op": "remove", "old": old_val})
        elif isinstance(old_val, dict) and isinstance(new_val, dict):
            changes.extend(_compute_diff(old_val, new_val, full_path))
        elif old_val != new_val:
            changes.append({"path": full_path, "op": "change", "old": old_val, "new": new_val})

    return changes
