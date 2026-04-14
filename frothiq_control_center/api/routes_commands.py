"""
Command Proxy Router — frothiq-control-center

The Control Center may NOT mutate system state directly.
All state-mutating operations are dispatched as signed commands to
frothiq-core via the gateway. This router:

  1. Validates the command type against the allowed set
  2. Applies RBAC — only super_admin and security_analyst may issue commands
  3. Signs the outbound request with HMAC-SHA256 using the gateway signing key
  4. Forwards the command to core via the gateway
  5. Returns a CommandReceipt — commands are ACKNOWLEDGED, never executed locally

The gateway then validates the signature before forwarding to core.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import time
import uuid
from typing import Any, Literal, Optional

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from frothiq_control_center.auth.dependencies import require_role
from frothiq_control_center.auth.jwt_handler import TokenData
from frothiq_control_center.config import get_settings
from frothiq_control_center.services.audit_service import log_action

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/commands", tags=["commands"])

# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------

CommandType = Literal[
    "trigger_policy_rollout",
    "revoke_license",
    "restore_license",
    "force_license_sync",
    "force_cluster_propagation",
    "run_simulation",
    "refresh_envelope",
    "block_ip",
    "unblock_ip",
    "rollback_policy",
]

_GATEWAY_ROUTES: set[str] = {
    "force_cluster_propagation",
    "block_ip",
    "unblock_ip",
}

_CORE_COMMAND_MAP: dict[str, str] = {
    "trigger_policy_rollout":    "/api/v2/policy/rollout",
    "revoke_license":            "/api/v2/internal/tenant/{target_id}/revoke",
    "restore_license":           "/api/v2/internal/tenant/{target_id}/restore",
    "force_license_sync":        "/api/v2/internal/tenant/{target_id}/sync",
    "force_cluster_propagation": "/api/v2/defense/global/propagate",
    "run_simulation":            "/api/v2/simulation/run",
    "refresh_envelope":          "/api/v2/envelope/{target_id}/refresh",
    "block_ip":                  "/api/v2/intelligence/response/block",
    "unblock_ip":                "/api/v2/intelligence/response/unblock/{target_id}",
    "rollback_policy":           "/api/v2/policy/{target_id}/rollback",
}


class CommandRequest(BaseModel):
    command: CommandType
    target_id: Optional[str] = None
    parameters: dict[str, Any] = Field(default_factory=dict)
    idempotency_key: Optional[str] = None


class CommandReceipt(BaseModel):
    receipt_id: str
    command: str
    status: Literal["acknowledged", "queued", "executing", "completed", "failed"]
    acknowledged_at: float
    target_id: Optional[str] = None
    estimated_seconds: Optional[int] = None
    error: Optional[str] = None


# ---------------------------------------------------------------------------
# In-memory receipt store (production: use Redis)
# ---------------------------------------------------------------------------

_receipts: dict[str, dict[str, Any]] = {}


# ---------------------------------------------------------------------------
# Signature helper
# ---------------------------------------------------------------------------

def _sign_command(method: str, path: str, ts: str, key: str) -> str:
    """HMAC-SHA256 signature for gateway validation."""
    payload = f"{method}:{path}:{ts}".encode()
    return hmac.new(key.encode(), payload, hashlib.sha256).hexdigest()


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.post("", response_model=CommandReceipt, status_code=202)
async def dispatch_command(
    cmd: CommandRequest,
    request: Request,
    current_user: TokenData = Depends(require_role("security_analyst")),
):
    """
    Dispatch a state-mutating command to frothiq-core via the gateway.

    Returns a CommandReceipt (HTTP 202 Accepted). The command is queued
    and forwarded asynchronously — the caller polls /commands/{receipt_id}
    for completion.
    """
    settings = get_settings()
    receipt_id = str(uuid.uuid4())
    idempotency_key = cmd.idempotency_key or f"{cmd.command}:{cmd.target_id}:{receipt_id}"

    # Build upstream path
    path_template = _CORE_COMMAND_MAP.get(cmd.command)
    if not path_template:
        raise HTTPException(status_code=400, detail=f"Unknown command: {cmd.command}")

    upstream_path = path_template.format(target_id=cmd.target_id or "")

    # Determine route (gateway → core, or gateway → edge)
    route = "gateway" if cmd.command in _GATEWAY_ROUTES else "core"
    base_url = settings.gateway_url

    # Build signed request headers
    ts = str(int(time.time()))
    sig = _sign_command("POST", upstream_path, ts, settings.gateway_signing_key)

    headers = {
        "Content-Type": "application/json",
        "X-CC-Sig": sig,
        "X-CC-Ts": ts,
        "X-CC-Receipt-Id": receipt_id,
        "X-CC-Command": cmd.command,
        "X-CC-User": current_user.user_id,
        "X-CC-Role": current_user.role,
        "X-Idempotency-Key": idempotency_key,
        "X-Forwarded-By": "frothiq-control-center",
    }

    body: dict[str, Any] = {
        **cmd.parameters,
        "_command": cmd.command,
        "_receipt_id": receipt_id,
        "_issued_by": current_user.user_id,
        "_issued_at": ts,
    }
    if cmd.target_id:
        body["target_id"] = cmd.target_id

    # Store receipt optimistically
    receipt: dict[str, Any] = {
        "receipt_id": receipt_id,
        "command": cmd.command,
        "status": "acknowledged",
        "acknowledged_at": time.time(),
        "target_id": cmd.target_id,
        "estimated_seconds": _estimate_seconds(cmd.command),
    }
    _receipts[receipt_id] = receipt

    # Log to audit trail
    await log_action(
        db=request.state.db,
        redis=request.state.redis,
        action=f"command:{cmd.command}",
        user_id=current_user.user_id,
        user_email=getattr(current_user, "email", ""),
        resource=cmd.target_id,
        detail=f"receipt_id={receipt_id}",
        ip_address=request.client.host if request.client else None,
    )

    # Dispatch to gateway asynchronously (don't block the receipt response)
    import asyncio
    asyncio.create_task(
        _forward_to_gateway(
            receipt_id=receipt_id,
            base_url=base_url,
            upstream_path=upstream_path,
            headers=headers,
            body=body,
        )
    )

    return CommandReceipt(**receipt)


@router.get("/{receipt_id}", response_model=CommandReceipt)
async def get_command_receipt(
    receipt_id: str,
    current_user: TokenData = Depends(require_role("read_only")),
):
    """Poll for the execution status of a dispatched command."""
    receipt = _receipts.get(receipt_id)
    if not receipt:
        raise HTTPException(status_code=404, detail="Receipt not found")
    return CommandReceipt(**receipt)


# ---------------------------------------------------------------------------
# Async dispatch
# ---------------------------------------------------------------------------

async def _forward_to_gateway(
    receipt_id: str,
    base_url: str,
    upstream_path: str,
    headers: dict,
    body: dict,
) -> None:
    """Forward the command to the gateway and update receipt status."""
    _receipts[receipt_id]["status"] = "queued"

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            _receipts[receipt_id]["status"] = "executing"
            resp = await client.post(
                f"{base_url}/control-center{upstream_path}",
                headers=headers,
                json=body,
            )
            if resp.status_code < 300:
                _receipts[receipt_id]["status"] = "completed"
                _receipts[receipt_id]["result"] = resp.json()
                logger.info(
                    "Command %s (receipt %s) completed — upstream %d",
                    body.get("_command"), receipt_id, resp.status_code,
                )
            else:
                _receipts[receipt_id]["status"] = "failed"
                _receipts[receipt_id]["error"] = f"Upstream {resp.status_code}: {resp.text[:200]}"
                logger.warning(
                    "Command %s (receipt %s) failed — upstream %d",
                    body.get("_command"), receipt_id, resp.status_code,
                )

    except Exception as exc:
        _receipts[receipt_id]["status"] = "failed"
        _receipts[receipt_id]["error"] = str(exc)
        logger.error("Command dispatch error for receipt %s: %s", receipt_id, exc)


def _estimate_seconds(command: str) -> int:
    return {
        "trigger_policy_rollout": 5,
        "revoke_license": 2,
        "restore_license": 2,
        "force_license_sync": 10,
        "force_cluster_propagation": 8,
        "run_simulation": 30,
        "refresh_envelope": 3,
        "block_ip": 1,
        "unblock_ip": 1,
        "rollback_policy": 4,
    }.get(command, 5)
