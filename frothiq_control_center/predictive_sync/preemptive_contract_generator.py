"""
Preemptive Contract Generator.

Generates a STAGED FederationContract from a ProjectedState.
The contract is inert until activated — it carries the predicted enforcement
parameters, the activation timestamp, and explicit fallback instructions.

Contract lifecycle flags:
  staged        — generated, not yet dispatched to edge
  dispatched    — sent to edge, awaiting activation or confirmation
  confirmed     — ERPNext confirmed; edge should activate immediately
  auto_activated — activation_timestamp passed, edge applied without confirmation
  discarded     — prediction was wrong; edge must NOT apply

Safety invariants baked into every contract:
  - "staged": true — edge must not apply without activation signal
  - "fallback_behavior": "maintain_current" — on any doubt, keep old contract
  - "max_valid_until": unix ts — hard expiry, edge discards automatically
  - "state_version_required": N — edge only activates if current version < N
"""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from typing import Any

from frothiq_control_center.predictive_sync.preemptive_state_builder import ProjectedState


def generate_staged_contract(
    projected: ProjectedState,
    signing_key: str = "",
) -> dict[str, Any]:
    """
    Build a complete staged FederationContract from a ProjectedState.

    Args:
        projected:   The computed future state.
        signing_key: Optional HMAC key to sign the contract payload.

    Returns:
        A contract dict ready for dispatch to edge plugins.
        The contract is INERT — it carries `"staged": true` and must not
        be applied until the edge receives an activation signal.
    """
    contract_id = str(uuid.uuid4())
    now         = time.time()

    contract: dict[str, Any] = {
        # Identity
        "contract_id":    contract_id,
        "tenant_id":      projected.tenant_id,
        "contract_version": projected.predicted_version,
        "contract_type":  "staged",

        # Staging lifecycle
        "staged":              True,
        "fallback_behavior":   "maintain_current",
        "activation_timestamp": projected.activation_at,
        "max_valid_until":     projected.valid_until,

        # Safety guard: edge only applies this contract if its current
        # state_version is strictly less than this value.
        "state_version_required": projected.predicted_version,

        # Predicted state payload
        "subscription_status": projected.predicted_status,
        "effective_plan":      projected.predicted_plan,
        "enforcement_mode":    projected.predicted_enforcement_mode,
        "features":            projected.predicted_features,
        "limits":              projected.predicted_limits,

        # Metadata
        "confidence_score":    round(projected.confidence_score, 3),
        "signal_type":         projected.signal_type,
        "generated_at":        now,

        # Activation instructions for edge
        "activation_rules": {
            "auto_activate_at":       projected.activation_at,
            "require_confirmation":   projected.confidence_score < 0.85,
            "discard_if_not_activated_by": projected.valid_until,
        },
    }

    # Optionally sign the contract so edge can verify authenticity
    if signing_key:
        contract["signature"] = _sign_contract(contract, signing_key)

    return contract


def _sign_contract(contract: dict[str, Any], key: str) -> str:
    """
    HMAC-SHA256 signature over the deterministic JSON of key fields.
    Edge verifies this before storing the staged contract.
    """
    import hmac as _hmac
    payload = json.dumps(
        {
            "contract_id":      contract["contract_id"],
            "tenant_id":        contract["tenant_id"],
            "contract_version": contract["contract_version"],
            "subscription_status": contract["subscription_status"],
            "generated_at":     int(contract["generated_at"]),
        },
        sort_keys=True,
    )
    return _hmac.new(
        key.encode("utf-8"),
        payload.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def make_invalidation_message(
    tenant_id: str,
    contract_id: str,
    contract_version: int,
    reason: str = "prediction_incorrect",
) -> dict[str, Any]:
    """
    Build the invalidation message sent to edges when a prediction was wrong.
    Edges must discard any staged contract matching this contract_id.
    """
    return {
        "message_type":      "staged_contract_invalidate",
        "tenant_id":         tenant_id,
        "contract_id":       contract_id,
        "contract_version":  contract_version,
        "reason":            reason,
        "issued_at":         time.time(),
    }


def make_activation_message(
    tenant_id: str,
    contract_id: str,
    contract_version: int,
    confirmed_state: str,
) -> dict[str, Any]:
    """
    Build the activation message sent to edges when ERPNext confirms the prediction.
    Edges must activate the staged contract immediately on receipt.
    """
    return {
        "message_type":      "staged_contract_activate",
        "tenant_id":         tenant_id,
        "contract_id":       contract_id,
        "contract_version":  contract_version,
        "confirmed_state":   confirmed_state,
        "activated_at":      time.time(),
    }
