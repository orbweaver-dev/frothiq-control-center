"""
Preemptive Contract Generator.

Generates a STAGED FederationContract from a ProjectedState.
The contract is inert until activated — it carries the predicted enforcement
parameters, the activation timestamp, and explicit fallback instructions.

Contract lifecycle:
  staged → dispatched → confirmed          (ERPNext confirmed match)
                      → discarded          (prediction incorrect or replaced)
                      → expired            (max_valid_until passed)
                      → replaced           (superseded by newer prediction)

Safety invariants (Rule 1 + Rule 3 + Rule 6)
─────────────────────────────────────────────
  1. require_confirmation = True UNLESS conf ≥ 0.85 AND transition is MORE RESTRICTIVE
  2. activation_guard block carries all edge validation conditions
  3. priority block encodes fail-safe precedence (confirmed > staged > current)
  4. fallback_behavior = "maintain_current" — on any doubt, keep old contract
  5. max_valid_until — hard 24h expiry; edge discards automatically
  6. state_version_required — edge only activates if its current version < N
"""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from typing import Any

from frothiq_control_center.predictive_sync.preemptive_state_builder import ProjectedState


# ---------------------------------------------------------------------------
# Rule 1 — Restrictive order definition
# ---------------------------------------------------------------------------

# Higher rank = more restrictive enforcement
RESTRICTIVE_ORDER: dict[str, int] = {
    "trial":     0,
    "active":    1,
    "past_due":  2,
    "suspended": 3,
    "canceled":  4,
    "expired":   5,
}


def is_more_restrictive(from_state: str, to_state: str) -> bool:
    """
    Return True if *to_state* enforces stricter controls than *from_state*.

    ACTIVE < PAST_DUE < SUSPENDED < EXPIRED (ascending restriction)

    Only transitions that move UP the order are considered more restrictive.
    Lateral moves (same rank) and downward moves require explicit confirmation.
    """
    from_rank = RESTRICTIVE_ORDER.get((from_state or "").lower(), 1)
    to_rank   = RESTRICTIVE_ORDER.get((to_state   or "").lower(), 1)
    return to_rank > from_rank


def requires_confirmation(
    from_state: str,
    to_state: str,
    confidence_score: float,
) -> bool:
    """
    Determine whether this contract must wait for ERPNext confirmation
    before an edge is allowed to auto-activate it.

    Rule 1:
      Auto-activation ONLY when BOTH:
        - confidence_score >= 0.85
        - predicted_state is MORE RESTRICTIVE than current_state

    In all other cases require_confirmation = True.
    This prevents premature plan downgrades or false "upgrade" activations.
    """
    if confidence_score >= 0.85 and is_more_restrictive(from_state, to_state):
        return False    # safe to auto-activate
    return True         # must wait for explicit confirmation


# ---------------------------------------------------------------------------
# Contract generator
# ---------------------------------------------------------------------------

def generate_staged_contract(
    projected: ProjectedState,
    signing_key: str = "",
) -> dict[str, Any]:
    """
    Build a complete staged FederationContract from a ProjectedState.

    The contract is INERT on receipt — it carries `"staged": true` and must
    not be applied until the edge receives an activation signal OR the
    auto-activation conditions are satisfied.

    Rules enforced:
      Rule 1 — require_confirmation derived from restrictiveness check
      Rule 3 — activation_guard block with all edge validation conditions
      Rule 6 — priority block encoding fail-safe precedence
    """
    contract_id  = str(uuid.uuid4())
    now          = time.time()
    from_state   = (
        projected.source_state.get("subscription_status") or "active"
    ).lower()
    req_confirm  = requires_confirmation(
        from_state, projected.predicted_status, projected.confidence_score
    )

    contract: dict[str, Any] = {
        # ── Identity ────────────────────────────────────────────────────
        "contract_id":      contract_id,
        "tenant_id":        projected.tenant_id,
        "contract_version": projected.predicted_version,
        "contract_type":    "staged",

        # ── Staging lifecycle ───────────────────────────────────────────
        "staged":             True,
        "fallback_behavior":  "maintain_current",
        "activation_timestamp": projected.activation_at,
        "max_valid_until":    projected.valid_until,

        # ── Predicted state payload ─────────────────────────────────────
        "subscription_status": projected.predicted_status,
        "effective_plan":      projected.predicted_plan,
        "enforcement_mode":    projected.predicted_enforcement_mode,
        "features":            projected.predicted_features,
        "limits":              projected.predicted_limits,

        # ── Metadata ────────────────────────────────────────────────────
        "confidence_score": round(projected.confidence_score, 3),
        "signal_type":      projected.signal_type,
        "generated_at":     now,
        "transition_from":  from_state,
        "transition_to":    projected.predicted_status,
        "is_more_restrictive": is_more_restrictive(from_state, projected.predicted_status),

        # ── Rule 1: activation instructions ─────────────────────────────
        "activation_rules": {
            "auto_activate_at":       projected.activation_at,
            "require_confirmation":   req_confirm,
            "discard_if_not_activated_by": projected.valid_until,
        },

        # ── Rule 3: activation guard — edge validates ALL before applying
        "activation_guard": {
            "contract_version_gt_current":  True,       # contract_version > edge.current_version
            "not_expired":                  True,       # time.now() < max_valid_until
            "not_invalidated":              True,       # no INVALIDATE message received for this contract_id
            "tenant_id_matches":            True,       # contract.tenant_id == edge.tenant_id
            "staged_flag_cleared":          True,       # only after ACTIVATE or auto-activate
            "state_version_required":       projected.predicted_version,
        },

        # ── Rule 6: fail-safe priority hierarchy ─────────────────────────
        "priority": 2,    # 1=confirmed, 2=staged, 3=current
        "fail_safe": {
            "priority_order": ["confirmed", "staged", "current"],
            "on_conflict":    "prefer_higher_priority",
            "never_downgrade_from_confirmed": True,
            "never_override_confirmed_state": True,
        },
    }

    # Sign so edges can verify authenticity before storing
    if signing_key:
        contract["signature"] = _sign_contract(contract, signing_key)

    return contract


# ---------------------------------------------------------------------------
# Signing
# ---------------------------------------------------------------------------

def _sign_contract(contract: dict[str, Any], key: str) -> str:
    """HMAC-SHA256 over canonical key fields."""
    import hmac as _hmac
    payload = json.dumps(
        {
            "contract_id":        contract["contract_id"],
            "tenant_id":          contract["tenant_id"],
            "contract_version":   contract["contract_version"],
            "subscription_status": contract["subscription_status"],
            "generated_at":       int(contract["generated_at"]),
            "transition_from":    contract["transition_from"],
            "transition_to":      contract["transition_to"],
        },
        sort_keys=True,
    )
    return _hmac.new(
        key.encode("utf-8"),
        payload.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


# ---------------------------------------------------------------------------
# Control messages
# ---------------------------------------------------------------------------

def make_invalidation_message(
    tenant_id: str,
    contract_id: str,
    contract_version: int,
    reason: str = "prediction_incorrect",
) -> dict[str, Any]:
    """
    Build the invalidation message sent to edges when a prediction was wrong
    or a contract is replaced (Rule 2).
    Edge must discard any staged contract matching this contract_id.
    """
    return {
        "message_type":     "staged_contract_invalidate",
        "tenant_id":        tenant_id,
        "contract_id":      contract_id,
        "contract_version": contract_version,
        "reason":           reason,
        "priority":         1,   # invalidations always highest priority
        "issued_at":        time.time(),
    }


def make_activation_message(
    tenant_id: str,
    contract_id: str,
    contract_version: int,
    confirmed_state: str,
) -> dict[str, Any]:
    """
    Build the activation message sent to edges when ERPNext confirms the prediction.
    Edge must activate the staged contract immediately on receipt.
    """
    return {
        "message_type":     "staged_contract_activate",
        "tenant_id":        tenant_id,
        "contract_id":      contract_id,
        "contract_version": contract_version,
        "confirmed_state":  confirmed_state,
        "priority":         1,   # activations always highest priority
        "activated_at":     time.time(),
    }
