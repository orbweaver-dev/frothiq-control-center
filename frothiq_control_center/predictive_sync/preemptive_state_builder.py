"""
Preemptive State Builder.

Simulates the future billing state that will result from a detected signal,
using the current MC3 state + billing subscription state machine rules.

Outputs a ProjectedState with full enforcement parameters computed.
Only the state machine transition rules defined in subscription_state_machine.py
are used — no billing logic is introduced here.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from frothiq_control_center.billing.subscription_state_machine import (
    SubscriptionState,
    validate_transition,
)
from frothiq_control_center.predictive_sync.predictive_signal_detector import (
    PredictiveSignal,
    SignalType,
)

# Enforcement mode per predicted state
_ENFORCEMENT_MAP: dict[str, str] = {
    "trial":     "alert_only",
    "active":    "alert_only",
    "past_due":  "optional_block",
    "suspended": "auto_block",
    "canceled":  "auto_block",
    "expired":   "auto_block",
}

# Feature set per plan (mirrors PlanEntitlementMapper)
_FEATURE_MAP: dict[str, dict[str, bool]] = {
    "free":       {"waf": True,  "rate_limiting": True,  "geo_blocking": False, "ai_detection": False},
    "pro":        {"waf": True,  "rate_limiting": True,  "geo_blocking": True,  "ai_detection": False},
    "enterprise": {"waf": True,  "rate_limiting": True,  "geo_blocking": True,  "ai_detection": True},
}

# Predicted contract TTL: staged contract is valid for at most this many seconds
MAX_CONTRACT_VALID_SEC = 86400   # 24 hours absolute ceiling


@dataclass
class ProjectedState:
    tenant_id:          str
    predicted_status:   str
    predicted_plan:     str
    predicted_enforcement_mode: str
    predicted_features: dict[str, bool]
    predicted_limits:   dict[str, int]
    confidence_score:   float
    predicted_version:  int          # current version + 1
    valid_until:        float        # unix ts — hard expiry of this projection
    activation_at:      float        # unix ts — when the transition is expected
    signal_type:        str
    source_state:       dict[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return {
            "tenant_id":                   self.tenant_id,
            "predicted_status":            self.predicted_status,
            "predicted_plan":              self.predicted_plan,
            "predicted_enforcement_mode":  self.predicted_enforcement_mode,
            "predicted_features":          self.predicted_features,
            "predicted_limits":            self.predicted_limits,
            "confidence_score":            round(self.confidence_score, 3),
            "predicted_version":           self.predicted_version,
            "valid_until":                 self.valid_until,
            "activation_at":               self.activation_at,
            "signal_type":                 self.signal_type,
        }


def build_projected_state(
    current_state: dict[str, Any],
    signal: PredictiveSignal,
) -> ProjectedState | None:
    """
    Compute the projected future billing state for a tenant given a signal.

    Returns None if the state machine rejects the predicted transition
    (safety: never project an illegal state).
    """
    current_status = (current_state.get("subscription_status") or "active").lower()
    predicted_to   = signal.expected_transition_to

    # For plan upgrade signals, the state stays "active" but plan changes
    if signal.signal_type == SignalType.PLAN_UPGRADE_INITIATED:
        predicted_plan = _extract_plan_from_transition(signal.expected_transition_to)
        predicted_status = "active"
    else:
        predicted_status = predicted_to.split("/")[0]    # normalise "active/pro" → "active"
        predicted_plan   = (current_state.get("effective_plan") or "free").lower()

    # Validate via state machine — reject illegal projections
    try:
        from_state = SubscriptionState(current_status)
        to_state   = SubscriptionState(predicted_status)
        result     = validate_transition(from_state, to_state)
        if not result.accepted and predicted_status != current_status:
            return None     # State machine rejects — don't build a contract
    except ValueError:
        return None         # Unknown state — do not speculate

    current_version = int(current_state.get("state_version") or 0)
    now             = time.time()

    enforcement = _ENFORCEMENT_MAP.get(predicted_status, "alert_only")
    features    = _FEATURE_MAP.get(predicted_plan, _FEATURE_MAP["free"]).copy()

    # Limit set: keep current limits unless plan changes
    if signal.signal_type == SignalType.PLAN_UPGRADE_INITIATED:
        limits = _compute_limits(predicted_plan)
    else:
        limits = current_state.get("limits") or _compute_limits(predicted_plan)

    # valid_until = min(signal window end, now + MAX_CONTRACT_VALID_SEC)
    valid_until = min(
        signal.expected_window_end + 3600,   # small buffer after window
        now + MAX_CONTRACT_VALID_SEC,
    )

    return ProjectedState(
        tenant_id=signal.tenant_id,
        predicted_status=predicted_status,
        predicted_plan=predicted_plan,
        predicted_enforcement_mode=enforcement,
        predicted_features=features,
        predicted_limits=limits,
        confidence_score=signal.confidence_score,
        predicted_version=current_version + 1,
        valid_until=valid_until,
        activation_at=signal.expected_window_start,
        signal_type=signal.signal_type.value,
        source_state=current_state,
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract_plan_from_transition(transition_to: str) -> str:
    """Parse 'active/pro' → 'pro', fall back to 'free'."""
    parts = transition_to.split("/")
    if len(parts) == 2:
        return parts[1].lower()
    return "free"


def _compute_limits(plan: str) -> dict[str, int]:
    limits_map = {
        "free":       {"requests_per_minute": 60,   "blocked_ips": 100,   "rule_count": 10},
        "pro":        {"requests_per_minute": 600,  "blocked_ips": 5000,  "rule_count": 100},
        "enterprise": {"requests_per_minute": 6000, "blocked_ips": 50000, "rule_count": 1000},
    }
    return limits_map.get(plan, limits_map["free"])
