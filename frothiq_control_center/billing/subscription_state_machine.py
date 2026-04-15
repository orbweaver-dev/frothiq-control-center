"""
Subscription State Machine — pure logic, no I/O.

Defines the valid subscription lifecycle states and the monotonic
transition rules that prevent illegal state regressions.

State flow:
    TRIAL → ACTIVE → PAST_DUE → SUSPENDED → CANCELED → EXPIRED
                ↑←←←←←←←← (reactivation via payment)
                    PAST_DUE → ACTIVE (payment received)
                    SUSPENDED → ACTIVE (payment received)

CANCELED and EXPIRED are terminal; only an explicit ERPNext
administrator action can reopen a CANCELED tenant.
"""

from __future__ import annotations

import time
from enum import Enum
from typing import NamedTuple


class SubscriptionState(str, Enum):
    TRIAL = "trial"
    ACTIVE = "active"
    PAST_DUE = "past_due"
    SUSPENDED = "suspended"
    CANCELED = "canceled"
    EXPIRED = "expired"


# State rank — higher rank = further along the degradation path.
# A transition is "forward" if new_rank > current_rank.
# Backward transitions (reactivation) are explicitly allowed in ALLOWED_TRANSITIONS.
_STATE_RANK: dict[SubscriptionState, int] = {
    SubscriptionState.TRIAL: 0,
    SubscriptionState.ACTIVE: 1,
    SubscriptionState.PAST_DUE: 2,
    SubscriptionState.SUSPENDED: 3,
    SubscriptionState.CANCELED: 4,
    SubscriptionState.EXPIRED: 5,
}

# Explicit allowed transitions (from → {allowed targets}).
# Any transition not in this map is rejected.
_ALLOWED_TRANSITIONS: dict[SubscriptionState, set[SubscriptionState]] = {
    SubscriptionState.TRIAL: {
        SubscriptionState.ACTIVE,
        SubscriptionState.CANCELED,
        SubscriptionState.EXPIRED,
    },
    SubscriptionState.ACTIVE: {
        SubscriptionState.PAST_DUE,
        SubscriptionState.CANCELED,
        SubscriptionState.EXPIRED,
    },
    SubscriptionState.PAST_DUE: {
        SubscriptionState.ACTIVE,      # payment received
        SubscriptionState.SUSPENDED,
        SubscriptionState.CANCELED,
        SubscriptionState.EXPIRED,
    },
    SubscriptionState.SUSPENDED: {
        SubscriptionState.ACTIVE,      # admin reactivation / payment
        SubscriptionState.CANCELED,
        SubscriptionState.EXPIRED,
    },
    SubscriptionState.CANCELED: {
        SubscriptionState.ACTIVE,      # explicit admin reopen only
    },
    SubscriptionState.EXPIRED: {
        SubscriptionState.ACTIVE,      # renewal
    },
}


class TransitionResult(NamedTuple):
    accepted: bool
    from_state: SubscriptionState
    to_state: SubscriptionState
    reason: str


def validate_transition(
    current: SubscriptionState,
    proposed: SubscriptionState,
) -> TransitionResult:
    """
    Check whether a proposed state transition is valid.

    Returns a TransitionResult with accepted=True if allowed.
    Never raises — callers can inspect .accepted and .reason.
    """
    if current == proposed:
        return TransitionResult(
            accepted=True,
            from_state=current,
            to_state=proposed,
            reason="no-op: same state",
        )

    allowed = _ALLOWED_TRANSITIONS.get(current, set())
    if proposed in allowed:
        return TransitionResult(
            accepted=True,
            from_state=current,
            to_state=proposed,
            reason=f"{current.value} → {proposed.value}",
        )

    return TransitionResult(
        accepted=False,
        from_state=current,
        to_state=proposed,
        reason=(
            f"illegal transition: {current.value} → {proposed.value}; "
            f"allowed: {', '.join(s.value for s in allowed) or 'none'}"
        ),
    )


def apply_event(
    current_state: SubscriptionState,
    current_version: int,
    event_state: SubscriptionState,
    event_source: str = "webhook",
) -> tuple[SubscriptionState, int, str]:
    """
    Apply a billing event to the current state.

    Args:
        current_state:   The tenant's current SubscriptionState.
        current_version: The current monotonic version counter.
        event_state:     The state proposed by the incoming event.
        event_source:    Label for logging ('webhook', 'pull', 'fallback').

    Returns:
        (new_state, new_version, log_message)

    The version is incremented on every accepted transition (including no-op,
    to signal that the event was processed even if state didn't change).
    """
    result = validate_transition(current_state, event_state)
    if result.accepted:
        new_version = current_version + 1
        msg = f"[{event_source}] state v{new_version}: {result.reason}"
        return event_state, new_version, msg
    else:
        msg = (
            f"[{event_source}] REJECTED v{current_version}: {result.reason}"
        )
        return current_state, current_version, msg


def erpnext_status_to_state(erpnext_status: str) -> SubscriptionState:
    """
    Map an ERPNext Subscription.status value to a SubscriptionState.

    ERPNext statuses:
        Active, Past Due Date, Cancelled, Trialling, Unpaid
    """
    mapping = {
        "active":        SubscriptionState.ACTIVE,
        "trialling":     SubscriptionState.TRIAL,
        "trial":         SubscriptionState.TRIAL,
        "past due date": SubscriptionState.PAST_DUE,
        "past_due":      SubscriptionState.PAST_DUE,
        "unpaid":        SubscriptionState.PAST_DUE,
        "suspended":     SubscriptionState.SUSPENDED,
        "cancelled":     SubscriptionState.CANCELED,
        "canceled":      SubscriptionState.CANCELED,
        "expired":       SubscriptionState.EXPIRED,
    }
    return mapping.get((erpnext_status or "").lower().strip(), SubscriptionState.ACTIVE)


def grace_period_active(grace_until: float | None) -> bool:
    """Return True if the tenant is within a grace period (still has access)."""
    if grace_until is None:
        return False
    return time.time() < grace_until
