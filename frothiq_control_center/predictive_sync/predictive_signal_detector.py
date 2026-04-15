"""
Predictive Signal Detector.

Analyses cached billing state and optional ERPNext data to detect early
indicators of an upcoming subscription state transition.

Signal taxonomy
───────────────
SIGNAL                       TRIGGER                                CONFIDENCE RANGE
invoice_due_soon             expiry in ≤ 3 days                    0.70 – 0.92
invoice_generated            expiry in 4–14 days                   0.55 – 0.70
payment_retry_scheduled      status=past_due, last_updated recent  0.60 – 0.80
subscription_near_expiry     expiry in ≤ 7 days, no grace           0.75 – 0.88
grace_period_expiring        grace_until in ≤ 2 days               0.85 – 0.95
plan_upgrade_initiated       plan_upgrade flag in ERPNext           0.65 – 0.85
suspension_imminent          past_due + age ≥ 3 days               0.72 – 0.88
"""

from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import httpx

from frothiq_control_center.billing.license_state_cache import (
    get_all_billing_states,
    get_billing_state,
)

logger = logging.getLogger(__name__)

_FRAPPE_BASE    = os.getenv("FRAPPE_SITE_URL", "http://localhost:8000")
_FRAPPE_API_KEY = os.getenv("FRAPPE_API_KEY", "")
_FRAPPE_API_SEC = os.getenv("FRAPPE_API_SECRET", "")

# Confidence thresholds
CONFIDENCE_ACT_THRESHOLD = 0.70   # minimum to generate a staged contract


class SignalType(str, Enum):
    INVOICE_DUE_SOON           = "invoice_due_soon"
    INVOICE_GENERATED          = "invoice_generated"
    PAYMENT_RETRY_SCHEDULED    = "payment_retry_scheduled"
    SUBSCRIPTION_NEAR_EXPIRY   = "subscription_near_expiry"
    GRACE_PERIOD_EXPIRING      = "grace_period_expiring"
    PLAN_UPGRADE_INITIATED     = "plan_upgrade_initiated"
    SUSPENSION_IMMINENT        = "suspension_imminent"


@dataclass
class PredictiveSignal:
    tenant_id:                str
    signal_type:              SignalType
    confidence_score:         float           # 0.0 – 1.0
    expected_transition_from: str             # current state
    expected_transition_to:   str             # predicted next state
    expected_window_start:    float           # unix ts: earliest activation
    expected_window_end:      float           # unix ts: latest activation
    source_data:              dict[str, Any] = field(default_factory=dict)
    detected_at:              float           = field(default_factory=time.time)

    @property
    def actionable(self) -> bool:
        return self.confidence_score >= CONFIDENCE_ACT_THRESHOLD

    def as_dict(self) -> dict[str, Any]:
        return {
            "tenant_id":                self.tenant_id,
            "signal_type":              self.signal_type.value,
            "confidence_score":         round(self.confidence_score, 3),
            "expected_transition_from": self.expected_transition_from,
            "expected_transition_to":   self.expected_transition_to,
            "expected_window_start":    self.expected_window_start,
            "expected_window_end":      self.expected_window_end,
            "detected_at":              self.detected_at,
            "actionable":               self.actionable,
        }


# ---------------------------------------------------------------------------
# Public: detect signals for one tenant
# ---------------------------------------------------------------------------

async def detect_signals_for_tenant(tenant_id: str) -> list[PredictiveSignal]:
    """
    Analyse a single tenant's cached billing state and optional ERPNext
    supplementary data to produce zero or more PredictiveSignals.
    """
    state = await get_billing_state(tenant_id)
    if not state:
        return []

    signals: list[PredictiveSignal] = []
    now = time.time()

    status       = (state.get("subscription_status") or "active").lower()
    expiry       = state.get("expiry")
    grace_until  = state.get("grace_until")
    last_updated = float(state.get("last_updated") or 0)
    plan         = (state.get("effective_plan") or "free").lower()

    # ── 1. SUBSCRIPTION_NEAR_EXPIRY ────────────────────────────────────
    if expiry and status in ("active", "trial"):
        time_to_expiry = expiry - now
        if 0 < time_to_expiry <= 3 * 86400:          # ≤ 3 days
            conf = _lerp(time_to_expiry, 3 * 86400, 0, 0.92, 0.75)
            signals.append(PredictiveSignal(
                tenant_id=tenant_id,
                signal_type=SignalType.SUBSCRIPTION_NEAR_EXPIRY,
                confidence_score=conf,
                expected_transition_from=status,
                expected_transition_to="expired",
                expected_window_start=max(now, expiry - 3600),
                expected_window_end=expiry + 86400,
                source_data={"expiry": expiry, "time_to_expiry_s": time_to_expiry},
            ))
        elif 3 * 86400 < time_to_expiry <= 7 * 86400:  # 3–7 days
            conf = _lerp(time_to_expiry, 7 * 86400, 3 * 86400, 0.65, 0.75)
            signals.append(PredictiveSignal(
                tenant_id=tenant_id,
                signal_type=SignalType.INVOICE_GENERATED,
                confidence_score=conf,
                expected_transition_from=status,
                expected_transition_to="past_due",
                expected_window_start=expiry - 86400,
                expected_window_end=expiry + 2 * 86400,
                source_data={"expiry": expiry},
            ))

    # ── 2. INVOICE_DUE_SOON (expiry ≤ 3 days, non-trial) ──────────────
    if expiry and status == "active" and plan != "free":
        time_to_expiry = expiry - now
        if 0 < time_to_expiry <= 3 * 86400:
            conf = _lerp(time_to_expiry, 3 * 86400, 0, 0.92, 0.80)
            signals.append(PredictiveSignal(
                tenant_id=tenant_id,
                signal_type=SignalType.INVOICE_DUE_SOON,
                confidence_score=conf,
                expected_transition_from="active",
                expected_transition_to="past_due",
                expected_window_start=max(now, expiry - 7200),
                expected_window_end=expiry + 3 * 86400,
                source_data={"expiry": expiry, "plan": plan},
            ))

    # ── 3. GRACE_PERIOD_EXPIRING ───────────────────────────────────────
    if grace_until and status in ("past_due", "suspended"):
        time_to_grace_end = grace_until - now
        if 0 < time_to_grace_end <= 2 * 86400:
            conf = _lerp(time_to_grace_end, 2 * 86400, 0, 0.95, 0.85)
            next_state = "suspended" if status == "past_due" else "canceled"
            signals.append(PredictiveSignal(
                tenant_id=tenant_id,
                signal_type=SignalType.GRACE_PERIOD_EXPIRING,
                confidence_score=conf,
                expected_transition_from=status,
                expected_transition_to=next_state,
                expected_window_start=max(now, grace_until - 3600),
                expected_window_end=grace_until + 86400,
                source_data={"grace_until": grace_until},
            ))

    # ── 4. PAYMENT_RETRY_SCHEDULED ─────────────────────────────────────
    if status == "past_due":
        age_s = now - last_updated
        # Confidence rises as past_due age increases (retry logic kicks in)
        conf = min(0.80, 0.60 + (age_s / 86400) * 0.05)
        signals.append(PredictiveSignal(
            tenant_id=tenant_id,
            signal_type=SignalType.PAYMENT_RETRY_SCHEDULED,
            confidence_score=conf,
            expected_transition_from="past_due",
            expected_transition_to="active",      # optimistic: payment succeeds
            expected_window_start=now,
            expected_window_end=now + 7 * 86400,
            source_data={"past_due_age_s": age_s},
        ))

    # ── 5. SUSPENSION_IMMINENT ─────────────────────────────────────────
    if status == "past_due":
        age_s = now - last_updated
        if age_s >= 3 * 86400:   # past_due for ≥ 3 days → suspension likely
            conf = min(0.88, 0.72 + (age_s / 86400 - 3) * 0.04)
            signals.append(PredictiveSignal(
                tenant_id=tenant_id,
                signal_type=SignalType.SUSPENSION_IMMINENT,
                confidence_score=conf,
                expected_transition_from="past_due",
                expected_transition_to="suspended",
                expected_window_start=now,
                expected_window_end=now + 2 * 86400,
                source_data={"past_due_age_days": round(age_s / 86400, 1)},
            ))

    # ── 6. PLAN_UPGRADE_INITIATED (from optional ERPNext poll) ─────────
    upgrade_signal = await _poll_erp_upgrade(tenant_id, state)
    if upgrade_signal:
        signals.append(upgrade_signal)

    # Filter to actionable only
    return [s for s in signals if s.confidence_score >= CONFIDENCE_ACT_THRESHOLD]


async def detect_signals_all_tenants() -> list[PredictiveSignal]:
    """Run signal detection for all known tenants."""
    import asyncio
    states = await get_all_billing_states()
    tasks  = [detect_signals_for_tenant(s["tenant_id"]) for s in states]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    out: list[PredictiveSignal] = []
    for r in results:
        if isinstance(r, list):
            out.extend(r)
    return out


# ---------------------------------------------------------------------------
# ERPNext poll for upgrade signals
# ---------------------------------------------------------------------------

async def _poll_erp_upgrade(
    tenant_id: str,
    cached_state: dict[str, Any],
) -> PredictiveSignal | None:
    """
    Optional HTTP call to ERPNext to check for an in-progress plan upgrade.
    Returns None if ERPNext is unreachable or no upgrade found.
    """
    if not _FRAPPE_API_KEY:
        return None
    url    = f"{_FRAPPE_BASE}/api/method/frothiq_frappe.frothiq_billing_bridge.subscription_state_api.get_pending_upgrade"
    params = {"tenant_id": tenant_id}
    headers = {"Authorization": f"token {_FRAPPE_API_KEY}:{_FRAPPE_API_SEC}"}
    try:
        async with httpx.AsyncClient(timeout=4.0) as client:
            resp = await client.get(url, params=params, headers=headers)
            if resp.status_code == 200:
                data = resp.json().get("message") or {}
                if data.get("upgrade_pending"):
                    target_plan = data.get("target_plan", "pro")
                    current_plan = (cached_state.get("effective_plan") or "free").lower()
                    now = time.time()
                    return PredictiveSignal(
                        tenant_id=tenant_id,
                        signal_type=SignalType.PLAN_UPGRADE_INITIATED,
                        confidence_score=0.78,
                        expected_transition_from=f"active/{current_plan}",
                        expected_transition_to=f"active/{target_plan}",
                        expected_window_start=now,
                        expected_window_end=now + 3600,
                        source_data=data,
                    )
    except Exception:
        pass  # Upgrade signal is optional — never block on it
    return None


# ---------------------------------------------------------------------------
# Helper: linear interpolation for confidence scoring
# ---------------------------------------------------------------------------

def _lerp(value: float, high: float, low: float, conf_at_high: float, conf_at_low: float) -> float:
    """
    Map *value* in [low, high] to a confidence in [conf_at_low, conf_at_high].
    Values outside range are clamped.
    """
    if high == low:
        return conf_at_low
    t = max(0.0, min(1.0, (value - low) / (high - low)))
    return conf_at_low + t * (conf_at_high - conf_at_low)
