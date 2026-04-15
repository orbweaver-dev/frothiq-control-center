"""
Drift Detector — compares state across ERPNext, MC3 cache, and edge plugins.

Outputs DriftReport instances that feed the reconciliation engine.

Drift classification matrix
───────────────────────────
TYPE                 CONDITION                                   SEVERITY
STATE_MISMATCH       MC3.status  ≠ ERP.status                   HIGH
PLAN_MISMATCH        MC3.plan    ≠ ERP.plan                     HIGH
VERSION_MISMATCH     MC3.version < ERP.version (stale)          MEDIUM
EDGE_STALE           edge.last_sync > STALE_THRESHOLD            MEDIUM
EDGE_CONFLICT        edge.enforcement_mode ≠ MC3.enforcement     HIGH
MISSING_STATE        tenant absent from MC3 cache               CRITICAL
SPLIT_BRAIN          ERP ≠ MC3 ≠ Edge (all three differ)        CRITICAL
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class DriftType(str, Enum):
    STATE_MISMATCH  = "STATE_MISMATCH"
    PLAN_MISMATCH   = "PLAN_MISMATCH"
    VERSION_MISMATCH = "VERSION_MISMATCH"
    EDGE_STALE      = "EDGE_STALE"
    EDGE_CONFLICT   = "EDGE_CONFLICT"
    MISSING_STATE   = "MISSING_STATE"
    SPLIT_BRAIN     = "SPLIT_BRAIN"


class DriftSeverity(str, Enum):
    LOW      = "LOW"
    MEDIUM   = "MEDIUM"
    HIGH     = "HIGH"
    CRITICAL = "CRITICAL"


# ---------------------------------------------------------------------------
# Data containers
# ---------------------------------------------------------------------------

@dataclass
class DriftReport:
    tenant_id:   str
    drift_type:  DriftType
    severity:    DriftSeverity
    mc3_state:   dict[str, Any] | None
    erp_state:   dict[str, Any] | None
    edge_state:  dict[str, Any] | None
    detected_at: float = field(default_factory=time.time)
    detail:      str   = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "tenant_id":   self.tenant_id,
            "drift_type":  self.drift_type.value,
            "severity":    self.severity.value,
            "mc3_state":   self.mc3_state,
            "erp_state":   self.erp_state,
            "edge_state":  self.edge_state,
            "detected_at": self.detected_at,
            "detail":      self.detail,
        }


# ---------------------------------------------------------------------------
# Thresholds
# ---------------------------------------------------------------------------

# Edge is considered stale if it hasn't synced within this many seconds
EDGE_STALE_THRESHOLD_SEC = 600   # 10 minutes

# Version delta above which we escalate severity from MEDIUM → HIGH
VERSION_DELTA_HIGH = 3


# ---------------------------------------------------------------------------
# Severity matrix helpers
# ---------------------------------------------------------------------------

def _state_severity(mc3_status: str, erp_status: str) -> DriftSeverity:
    """Escalate severity based on how bad the state mismatch is."""
    # Suspended/canceled on ERP but active on MC3 = CRITICAL (overcharging/free-riding)
    erp_terminal = erp_status in ("suspended", "canceled", "expired")
    mc3_active   = mc3_status in ("active", "trial")
    if erp_terminal and mc3_active:
        return DriftSeverity.CRITICAL
    return DriftSeverity.HIGH


# ---------------------------------------------------------------------------
# Main detection function
# ---------------------------------------------------------------------------

def detect_drift(
    tenant_id: str,
    mc3_state:  dict[str, Any] | None,
    erp_state:  dict[str, Any] | None,
    edge_state: dict[str, Any] | None = None,
) -> list[DriftReport]:
    """
    Compare the three state sources for *tenant_id* and return all detected
    DriftReport objects (empty list = no drift).

    Args:
        tenant_id:  The tenant being checked.
        mc3_state:  State dict from MC3 cache/DB (may be None if not found).
        erp_state:  Authoritative state dict from ERPNext (may be None if unreachable).
        edge_state: Optional heartbeat payload from the edge plugin.

    Returns:
        List of DriftReport — may contain multiple drift types simultaneously.
    """
    reports: list[DriftReport] = []

    # ------------------------------------------------------------------
    # MISSING_STATE: tenant has no MC3 record at all
    # ------------------------------------------------------------------
    if mc3_state is None and erp_state is not None:
        reports.append(DriftReport(
            tenant_id=tenant_id,
            drift_type=DriftType.MISSING_STATE,
            severity=DriftSeverity.CRITICAL,
            mc3_state=None,
            erp_state=erp_state,
            edge_state=edge_state,
            detail="tenant exists in ERPNext but has no MC3 cache entry",
        ))
        # No further checks possible without MC3 state
        return reports

    if mc3_state is None and erp_state is None:
        # Both missing — nothing to compare
        return reports

    # ------------------------------------------------------------------
    # Compare MC3 vs ERPNext (when both available)
    # ------------------------------------------------------------------
    if erp_state is not None and mc3_state is not None:
        mc3_status = (mc3_state.get("subscription_status") or "").lower()
        erp_status = (erp_state.get("subscription_status") or "").lower()

        # STATE_MISMATCH
        if mc3_status != erp_status:
            severity = _state_severity(mc3_status, erp_status)
            reports.append(DriftReport(
                tenant_id=tenant_id,
                drift_type=DriftType.STATE_MISMATCH,
                severity=severity,
                mc3_state=mc3_state,
                erp_state=erp_state,
                edge_state=edge_state,
                detail=(
                    f"MC3 status={mc3_status!r} but ERPNext status={erp_status!r}"
                ),
            ))

        # PLAN_MISMATCH
        mc3_plan = (mc3_state.get("effective_plan") or mc3_state.get("plan") or "").lower()
        erp_plan = (erp_state.get("effective_plan") or erp_state.get("plan") or "").lower()
        if mc3_plan != erp_plan:
            reports.append(DriftReport(
                tenant_id=tenant_id,
                drift_type=DriftType.PLAN_MISMATCH,
                severity=DriftSeverity.HIGH,
                mc3_state=mc3_state,
                erp_state=erp_state,
                edge_state=edge_state,
                detail=f"MC3 plan={mc3_plan!r} but ERPNext plan={erp_plan!r}",
            ))

        # VERSION_MISMATCH
        mc3_ver = int(mc3_state.get("state_version") or 0)
        erp_ver = int(erp_state.get("state_version") or 0)
        if erp_ver > mc3_ver:
            delta = erp_ver - mc3_ver
            sev = DriftSeverity.HIGH if delta >= VERSION_DELTA_HIGH else DriftSeverity.MEDIUM
            reports.append(DriftReport(
                tenant_id=tenant_id,
                drift_type=DriftType.VERSION_MISMATCH,
                severity=sev,
                mc3_state=mc3_state,
                erp_state=erp_state,
                edge_state=edge_state,
                detail=f"MC3 version={mc3_ver} is {delta} behind ERPNext version={erp_ver}",
            ))

    # ------------------------------------------------------------------
    # Edge checks (when edge heartbeat payload is present)
    # ------------------------------------------------------------------
    if edge_state is not None and mc3_state is not None:
        # EDGE_STALE: edge hasn't synced within threshold
        edge_last_sync = float(edge_state.get("last_sync_at") or edge_state.get("ts") or 0)
        if edge_last_sync > 0:
            staleness = time.time() - edge_last_sync
            if staleness > EDGE_STALE_THRESHOLD_SEC:
                reports.append(DriftReport(
                    tenant_id=tenant_id,
                    drift_type=DriftType.EDGE_STALE,
                    severity=DriftSeverity.MEDIUM,
                    mc3_state=mc3_state,
                    erp_state=erp_state,
                    edge_state=edge_state,
                    detail=f"edge last synced {staleness:.0f}s ago (threshold={EDGE_STALE_THRESHOLD_SEC}s)",
                ))

        # EDGE_CONFLICT: edge running different enforcement_mode than MC3
        edge_mode = (edge_state.get("enforcement_mode") or "").lower()
        mc3_mode  = (mc3_state.get("enforcement_mode") or "").lower()
        if edge_mode and mc3_mode and edge_mode != mc3_mode:
            reports.append(DriftReport(
                tenant_id=tenant_id,
                drift_type=DriftType.EDGE_CONFLICT,
                severity=DriftSeverity.HIGH,
                mc3_state=mc3_state,
                erp_state=erp_state,
                edge_state=edge_state,
                detail=(
                    f"edge enforcement_mode={edge_mode!r} conflicts with MC3={mc3_mode!r}"
                ),
            ))

    # ------------------------------------------------------------------
    # SPLIT_BRAIN: all three sources disagree
    # ------------------------------------------------------------------
    if erp_state is not None and mc3_state is not None and edge_state is not None:
        erp_s  = (erp_state.get("subscription_status") or "").lower()
        mc3_s  = (mc3_state.get("subscription_status") or "").lower()
        edge_s = (edge_state.get("subscription_status") or "").lower()
        if edge_s and erp_s != mc3_s != edge_s and erp_s != edge_s:
            # Already have STATE_MISMATCH; add SPLIT_BRAIN on top
            reports.append(DriftReport(
                tenant_id=tenant_id,
                drift_type=DriftType.SPLIT_BRAIN,
                severity=DriftSeverity.CRITICAL,
                mc3_state=mc3_state,
                erp_state=erp_state,
                edge_state=edge_state,
                detail=(
                    f"three-way split: ERP={erp_s!r} MC3={mc3_s!r} edge={edge_s!r}"
                ),
            ))

    return reports


# ---------------------------------------------------------------------------
# Batch check across all known tenants
# ---------------------------------------------------------------------------

async def detect_all_drift(
    tenant_ids: list[str],
    erp_pull_fn,  # async (tenant_id) -> dict | None
    mc3_read_fn,  # async (tenant_id) -> dict | None
    edge_read_fn=None,  # async (tenant_id) -> dict | None  (optional)
) -> list[DriftReport]:
    """
    Run drift detection for a list of tenants.

    Uses callables so the engine can be tested without real I/O.
    """
    import asyncio
    all_reports: list[DriftReport] = []

    async def _check(tid: str) -> list[DriftReport]:
        mc3_state  = await mc3_read_fn(tid)
        erp_state  = await erp_pull_fn(tid)
        edge_state = await edge_read_fn(tid) if edge_read_fn else None
        return detect_drift(tid, mc3_state, erp_state, edge_state)

    results = await asyncio.gather(*[_check(tid) for tid in tenant_ids], return_exceptions=True)
    for r in results:
        if isinstance(r, list):
            all_reports.extend(r)
    return all_reports
