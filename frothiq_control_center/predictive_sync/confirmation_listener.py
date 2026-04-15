"""
Confirmation Listener.

Called immediately after every confirmed ERPNext billing event (webhook or pull).
Compares the confirmed state against any existing staged contract for that tenant.

Decision matrix:
  confirmed_state == predicted_state  → ACTIVATE staged contract on edges
  confirmed_state != predicted_state  → DISCARD staged contract on edges
  no staged contract exists           → no-op (normal billing flow)

The listener never blocks the billing webhook response — it is called
in a background task from routes_billing.py after the confirmed state
has already been persisted.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

from frothiq_control_center.predictive_sync.preemptive_contract_generator import (
    make_activation_message,
    make_invalidation_message,
)
from frothiq_control_center.predictive_sync.staged_contract_dispatcher import (
    get_staged_contract,
    invalidate_staged_contract,
)
from frothiq_control_center.predictive_sync.prediction_accuracy_tracker import (
    record_outcome,
    OutcomeType,
)

logger = logging.getLogger(__name__)


async def on_billing_confirmed(
    tenant_id:       str,
    confirmed_state: dict[str, Any],
) -> None:
    """
    Entry point called after every confirmed billing state write.

    Looks up any pending staged contract for *tenant_id* and either:
      - broadcasts an ACTIVATE message (match)
      - broadcasts a DISCARD message + invalidates (mismatch)

    This function is designed to be fire-and-forget from the webhook handler:
        asyncio.create_task(on_billing_confirmed(tenant_id, state))
    """
    try:
        staged = await get_staged_contract(tenant_id)
        if not staged:
            return   # No staged contract — nothing to do

        # Only act on contracts that haven't already been resolved
        if staged.get("contract_type") != "staged" or not staged.get("staged"):
            return

        contract_id      = staged["contract_id"]
        contract_version = staged["contract_version"]
        predicted_status = staged.get("subscription_status", "")
        confirmed_status = (confirmed_state.get("subscription_status") or "").lower()

        match = _states_match(predicted_status, confirmed_status)

        if match:
            await _handle_match(tenant_id, contract_id, contract_version, confirmed_status, staged)
        else:
            await _handle_mismatch(tenant_id, contract_id, contract_version, confirmed_status, staged)

    except Exception as exc:
        logger.error("on_billing_confirmed failed: tenant=%s: %s", tenant_id, exc)


# ---------------------------------------------------------------------------
# Match path: prediction was correct — activate on all edges
# ---------------------------------------------------------------------------

async def _handle_match(
    tenant_id:        str,
    contract_id:      str,
    contract_version: int,
    confirmed_status: str,
    staged:           dict[str, Any],
) -> None:
    """Prediction correct — signal edges to activate staged contract now."""
    activation_msg = make_activation_message(
        tenant_id=tenant_id,
        contract_id=contract_id,
        contract_version=contract_version,
        confirmed_state=confirmed_status,
    )

    # Push activation to edges via billing event publisher
    await _broadcast_to_edges(tenant_id, activation_msg)

    # Publish to WS channel so UI reflects instant activation
    await _publish_ws(tenant_id, activation_msg)

    # Record correct prediction in accuracy tracker
    predicted_at = staged.get("generated_at") or time.time()
    latency_saved_ms = _estimate_latency_saved(staged)

    await record_outcome(
        tenant_id=tenant_id,
        signal_type=staged.get("signal_type", ""),
        predicted_to=staged.get("subscription_status", ""),
        confidence_score=float(staged.get("confidence_score") or 0),
        outcome=OutcomeType.CORRECT,
        confirmed_state=confirmed_status,
        latency_saved_ms=latency_saved_ms,
    )

    # Update DB: status → confirmed, activation_mode → confirmed
    await _update_staged_status(tenant_id, "confirmed", "confirmed", confirmed_status)

    # Invalidate Redis key (contract now applied)
    await invalidate_staged_contract(tenant_id, reason="confirmed_activated")

    logger.info(
        "prediction CORRECT: tenant=%s contract=%s predicted=%s confirmed=%s saved=%.0fms",
        tenant_id, contract_id, staged.get("subscription_status"), confirmed_status,
        latency_saved_ms,
    )


# ---------------------------------------------------------------------------
# Mismatch path: prediction was wrong — discard on all edges
# ---------------------------------------------------------------------------

async def _handle_mismatch(
    tenant_id:        str,
    contract_id:      str,
    contract_version: int,
    confirmed_status: str,
    staged:           dict[str, Any],
) -> None:
    """Prediction wrong — signal edges to discard staged contract."""
    invalidation_msg = make_invalidation_message(
        tenant_id=tenant_id,
        contract_id=contract_id,
        contract_version=contract_version,
        reason=f"mismatch: predicted={staged.get('subscription_status')!r} confirmed={confirmed_status!r}",
    )

    await _broadcast_to_edges(tenant_id, invalidation_msg)
    await _publish_ws(tenant_id, invalidation_msg)

    await record_outcome(
        tenant_id=tenant_id,
        signal_type=staged.get("signal_type", ""),
        predicted_to=staged.get("subscription_status", ""),
        confidence_score=float(staged.get("confidence_score") or 0),
        outcome=OutcomeType.INCORRECT,
        confirmed_state=confirmed_status,
        latency_saved_ms=None,
    )

    # Invalidate Redis and mark DB row as discarded
    await invalidate_staged_contract(tenant_id, reason="prediction_incorrect")
    await _update_staged_status(tenant_id, "discarded", "none", confirmed_status)

    logger.warning(
        "prediction INCORRECT: tenant=%s contract=%s predicted=%s confirmed=%s — discarded",
        tenant_id, contract_id, staged.get("subscription_status"), confirmed_status,
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _states_match(predicted: str, confirmed: str) -> bool:
    """Two states match if they normalise to the same canonical string."""
    return predicted.lower().strip() == confirmed.lower().strip()


def _estimate_latency_saved(staged: dict[str, Any]) -> float:
    """
    Estimate how many milliseconds of enforcement lag were prevented.
    Base: time from now to activation_timestamp (i.e. how far ahead we pre-staged).
    """
    activation_at = float(staged.get("activation_timestamp") or staged.get("activation_at") or 0)
    generated_at  = float(staged.get("generated_at") or 0)
    now           = time.time()

    if activation_at > now:
        # Still in the future → confirmed earlier than expected → big saving
        return (activation_at - now) * 1000
    elif generated_at > 0:
        # How long ago we pre-staged it (already past activation point)
        return (now - generated_at) * 1000
    return 0.0


async def _broadcast_to_edges(tenant_id: str, message: dict[str, Any]) -> None:
    """Send activation or invalidation message to all edge nodes."""
    from frothiq_control_center.billing.billing_event_publisher import (
        _get_edge_nodes,
        _build_edge_billing_url,
    )
    import httpx

    nodes = await _get_edge_nodes(tenant_id)
    if not nodes:
        return

    async with httpx.AsyncClient(timeout=5.0) as client:
        for node in nodes:
            url = _build_edge_billing_url(node)
            if not url:
                continue
            # Activation/invalidation messages go to the staged-contract endpoint
            msg_url = url.replace("/billing-state", "/staged-contract")
            try:
                await client.post(msg_url, json=message)
            except Exception as exc:
                logger.debug("_broadcast_to_edges failed node %s: %s", node.get("id"), exc)


async def _publish_ws(tenant_id: str, message: dict[str, Any]) -> None:
    """Publish activation/invalidation event to the WS pub/sub channel."""
    import json
    from frothiq_control_center.integrations.redis_client import get_pubsub_client
    channel = f"frothiq:billing:events:{tenant_id}"
    try:
        redis = await get_pubsub_client()
        await redis.publish(channel, json.dumps(message))
    except Exception as exc:
        logger.debug("_publish_ws failed: %s", exc)


async def _update_staged_status(
    tenant_id: str,
    status: str,
    activation_mode: str,
    erp_confirmed_state: str,
) -> None:
    """Update the StagedContractRecord in DB after resolution."""
    from sqlalchemy import update
    from frothiq_control_center.models.predictive_sync import StagedContractRecord
    from frothiq_control_center.models.user import _utcnow
    try:
        async with get_session_factory()() as session:
            await session.execute(
                update(StagedContractRecord)
                .where(StagedContractRecord.tenant_id == tenant_id)
                .values(
                    status=status,
                    activation_mode=activation_mode,
                    erp_confirmed_state=erp_confirmed_state,
                    outcome=status,
                    outcome_at=_utcnow(),
                    activated_at=_utcnow() if status == "confirmed" else None,
                )
            )
            await session.commit()
    except Exception as exc:
        logger.warning("_update_staged_status failed: %s", exc)


def get_session_factory():
    from frothiq_control_center.integrations.database import get_session_factory as _gsf
    return _gsf()
