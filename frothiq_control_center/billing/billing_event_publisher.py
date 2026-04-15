"""
Billing Event Publisher.

After a billing state change is committed, this module pushes
the update to three channels:

  1. Edge plugin pull endpoints — HTTP PATCH to each registered
     edge node for the affected tenant (best-effort, no retry).
  2. WebSocket channel — Redis pub/sub publish on
     frothiq:billing:events:{tenant_id} so connected CC UI
     clients get real-time updates.
  3. Internal broadcast — publishes to frothiq:billing:broadcast
     for any internal consumers (e.g. rate-limiter, feature-flag cache).
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any

import httpx
from sqlalchemy import select

from frothiq_control_center.integrations.redis_client import get_pubsub_client
from frothiq_control_center.integrations.database import get_session_factory
from frothiq_control_center.models.edge import EdgeNode, EdgeTenant

logger = logging.getLogger(__name__)

_BILLING_EVENT_CHANNEL = "frothiq:billing:events:{tenant_id}"
_BILLING_BROADCAST_CHANNEL = "frothiq:billing:broadcast"
_EDGE_PUSH_TIMEOUT = 5.0       # seconds per edge node


async def publish_billing_update(
    tenant_id: str,
    state: dict[str, Any],
    event_type: str = "billing.state_changed",
) -> dict[str, Any]:
    """
    Broadcast a billing state change to all interested parties.

    Args:
        tenant_id:  Tenant whose state changed.
        state:      Full billing state dict (from license_state_cache).
        event_type: Event label for subscribers.

    Returns summary of publish results.
    """
    payload = {
        "event_type": event_type,
        "tenant_id":  tenant_id,
        "timestamp":  time.time(),
        "data":       state,
    }

    ws_ok    = await _publish_websocket(tenant_id, payload)
    edge_ok  = await _push_to_edge_nodes(tenant_id, state)
    bcast_ok = await _publish_broadcast(payload)

    return {
        "websocket_published": ws_ok,
        "edge_nodes_notified": edge_ok,
        "broadcast_published": bcast_ok,
    }


# ---------------------------------------------------------------------------
# WebSocket channel (Redis pub/sub)
# ---------------------------------------------------------------------------

async def _publish_websocket(tenant_id: str, payload: dict[str, Any]) -> bool:
    channel = _BILLING_EVENT_CHANNEL.format(tenant_id=tenant_id)
    try:
        redis = await get_pubsub_client()
        await redis.publish(channel, json.dumps(payload))
        logger.debug("billing ws published: channel=%s", channel)
        return True
    except Exception as exc:
        logger.warning("billing ws publish failed: %s", exc)
        return False


async def _publish_broadcast(payload: dict[str, Any]) -> bool:
    try:
        redis = await get_pubsub_client()
        await redis.publish(_BILLING_BROADCAST_CHANNEL, json.dumps(payload))
        return True
    except Exception as exc:
        logger.warning("billing broadcast failed: %s", exc)
        return False


# ---------------------------------------------------------------------------
# Edge node HTTP push
# ---------------------------------------------------------------------------

async def _push_to_edge_nodes(
    tenant_id: str, state: dict[str, Any]
) -> int:
    """
    Send a lightweight billing state update to each active edge node
    belonging to *tenant_id*.  Best-effort: individual failures are
    logged but do not abort the batch.
    Returns the number of nodes successfully notified.
    """
    nodes = await _get_edge_nodes(tenant_id)
    if not nodes:
        return 0

    slim_payload = {
        "subscription_status": state.get("subscription_status"),
        "effective_plan":      state.get("effective_plan"),
        "enforcement_mode":    state.get("enforcement_mode"),
        "state_version":       state.get("state_version"),
        "expiry":              state.get("expiry"),
        "grace_until":         state.get("grace_until"),
    }

    ok_count = 0
    async with httpx.AsyncClient(timeout=_EDGE_PUSH_TIMEOUT) as client:
        for node in nodes:
            url = _build_edge_billing_url(node)
            if not url:
                continue
            try:
                resp = await client.patch(url, json=slim_payload)
                if resp.status_code < 400:
                    ok_count += 1
                else:
                    logger.warning(
                        "edge billing push HTTP %d: node=%s tenant=%s",
                        resp.status_code, node.get("id"), tenant_id,
                    )
            except Exception as exc:
                logger.warning(
                    "edge billing push failed: node=%s err=%s",
                    node.get("id"), exc,
                )

    return ok_count


async def _get_edge_nodes(tenant_id: str) -> list[dict[str, Any]]:
    """Return active EdgeNodes for the given tenant as plain dicts."""
    try:
        async with get_session_factory()() as session:
            # Find EdgeTenant by tenant_id
            tenant = await session.scalar(
                select(EdgeTenant).where(EdgeTenant.tenant_id == tenant_id)
            )
            if not tenant:
                return []

            result = await session.execute(
                select(EdgeNode).where(
                    EdgeNode.tenant_id == tenant.id,  # type: ignore[arg-type]
                    EdgeNode.is_active == True,  # noqa: E712
                )
            )
            nodes = result.scalars().all()
            return [
                {
                    "id":       n.id,
                    "site_url": getattr(n, "site_url", None) or getattr(n, "callback_url", None),
                    "platform": getattr(n, "platform", None),
                }
                for n in nodes
            ]
    except Exception as exc:
        logger.warning("_get_edge_nodes failed for %s: %s", tenant_id, exc)
        return []


def _build_edge_billing_url(node: dict[str, Any]) -> str | None:
    """
    Build the billing push URL for an edge node.
    Edge nodes expose: POST/PATCH /frothiq/billing-state
    """
    site_url = node.get("site_url")
    if not site_url:
        return None
    site_url = site_url.rstrip("/")
    platform = (node.get("platform") or "").lower()
    if "wordpress" in platform:
        return f"{site_url}/?frothiq_action=billing_state_push"
    if "joomla" in platform:
        return f"{site_url}/index.php?option=com_frothiq&task=billing.push"
    if "frappe" in platform or "erpnext" in platform:
        return f"{site_url}/api/method/frothiq_frappe.frothiq.api.billing.push_state"
    # Generic fallback
    return f"{site_url}/frothiq/billing-state"
