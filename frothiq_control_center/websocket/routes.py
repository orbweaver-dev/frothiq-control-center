"""
WebSocket endpoint — /ws/events

Clients connect with a valid JWT access token:
  ws://control-center/ws/events?token=<access_jwt>

On connect:
  - JWT is validated
  - Connection is registered in ConnectionManager
  - Client receives a "CONNECTED" confirmation event

On heartbeat:
  - Server sends "PING" every CC_WS_HEARTBEAT_INTERVAL seconds
  - Client should respond with "PONG" text frame

On disconnect:
  - Connection is removed from ConnectionManager

Events are pushed as JSON:
  {
    "event_type": "DEFENSE_CLUSTER_UPDATE",
    "payload": {...},
    "tenant_id": "optional",
    "ts": 1700000000.0
  }
"""

from __future__ import annotations

import asyncio
import json
import logging
import time

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from frothiq_control_center.auth.jwt_handler import decode_token
from frothiq_control_center.config import get_settings
from .connection_manager import connection_manager

logger = logging.getLogger(__name__)
router = APIRouter(tags=["websocket"])


@router.websocket("/ws/events")
async def websocket_events(websocket: WebSocket):
    """
    Main WebSocket endpoint for real-time Control Center events.
    Requires a valid JWT access token as ?token= query parameter.
    """
    settings = get_settings()

    # Auth
    token = websocket.query_params.get("token")
    if not token:
        await websocket.close(code=4001, reason="Missing token")
        return

    try:
        payload = decode_token(token)
        if payload.type != "access":
            await websocket.close(code=4001, reason="Not an access token")
            return
    except Exception:
        await websocket.close(code=4001, reason="Invalid or expired token")
        return

    # Register connection
    client = await connection_manager.connect(websocket, payload.sub, payload.role)

    # Send welcome event
    await websocket.send_text(json.dumps({
        "event_type": "CONNECTED",
        "payload": {
            "user_id": payload.sub,
            "role": payload.role,
            "connections": connection_manager.get_connection_count(),
        },
        "ts": time.time(),
    }))

    heartbeat_interval = settings.ws_heartbeat_interval

    try:
        while True:
            # Wait for client messages (PONG or graceful disconnect)
            # with a timeout equal to the heartbeat interval
            try:
                data = await asyncio.wait_for(
                    websocket.receive_text(),
                    timeout=heartbeat_interval,
                )
                # Handle PONG response
                if data.strip() in ("PONG", '"PONG"'):
                    client.last_ping = time.monotonic()
                # Ignore other client messages silently

            except asyncio.TimeoutError:
                # Send heartbeat PING
                await websocket.send_text(json.dumps({
                    "event_type": "PING",
                    "payload": {"ts": time.time()},
                    "ts": time.time(),
                }))

    except WebSocketDisconnect:
        logger.info("WS client disconnected: user=%s", payload.sub)
    except Exception as exc:
        logger.warning("WS error for user %s: %s", payload.sub, exc)
    finally:
        await connection_manager.disconnect(client)


@router.get("/ws/stats")
async def ws_stats():
    """Return current WebSocket connection statistics (no auth — internal monitoring use)."""
    return connection_manager.get_stats()
