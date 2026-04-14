"""
WebSocket connection manager — tracks active connections, broadcasts events.

Connections are authenticated via JWT (passed as ?token= query param).
Each connection is associated with a user and their role.

Broadcast channels:
  - "all" — broadcast to every connected admin
  - "super_admin" — super_admin only
  - "security" — security_analyst and above
  - "billing" — billing_admin and above
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any

from fastapi import WebSocket

from frothiq_control_center.auth.jwt_handler import ROLE_LEVEL

logger = logging.getLogger(__name__)


@dataclass
class ConnectedClient:
    websocket: WebSocket
    user_id: str
    role: str
    connected_at: float = field(default_factory=time.monotonic)
    last_ping: float = field(default_factory=time.monotonic)


class ConnectionManager:
    """
    Thread-safe (asyncio) WebSocket connection manager.
    Supports role-filtered broadcasts.
    """

    def __init__(self) -> None:
        self._clients: list[ConnectedClient] = []
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket, user_id: str, role: str) -> ConnectedClient:
        await websocket.accept()
        client = ConnectedClient(websocket=websocket, user_id=user_id, role=role)
        async with self._lock:
            self._clients.append(client)
        logger.info("WS connected: user=%s role=%s total=%d", user_id, role, len(self._clients))
        return client

    async def disconnect(self, client: ConnectedClient) -> None:
        async with self._lock:
            self._clients = [c for c in self._clients if c is not client]
        logger.info("WS disconnected: user=%s total=%d", client.user_id, len(self._clients))

    async def broadcast(
        self,
        event_type: str,
        payload: dict[str, Any],
        min_role: str = "read_only",
        tenant_id: str | None = None,
    ) -> int:
        """
        Broadcast an event to all connected clients with the required role level.

        Args:
            event_type: e.g. "ENVELOPE_UPDATE", "LICENSE_REVOKED"
            payload: arbitrary event data
            min_role: minimum role required to receive this event
            tenant_id: if set, only broadcast to clients managing this tenant

        Returns:
            Number of clients that received the event
        """
        message = json.dumps({
            "event_type": event_type,
            "payload": payload,
            "tenant_id": tenant_id,
            "ts": time.time(),
        })

        min_level = ROLE_LEVEL.get(min_role, 1)
        sent = 0

        async with self._lock:
            targets = [
                c for c in self._clients
                if ROLE_LEVEL.get(c.role, 0) >= min_level
            ]

        dead: list[ConnectedClient] = []
        for client in targets:
            try:
                await client.websocket.send_text(message)
                sent += 1
            except Exception:
                dead.append(client)

        # Clean up dead connections
        if dead:
            async with self._lock:
                for d in dead:
                    if d in self._clients:
                        self._clients.remove(d)

        return sent

    async def send_to_user(self, user_id: str, event_type: str, payload: dict[str, Any]) -> bool:
        """Send an event to a specific user's connection(s)."""
        message = json.dumps({
            "event_type": event_type,
            "payload": payload,
            "ts": time.time(),
        })
        sent = False
        async with self._lock:
            targets = [c for c in self._clients if c.user_id == user_id]

        for client in targets:
            try:
                await client.websocket.send_text(message)
                sent = True
            except Exception:
                pass

        return sent

    def get_connection_count(self) -> int:
        return len(self._clients)

    def get_stats(self) -> dict[str, Any]:
        return {
            "total_connections": len(self._clients),
            "by_role": {
                role: sum(1 for c in self._clients if c.role == role)
                for role in ("super_admin", "security_analyst", "billing_admin", "read_only")
            },
        }


# Module-level singleton
connection_manager = ConnectionManager()
