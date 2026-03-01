"""
ZeroTrust - WebSocket Manager
Handles real-time event streaming to connected SOC dashboard clients.
"""

import json
import asyncio
import logging
from datetime import datetime, timezone
from typing import Dict, Set
from fastapi import WebSocket, WebSocketDisconnect

logger = logging.getLogger("zerotrust.websocket")


class ConnectionManager:
    """Manages WebSocket connections for live event streaming."""

    def __init__(self):
        self.active_connections: Set[WebSocket] = set()
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        async with self._lock:
            self.active_connections.add(websocket)
        logger.info(f"WS client connected. Total: {len(self.active_connections)}")

    async def disconnect(self, websocket: WebSocket):
        async with self._lock:
            self.active_connections.discard(websocket)
        logger.info(f"WS client disconnected. Total: {len(self.active_connections)}")

    async def broadcast(self, message: dict):
        """Broadcast a message to all connected clients."""
        if not self.active_connections:
            return

        payload = json.dumps(message, default=str)
        disconnected = set()

        async with self._lock:
            for conn in self.active_connections:
                try:
                    await conn.send_text(payload)
                except Exception:
                    disconnected.add(conn)

            self.active_connections -= disconnected

    async def send_personal(self, websocket: WebSocket, message: dict):
        """Send a message to a specific client."""
        try:
            await websocket.send_text(json.dumps(message, default=str))
        except Exception:
            await self.disconnect(websocket)

    @property
    def client_count(self) -> int:
        return len(self.active_connections)


# Global instance
manager = ConnectionManager()


async def broadcast_device_update(device_data: dict):
    """Broadcast a device status update to all clients."""
    await manager.broadcast({
        "type": "device_update",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "data": device_data,
    })


async def broadcast_alert(alert_data: dict):
    """Broadcast a security alert to all clients."""
    await manager.broadcast({
        "type": "alert",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "data": alert_data,
    })


async def broadcast_risk_event(event_data: dict):
    """Broadcast a risk event to all clients."""
    await manager.broadcast({
        "type": "risk_event",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "data": event_data,
    })


async def broadcast_stats(stats_data: dict):
    """Broadcast aggregated stats to all clients."""
    await manager.broadcast({
        "type": "stats_update",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "data": stats_data,
    })
