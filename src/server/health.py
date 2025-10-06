# src/server/health.py
# Server health monitoring and heartbeat protocol (Section 8.4)

import asyncio
import time
from src.utils.json_utils import serialize_message
from src.crypto import rsa_crpt

def b64url_encode(data: bytes) -> str:
    import base64
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')

class HealthMonitor:
    """Manages server health checks and heartbeats"""
    
    def __init__(self, state):
        self.state = state
        self.heartbeat_interval = 15  # seconds
        self.timeout_threshold = 45   # seconds
    
    async def start_heartbeat_loop(self):
        """Send heartbeat to all connected servers every 15s"""
        while True:
            await asyncio.sleep(self.heartbeat_interval)
            await self._send_heartbeats()
    
    async def _send_heartbeats(self):
        """Send HEARTBEAT to all servers"""
        for srv_id, srv_ws in list(self.state.servers.items()):
            payload = {}
            heartbeat_msg = {
                "type": "HEARTBEAT",
                "from": self.state.server_id,
                "to": srv_id,
                "ts": int(time.time()*1000),
                "payload": payload,
                "sig": b64url_encode(rsa_crpt.sign_message(
                    rsa_crpt.canonical_payload_bytes(payload), self.state.private_key))
            }
            try:
                await srv_ws.send(serialize_message(heartbeat_msg))
            except:
                pass
    
    async def start_health_check_loop(self):
        """Check for dead servers (45s timeout)"""
        while True:
            await asyncio.sleep(10)
            await self._check_timeouts()
    
    async def _check_timeouts(self):
        """Detect and close dead server connections"""
        now = time.time()
        for srv_id, last_seen in list(self.state.last_heartbeat.items()):
            if now - last_seen > self.timeout_threshold:
                print(f"[Health] Server {srv_id} timeout (no heartbeat for {self.timeout_threshold}s)")
                await self._close_dead_server(srv_id)
    
    async def _close_dead_server(self, srv_id):
        """Close and remove dead server connection"""
        if srv_id in self.state.servers:
            try:
                await self.state.servers[srv_id].close()
            except:
                pass
        self.state.remove_server(srv_id)
    
    def handle_heartbeat(self, msg):
        """Handle received HEARTBEAT message"""
        sender = msg.get("from")
        self.state.last_heartbeat[sender] = time.time()