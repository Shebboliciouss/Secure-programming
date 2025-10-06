# src/server/presence.py
# User presence gossip protocol (Section 8.2)

import time
from src.utils.json_utils import serialize_message
from src.crypto import rsa_crpt

def b64url_encode(data: bytes) -> str:
    import base64
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')

class PresenceManager:
    """Manages user presence across the network"""
    
    def __init__(self, state):
        self.state = state
    
    async def advertise_user(self, user_id, metadata=None):
        """Advertise user presence to all servers (Section 8.2)"""
        username = metadata.get('username') if metadata else user_id
        print(f"[Presence] DEBUG: advertise_user called for {username}")
        print(f"[Presence] DEBUG: Connected servers: {list(self.state.servers.keys())}")
        print(f"[Presence] DEBUG: Number of servers: {len(self.state.servers)}")
        
        payload = {
            "user_id": user_id,
            "server_id": self.state.server_id,
            "meta": metadata or {}
        }
        
        advertise_msg = {
            "type": "USER_ADVERTISE",
            "from": self.state.server_id,
            "to": "*",
            "ts": int(time.time()*1000),
            "payload": payload,
            "sig": b64url_encode(rsa_crpt.sign_message(
                rsa_crpt.canonical_payload_bytes(payload), self.state.private_key))
        }
        
        sent_count = 0
        for srv_id, srv_ws in self.state.servers.items():
            try:
                await srv_ws.send(serialize_message(advertise_msg))
                sent_count += 1
                print(f"[Presence] DEBUG: Sent USER_ADVERTISE to {srv_id}")
            except Exception as e:
                print(f"[Presence] DEBUG: Failed to send to {srv_id}: {e}")
        
        print(f"[Presence] Advertised user {username} to {sent_count} servers")
    
    async def remove_user(self, user_id):
        """Remove user from network (Section 8.2)"""
        payload = {
            "user_id": user_id,
            "server_id": self.state.server_id
        }
        
        remove_msg = {
            "type": "USER_REMOVE",
            "from": self.state.server_id,
            "to": "*",
            "ts": int(time.time()*1000),
            "payload": payload,
            "sig": b64url_encode(rsa_crpt.sign_message(
                rsa_crpt.canonical_payload_bytes(payload), self.state.private_key))
        }
        
        for srv_id, srv_ws in self.state.servers.items():
            try:
                await srv_ws.send(serialize_message(remove_msg))
            except:
                pass
        
        print(f"[Presence] Removed user {self.state.usernames.get(user_id, user_id)}")
    
    async def handle_user_advertise(self, msg):
        """Handle USER_ADVERTISE from remote server"""
        payload = msg.get("payload", {})
        user_id = payload.get("user_id")
        server_id = payload.get("server_id")
        meta = payload.get("meta", {})
        
        username = meta.get("username", user_id)
        print(f"[Presence] DEBUG: Received USER_ADVERTISE for {username} from {server_id}")
        print(f"[Presence] DEBUG: Has pubkey: {'pubkey' in meta}")
        
        # Register remote user
        self.state.add_remote_user(
            user_id, 
            server_id, 
            meta.get("username"),
            meta.get("pubkey")
        )
        
        print(f"[Presence] User {username} advertised on {server_id}")
        print(f"[Presence] DEBUG: user_keys now has {len(self.state.user_keys)} keys")
        print(f"[Presence] DEBUG: user_locations now has {len(self.state.user_locations)} users")
        
        # Notify local clients about this remote user
        if "pubkey" in meta:
            print(f"[Presence] DEBUG: Notifying {len(self.state.local_users)} local clients")
            await self._notify_local_clients(user_id, meta)
    
    async def handle_user_remove(self, msg):
        """Handle USER_REMOVE from remote server"""
        payload = msg.get("payload", {})
        user_id = payload.get("user_id")
        server_id = payload.get("server_id")
        
        if self.state.remove_remote_user(user_id, server_id):
            print(f"[Presence] User {user_id} removed from {server_id}")
    
    async def _notify_local_clients(self, user_id, meta):
        """Notify local clients about new remote user"""
        notified_count = 0
        for local_user_id, local_ws in self.state.local_users.items():
            hello_msg = {
                "type": "USER_HELLO",
                "from": user_id,
                "to": local_user_id,
                "ts": int(time.time()*1000),
                "payload": {
                    "pubkey": meta.get("pubkey"),
                    "username": meta.get("username", user_id)
                },
                "sig": ""
            }
            try:
                await local_ws.send(serialize_message(hello_msg))
                notified_count += 1
                print(f"[Presence] DEBUG: Notified {self.state.usernames.get(local_user_id)} about remote user")
            except Exception as e:
                print(f"[Presence] DEBUG: Failed to notify {local_user_id}: {e}")
        
        print(f"[Presence] DEBUG: Notified {notified_count} local clients about remote user")