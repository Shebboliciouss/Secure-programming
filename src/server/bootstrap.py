# src/server/bootstrap.py
# Bootstrap and network join protocol (Section 8.1)

import asyncio
import websockets
import time
import uuid
from src.utils.json_utils import serialize_message, deserialize_message
from src.crypto import rsa_crpt

def b64url_encode(data: bytes) -> str:
    import base64
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')

class Bootstrap:
    """Handles server bootstrap and network joining"""
    
    def __init__(self, state):
        self.state = state
    
    async def join_network(self, introducers):
        """Join the network via an introducer (Section 8.1)"""
        for intro in introducers:
            try:
                intro_addr = f"ws://{intro['host']}:{intro['port']}"
                
                # DON'T use async with - we need to keep the connection open
                ws = await websockets.connect(intro_addr)
                
                # Send SERVER_HELLO_JOIN
                join_msg = self._create_hello_join_msg(intro)
                await ws.send(serialize_message(join_msg))
                print(f"[Bootstrap] Sent SERVER_HELLO_JOIN to {intro_addr}")
                
                # Wait for SERVER_WELCOME
                welcome_raw = await ws.recv()
                welcome = deserialize_message(welcome_raw)
                
                if welcome.get("type") == "SERVER_WELCOME":
                    await self._process_welcome(welcome, ws)
                    return True, ws  # Return both success flag AND the websocket
                    
            except Exception as e:
                print(f"[Bootstrap] Failed to join via {intro['host']}:{intro['port']}: {e}")
                continue
        
        print("[Bootstrap] Failed to join network via any introducer")
        return False, None
    
    def _create_hello_join_msg(self, intro):
        """Create SERVER_HELLO_JOIN message"""
        payload = {
            "host": self.state.host,
            "port": self.state.port,
            "pubkey": b64url_encode(rsa_crpt.export_public_key(self.state.public_key))
        }
        
        return {
            "type": "SERVER_HELLO_JOIN",
            "from": self.state.server_id,
            "to": f"{intro['host']}:{intro['port']}",
            "ts": int(time.time()*1000),
            "payload": payload,
            "sig": b64url_encode(rsa_crpt.sign_message(
                rsa_crpt.canonical_payload_bytes(payload), self.state.private_key))
        }
    
    async def _process_welcome(self, welcome, bootstrap_ws):
        """Process SERVER_WELCOME response"""
        assigned_id = welcome["payload"].get("assigned_id")
        servers_list = welcome["payload"].get("servers", [])
        introducer_id = welcome.get("from")
        
        print(f"[Bootstrap] Received SERVER_WELCOME, assigned ID: {assigned_id}")
        
        # Update server ID if changed
        if assigned_id != self.state.server_id:
            self.state.server_id = assigned_id
        
        # Store the bootstrap connection as the connection to the introducer
        self.state.servers[introducer_id] = bootstrap_ws
        print(f"[Bootstrap] Keeping connection to introducer {introducer_id}")
        
        # Store other server addresses (but don't store introducer again)
        for srv in servers_list:
            srv_id = srv.get("server_id")
            if srv_id != self.state.server_id and srv_id != introducer_id:
                self.state.server_addrs[srv_id] = (srv.get("host"), srv.get("port"))
                self.state.server_pubkeys[srv_id] = srv.get("pubkey")
        
        # Announce to network
        await self.announce_to_network()
    
    async def announce_to_network(self):
        """Broadcast SERVER_ANNOUNCE to all servers"""
        payload = {
            "host": self.state.host,
            "port": self.state.port,
            "pubkey": b64url_encode(rsa_crpt.export_public_key(self.state.public_key))
        }
        
        announce_msg = {
            "type": "SERVER_ANNOUNCE",
            "from": self.state.server_id,
            "to": "*",
            "ts": int(time.time()*1000),
            "payload": payload,
            "sig": b64url_encode(rsa_crpt.sign_message(
                rsa_crpt.canonical_payload_bytes(payload), self.state.private_key))
        }
        
        for srv_id, srv_ws in self.state.servers.items():
            try:
                await srv_ws.send(serialize_message(announce_msg))
            except:
                pass
        
        print(f"[Bootstrap] Announced to network")
    
    async def handle_hello_join(self, msg, server_ws):
        """Handle SERVER_HELLO_JOIN as introducer"""
        print(f"[Bootstrap] DEBUG: handle_hello_join called")
        print(f"[Bootstrap] DEBUG: is_introducer = {self.state.is_introducer}")
        
        if not self.state.is_introducer:
            print(f"[Bootstrap] DEBUG: Not an introducer, returning")
            return
        
        payload = msg.get("payload", {})
        requesting_id = msg.get("from")
        host = payload.get("host")
        port = payload.get("port")
        pubkey = payload.get("pubkey")
        
        print(f"[Bootstrap] DEBUG: Processing join request from {requesting_id}")
        
        # Check if ID is unique
        assigned_id = requesting_id
        if assigned_id in self.state.server_addrs:
            assigned_id = f"server_{uuid.uuid4()}"
            print(f"[Bootstrap] DEBUG: ID conflict, assigned new ID: {assigned_id}")
        
        # Store new server WITH websocket connection
        self.state.add_server(assigned_id, server_ws, host, port, pubkey)
        print(f"[Introducer] Registered {assigned_id} at {host}:{port}")
        
        # Build server list - INCLUDE INTRODUCER ITSELF
        servers_list = []
        
        # Add the introducer (this server)
        servers_list.append({
            "server_id": self.state.server_id,
            "host": self.state.host,
            "port": self.state.port,
            "pubkey": b64url_encode(rsa_crpt.export_public_key(self.state.public_key))
        })
        
        # Add all other registered servers
        for srv_id, (srv_host, srv_port) in self.state.server_addrs.items():
            if srv_id != assigned_id:  # Don't send joining server back to itself
                servers_list.append({
                    "server_id": srv_id,
                    "host": srv_host,
                    "port": srv_port,
                    "pubkey": self.state.server_pubkeys.get(srv_id, "")
                })
        
        # Send SERVER_WELCOME
        welcome_payload = {
            "assigned_id": assigned_id,
            "servers": servers_list
        }
        
        welcome_msg = {
            "type": "SERVER_WELCOME",
            "from": self.state.server_id,
            "to": assigned_id,
            "ts": int(time.time()*1000),
            "payload": welcome_payload,
            "sig": b64url_encode(rsa_crpt.sign_message(
                rsa_crpt.canonical_payload_bytes(welcome_payload), self.state.private_key))
        }
        
        await server_ws.send(serialize_message(welcome_msg))
        print(f"[Introducer] Sent SERVER_WELCOME to {assigned_id}")
        print(f"[Introducer] Told {assigned_id} about {len(servers_list)} servers (including self)")
        
        # Debug: Check local users before syncing
        print(f"[Bootstrap] DEBUG: About to sync users")
        print(f"[Bootstrap] DEBUG: local_users count = {len(self.state.local_users)}")
        print(f"[Bootstrap] DEBUG: local_users keys = {list(self.state.local_users.keys())}")
        print(f"[Bootstrap] DEBUG: usernames = {self.state.usernames}")
        
        # Sync current users to new server immediately
        await self._sync_users_to_new_server(server_ws, assigned_id)
    
    async def _sync_users_to_new_server(self, server_ws, target_server_id):
        """Sync all local users to newly joined server"""
        print(f"[Bootstrap] DEBUG: _sync_users_to_new_server called for {target_server_id}")
        print(f"[Bootstrap] DEBUG: Iterating over {len(self.state.local_users)} local users")
        
        sync_count = 0
        for user_id in self.state.local_users.keys():
            username = self.state.usernames.get(user_id, user_id)
            pubkey = self.state.user_keys.get(user_id, "")
            
            print(f"[Bootstrap] DEBUG: Syncing user {username} ({user_id[:8]}...)")
            
            payload = {
                "user_id": user_id,
                "server_id": self.state.server_id,
                "meta": {"username": username, "pubkey": pubkey}
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
            
            try:
                await server_ws.send(serialize_message(advertise_msg))
                print(f"[Bootstrap] DEBUG: Sent USER_ADVERTISE for {username}")
                sync_count += 1
            except Exception as e:
                print(f"[Bootstrap] DEBUG: Failed to send USER_ADVERTISE for {username}: {e}")
        
        if sync_count > 0:
            print(f"[Introducer] Synchronized {sync_count} users to {target_server_id}")
        else:
            print(f"[Introducer] No users to synchronize (server has 0 local users)")