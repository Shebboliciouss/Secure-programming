# src/server/bootstrap.py
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
    def __init__(self, state):
        self.state = state
    
    async def join_network(self, introducers):
        for intro in introducers:
            try:
                intro_addr = f"ws://{intro['host']}:{intro['port']}"
                ws = await websockets.connect(intro_addr)
                
                join_msg = self._create_hello_join_msg(intro)
                await ws.send(serialize_message(join_msg))
                print(f"[Bootstrap] Sent SERVER_HELLO_JOIN to {intro_addr}")
                
                welcome_raw = await ws.recv()
                welcome = deserialize_message(welcome_raw)
                
                if welcome.get("type") == "SERVER_WELCOME":
                    await self._process_welcome(welcome, ws)
                    return True, ws
                    
            except Exception as e:
                print(f"[Bootstrap] Failed to join via {intro['host']}:{intro['port']}: {e}")
                continue
        
        print("[Bootstrap] Failed to join network via any introducer")
        return False, None
    
    def _create_hello_join_msg(self, intro):
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
        assigned_id = welcome["payload"].get("assigned_id")
        servers_list = welcome["payload"].get("servers", [])
        introducer_id = welcome.get("from")
        
        print(f"[Bootstrap] Received SERVER_WELCOME, assigned ID: {assigned_id}")
        
        if assigned_id != self.state.server_id:
            self.state.server_id = assigned_id
        
        self.state.servers[introducer_id] = bootstrap_ws
        print(f"[Bootstrap] Connected to introducer {introducer_id}")
        
        for srv in servers_list:
            srv_id = srv.get("server_id")
            if srv_id != self.state.server_id and srv_id != introducer_id:
                self.state.server_addrs[srv_id] = (srv.get("host"), srv.get("port"))
                self.state.server_pubkeys[srv_id] = srv.get("pubkey")
        
        await self.announce_to_network()
    
    async def announce_to_network(self):
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
        
        for srv_id, srv_ws in list(self.state.servers.items()):
            try:
                await srv_ws.send(serialize_message(announce_msg))
            except Exception as e:
                print(f"[Bootstrap] Failed to announce to {srv_id}: {e}")
        
        print(f"[Bootstrap] Announced to network")
    
    async def handle_hello_join(self, msg, server_ws):
        if not self.state.is_introducer:
            return
        
        payload = msg.get("payload", {})
        requesting_id = msg.get("from")
        host = payload.get("host")
        port = payload.get("port")
        pubkey = payload.get("pubkey")
        
        assigned_id = requesting_id
        if assigned_id in self.state.server_addrs:
            assigned_id = f"server_{uuid.uuid4()}"
        
        # CRITICAL: Only store websocket, NOT in server_addrs yet
        # so SERVER_ANNOUNCE relay logic to work correctly
        self.state.servers[assigned_id] = server_ws
        if pubkey:
            self.state.server_pubkeys[assigned_id] = pubkey
        
        print(f"[Introducer] Registered {assigned_id} at {host}:{port} (websocket only)")
        
        # Build server list for SERVER_WELCOME
        servers_list = []
        
        servers_list.append({
            "server_id": self.state.server_id,
            "host": self.state.host,
            "port": self.state.port,
            "pubkey": b64url_encode(rsa_crpt.export_public_key(self.state.public_key))
        })
        
        for srv_id, (srv_host, srv_port) in list(self.state.server_addrs.items()):
            if srv_id != assigned_id:
                servers_list.append({
                    "server_id": srv_id,
                    "host": srv_host,
                    "port": srv_port,
                    "pubkey": self.state.server_pubkeys.get(srv_id, "")
                })
        
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
        
        try:
            await server_ws.send(serialize_message(welcome_msg))
            print(f"[Introducer] Sent SERVER_WELCOME to {assigned_id}")
        except Exception as e:
            print(f"[Introducer] Failed to send SERVER_WELCOME to {assigned_id}: {e}")
            return
        
        asyncio.create_task(self._sync_users_to_new_server(server_ws, assigned_id))
    
    async def _sync_users_to_new_server(self, server_ws, target_server_id):
        local_users_snapshot = list(self.state.local_users.keys())
        sync_count = 0
        
        for user_id in local_users_snapshot:
            username = self.state.usernames.get(user_id, user_id)
            pubkey = self.state.user_keys.get(user_id, "")
            
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
                sync_count += 1
                await asyncio.sleep(0)
            except Exception as e:
                print(f"[Bootstrap] Failed to sync user {username}: {e}")
                break
        
        if sync_count > 0:
            print(f"[Introducer] Synchronized {sync_count} users to {target_server_id}")