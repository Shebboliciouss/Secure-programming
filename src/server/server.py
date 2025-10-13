# server.py - Production Version
import asyncio
import websockets
import time
from src.utils.json_utils import serialize_message, deserialize_message
from src.crypto import rsa_crpt

from .state import ServerState
from .bootstrap import Bootstrap
from .presence import PresenceManager
from .delivery import DeliveryManager
from .health import HealthMonitor

def b64url_encode(data: bytes) -> str:
    import base64
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')

class ChatServer:
    def __init__(self, port, server_id, bootstrap_list=None, is_introducer=False):
        self.state = ServerState(server_id, "localhost", port, is_introducer)
        self.bootstrap = Bootstrap(self.state)
        self.presence = PresenceManager(self.state)
        self.delivery = DeliveryManager(self.state)
        self.health = HealthMonitor(self.state)
        
        self.recent_messages = {}
        self.message_cache_ttl = 5000
        self.seen_announcements = set()
        
        if bootstrap_list:
            self.state.bootstrap_servers = bootstrap_list
    
    async def start(self):
        print(f"[Server] Starting {self.state.server_id} on ws://{self.state.host}:{self.state.port}")
        
        asyncio.create_task(self.health.start_heartbeat_loop())
        asyncio.create_task(self.health.start_health_check_loop())
        
        if not self.state.is_introducer and self.state.bootstrap_servers:
            success, bootstrap_ws = await self.bootstrap.join_network(self.state.bootstrap_servers)
            if success:
                introducer_id = None
                for srv_id, srv_ws in self.state.servers.items():
                    if srv_ws == bootstrap_ws:
                        introducer_id = srv_id
                        break
                
                if introducer_id:
                    asyncio.create_task(self._handle_bootstrap_connection(introducer_id, bootstrap_ws))
                
                print(f"[Federation] Connecting to {len(self.state.server_addrs)} other servers...")
                await asyncio.sleep(1)
                for srv_id, (host, port) in list(self.state.server_addrs.items()):
                    if srv_id != self.state.server_id and srv_id != introducer_id:
                        print(f"[Federation] Initiating connection to {srv_id} at {host}:{port}")
                        asyncio.create_task(self._connect_to_server(srv_id, host, port))
        
        async with websockets.serve(self.handler, self.state.host, self.state.port):
            print(f"[Server] {self.state.server_id} ready")
            await asyncio.Future()
    
    async def _handle_bootstrap_connection(self, server_id, ws):
        try:
            async for raw in ws:
                msg = deserialize_message(raw)
                await self.handle_server_message(msg, ws)
        except websockets.ConnectionClosed:
            self.state.remove_server(server_id)
            print(f"[Federation] Bootstrap connection to {server_id} closed")
        except Exception as e:
            self.state.remove_server(server_id)
            print(f"[Federation] Error with bootstrap connection to {server_id}: {e}")
    
    async def _connect_to_server(self, server_id, host, port):
        while True:
            try:
                addr = f"ws://{host}:{port}"
                async with websockets.connect(addr) as ws:
                    self.state.servers[server_id] = ws
                    print(f"[Federation] Connected to {server_id} at {addr}")
                    
                    # Send SERVER_ANNOUNCE so remote server knows about this connection
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
                    
                    await ws.send(serialize_message(announce_msg))
                    
                    # Advertise all our local users to this server
                    await self._advertise_users_to_server(server_id)
                    
                    async for raw in ws:
                        msg = deserialize_message(raw)
                        await self.handle_server_message(msg, ws)
                        
            except websockets.ConnectionClosed:
                self.state.remove_server(server_id)
                print(f"[Federation] Connection to {server_id} closed, reconnecting in 5s...")
                await asyncio.sleep(5)
            except Exception as e:
                self.state.remove_server(server_id)
                print(f"[Federation] Error with {server_id}: {e}, reconnecting in 5s...")
                await asyncio.sleep(5)
    
    async def _advertise_users_to_server(self, target_server_id):
        if target_server_id not in self.state.servers:
            return
        
        target_ws = self.state.servers[target_server_id]
        if target_ws is None:
            return
            
        advertised = 0
        
        for user_id in list(self.state.local_users.keys()):
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
                await target_ws.send(serialize_message(advertise_msg))
                advertised += 1
                await asyncio.sleep(0)
            except Exception as e:
                print(f"[Federation] Failed to advertise {username} to {target_server_id}: {e}")
                break
        
        if advertised > 0:
            print(f"[Federation] Advertised {advertised} users to {target_server_id}")
    
    async def handler(self, ws):
        user_id = None
        server_id = None
        
        try:
            first_msg = await ws.recv()
            msg = deserialize_message(first_msg)
            msg_type = msg.get("type")
            
            if msg_type == "SERVER_HELLO_JOIN":
                await self.handle_server_message(msg, ws)
                server_id = msg.get("from")
                
                async for raw in ws:
                    msg = deserialize_message(raw)
                    await self.handle_server_message(msg, ws)
                return
            
            if msg_type == "SERVER_ANNOUNCE":
                sender = msg.get("from")
                payload = msg.get("payload", {})
                
                # Store this incoming connection
                self.state.add_server(sender, ws, payload.get("host"), payload.get("port"), payload.get("pubkey"))
                
                await self.handle_server_message(msg, ws)
                server_id = sender
                
                # Advertise our users to this newly connected server
                await asyncio.sleep(0.2)
                await self._advertise_users_to_server(sender)
                
                # Keep handling server messages
                async for raw in ws:
                    msg = deserialize_message(raw)
                    await self.handle_server_message(msg, ws)
                return
            
            if msg_type == "USER_HELLO":
                user_id = await self.handle_user_hello(msg, ws)
                if not user_id:
                    return
            
            async for raw in ws:
                msg = deserialize_message(raw)
                await self.handle_client_message(msg, ws)
                
        finally:
            if user_id:
                username = self.state.remove_local_user(user_id)
                print(f"[Server] {username or user_id} disconnected")
                await self.presence.remove_user(user_id)
            
            if server_id:
                self.state.remove_server(server_id)
                print(f"[Server] Server {server_id} disconnected")
    
    async def handle_server_message(self, msg, server_ws):
        msg_type = msg.get("type")
        
        if msg_type == "SERVER_HELLO_JOIN":
            await self.bootstrap.handle_hello_join(msg, server_ws)
        
        elif msg_type == "SERVER_ANNOUNCE":
            payload = msg.get("payload", {})
            sender = msg.get("from")
            ts = msg.get("ts")
            
            announce_id = f"{sender}-{ts}"
            
            if announce_id in self.seen_announcements:
                return
            
            self.seen_announcements.add(announce_id)
            
            in_addr_book = sender in self.state.server_addrs
            
            # Relay to other servers if this is a new announcement
            if not in_addr_book:
                relay_count = 0
                for srv_id, srv_ws in list(self.state.servers.items()):
                    if srv_id != sender and srv_ws is not None:
                        try:
                            await srv_ws.send(serialize_message(msg))
                            relay_count += 1
                        except Exception as e:
                            print(f"[Federation] Failed to relay to {srv_id}: {e}")
                
                if relay_count > 0:
                    print(f"[Federation] Relayed {sender} to {relay_count} peers")
            
            # Handle announcement for ourselves
            if sender not in self.state.servers or self.state.servers[sender] is None:
                self.state.add_server(sender, None, payload.get("host"), payload.get("port"), payload.get("pubkey"))
                print(f"[Federation] Server {sender} announced, connecting")
                asyncio.create_task(self._connect_to_server(sender, payload.get("host"), payload.get("port")))
            elif not in_addr_book:
                self.state.server_addrs[sender] = (payload.get("host"), payload.get("port"))
                if payload.get("pubkey"):
                    self.state.server_pubkeys[sender] = payload.get("pubkey")
                asyncio.create_task(self._advertise_users_to_server(sender))
            else:
                asyncio.create_task(self._advertise_users_to_server(sender))
        
        elif msg_type == "USER_ADVERTISE":
            await self.presence.handle_user_advertise(msg)
        
        elif msg_type == "USER_REMOVE":
            await self.presence.handle_user_remove(msg)
        
        elif msg_type == "SERVER_DELIVER":
            await self.delivery.handle_server_deliver(msg)
        
        elif msg_type == "HEARTBEAT":
            self.health.handle_heartbeat(msg)
        
        elif msg_type == "MSG_PUBLIC_CHANNEL":
            recipient_id = msg.get("to")
            if self.state.is_local_user(recipient_id):
                try:
                    await self.state.local_users[recipient_id].send(serialize_message(msg))
                except Exception as e:
                    print(f"[Server] Failed to relay MSG_PUBLIC_CHANNEL: {e}")
        
        elif msg_type in ["FILE_START", "FILE_CHUNK", "FILE_END"]:
            recipient_id = msg.get("to")
            if self.state.is_local_user(recipient_id):
                try:
                    await self.state.local_users[recipient_id].send(serialize_message(msg))
                except Exception as e:
                    print(f"[Server] Failed to relay {msg_type}: {e}")
    
    async def handle_user_hello(self, msg, ws):
        sender = msg.get("from")
        username = msg.get("payload", {}).get("username", sender)
        pubkey = msg.get("payload", {}).get("pubkey", "")
        ts = msg.get("ts", int(time.time()*1000))
        
        if username in self.state.username_to_id:
            err = {"type":"ERROR","from":"server_1","to":sender,"ts":ts,
                   "payload":{"code":"NAME_IN_USE","detail":username},"sig":""}
            await ws.send(serialize_message(err))
            return None
        
        user_id = sender
        self.state.add_local_user(user_id, ws, username, pubkey)
        print(f"[Server] {username} connected")
        
        ack_payload = {"msg_ref":"USER_HELLO","user_id":user_id,"username":username}
        ack_msg = {"type":"ACK","from":"server_1","to":user_id,"ts":ts,"payload":ack_payload,
                   "sig":b64url_encode(rsa_crpt.sign_message(
                       rsa_crpt.canonical_payload_bytes(ack_payload), self.state.private_key))}
        await ws.send(serialize_message(ack_msg))
        
        for other_id, other_ws in self.state.local_users.items():
            if other_id != user_id:
                try:
                    await other_ws.send(serialize_message(msg))
                except: pass
        
        for existing_id, existing_pub in self.state.user_keys.items():
            if existing_id != user_id:
                hello_msg = {"type":"USER_HELLO","from":existing_id,"to":user_id,"ts":ts,
                             "payload":{"pubkey":existing_pub,"username":self.state.usernames.get(existing_id, existing_id)},
                             "sig":""}
                try:
                    await ws.send(serialize_message(hello_msg))
                except: pass
        
        await self.presence.advertise_user(user_id, {"username": username, "pubkey": pubkey})
        
        return user_id
    
    async def handle_client_message(self, msg, ws):
        msg_type = msg.get("type")
        sender = msg.get("from")
        ts = msg.get("ts", int(time.time()*1000))
        
        if msg_type == "USER_LIST":
            all_users = self.state.get_all_users()
            users_info = [{"uuid": uid, "username": self.state.usernames.get(uid, uid)} 
                          for uid in all_users]
            reply = {"type":"USER_LIST_REPLY","from":"server_1","to":sender,"ts":ts,
                     "payload":{"users":users_info},"sig":""}
            await ws.send(serialize_message(reply))
        
        elif msg_type == "MSG_PRIVATE":
            await self.handle_private_message(msg, ws)
        
        elif msg_type == "MSG_PUBLIC_CHANNEL":
            await self.handle_public_channel(msg, ws)
        
        elif msg_type in ["FILE_START","FILE_CHUNK","FILE_END"]:
            await self.handle_file_message(msg, ws)
    
    async def handle_private_message(self, msg, ws):
        sender = msg.get("from")
        recipient_raw = msg.get("to")
        recipient = self.state.resolve_username(recipient_raw)
        ts = msg.get("ts")
        
        msg_key = (sender, recipient, ts)
        current_time = int(time.time() * 1000)
        
        self.recent_messages = {k: v for k, v in self.recent_messages.items() 
                                if current_time - k[2] < self.message_cache_ttl}
        
        if msg_key in self.recent_messages:
            return
        
        self.recent_messages[msg_key] = True
        
        if recipient not in self.state.user_locations:
            err = {"type":"ERROR","from":"server_1","to":sender,"ts":msg.get("ts"),
                   "payload":{"code":"USER_NOT_FOUND","detail":recipient_raw},"sig":""}
            await ws.send(serialize_message(err))
            return
        
        if self.state.is_local_user(recipient):
            await self.state.local_users[recipient].send(serialize_message(msg))
            print(f"[Server] Delivered private message (LOCAL)")
        else:
            payload = msg.get("payload", {})
            success = await self.delivery.deliver_to_remote(
                recipient,
                payload.get("ciphertext"),
                self.state.usernames.get(sender, sender),
                self.state.user_keys.get(sender, ""),
                payload.get("content_sig")
            )
            if not success:
                err = {"type":"ERROR","from":"server_1","to":sender,"ts":msg.get("ts"),
                       "payload":{"code":"USER_NOT_FOUND","detail":recipient},"sig":""}
                await ws.send(serialize_message(err))
    
    async def handle_public_channel(self, msg, ws):
        sender = msg.get("from")
        shares = msg.get("payload", {}).get("shares", [])
        ts = msg.get("ts", int(time.time()*1000))
        
        for share in shares:
            member_raw = share.get("member")
            member = self.state.resolve_username(member_raw)
            
            deliver_msg = {"type":"MSG_PUBLIC_CHANNEL","from":sender,"to":member,"ts":ts,
                           "payload":{"shares":[share]}, "sig":""}
            
            if self.state.is_local_user(member):
                try:
                    await self.state.local_users[member].send(serialize_message(deliver_msg))
                except: pass
            else:
                recipient_location = self.state.get_user_location(member)
                if recipient_location and recipient_location != "local":
                    target_server_id = recipient_location
                    if target_server_id in self.state.servers:
                        try:
                            deliver_msg["to"] = member
                            await self.state.servers[target_server_id].send(serialize_message(deliver_msg))
                            print(f"[Server] Forwarded message to {target_server_id}")
                        except Exception as e:
                            print(f"[Server] Failed to forward message: {e}")
    
    async def handle_file_message(self, msg, ws):
        recipient = msg.get("to")
        msg_type = msg.get("type")
        
        recipient_id = self.state.resolve_username(recipient)
        
        if self.state.is_local_user(recipient_id):
            try:
                msg["to"] = recipient_id
                await self.state.local_users[recipient_id].send(serialize_message(msg))
                print(f"[Server] Relayed {msg_type} (LOCAL)")
            except Exception as e:
                print(f"[Server] Failed to relay {msg_type}: {e}")
        else:
            recipient_location = self.state.get_user_location(recipient_id)
            if recipient_location and recipient_location != "local":
                target_server_id = recipient_location
                if target_server_id in self.state.servers:
                    try:
                        msg["to"] = recipient_id
                        await self.state.servers[target_server_id].send(serialize_message(msg))
                        print(f"[Server] Forwarded {msg_type} to {target_server_id}")
                    except Exception as e:
                        print(f"[Server] Failed to forward {msg_type}: {e}")

async def main(port, server_id, bootstrap_list=None, is_introducer=False):
    server = ChatServer(port, server_id, bootstrap_list, is_introducer)
    await server.start()

if __name__ == "__main__":
    import sys
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8765
    server_id = sys.argv[2] if len(sys.argv) > 2 else None
    
    is_intro = "--introducer" in sys.argv
    bootstrap = []
    
    if "--bootstrap" in sys.argv:
        idx = sys.argv.index("--bootstrap")
        if idx + 1 < len(sys.argv):
            addrs = sys.argv[idx + 1].split(",")
            for addr in addrs:
                host, p = addr.split(":")
                bootstrap.append({"host": host, "port": int(p), "pubkey": ""})
    
    asyncio.run(main(port, server_id, bootstrap, is_intro))