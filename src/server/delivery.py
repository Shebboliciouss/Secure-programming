# src/server/delivery.py
# Forwarded message delivery protocol (Section 8.3)

import time
from src.utils.json_utils import serialize_message
from src.crypto import rsa_crpt

def b64url_encode(data: bytes) -> str:
    import base64
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')

class DeliveryManager:
    """Handles message delivery to local and remote users"""
    
    def __init__(self, state):
        self.state = state
    
    async def deliver_to_remote(self, recipient_id, ciphertext, sender_name, sender_pub, content_sig):
        """Deliver message to user on remote server (Section 8.3)"""
        recipient_location = self.state.get_user_location(recipient_id)
        
        print(f"[Delivery] DEBUG: deliver_to_remote called for {recipient_id}")
        print(f"[Delivery] DEBUG: recipient_location = {recipient_location}")
        
        if not recipient_location or recipient_location == "local":
            print(f"[Delivery] DEBUG: Recipient is local or not found, returning False")
            return False
        
        target_server_id = recipient_location
        
        if target_server_id not in self.state.servers:
            print(f"[Delivery] Server {target_server_id} not connected")
            return False
        
        payload = {
            "user_id": recipient_id,
            "ciphertext": ciphertext,
            "sender": sender_name,
            "sender_pub": sender_pub,
            "content_sig": content_sig
        }
        
        deliver_msg = {
            "type": "SERVER_DELIVER",
            "from": self.state.server_id,
            "to": target_server_id,
            "ts": int(time.time()*1000),
            "payload": payload,
            "sig": b64url_encode(rsa_crpt.sign_message(
                rsa_crpt.canonical_payload_bytes(payload), self.state.private_key))
        }
        
        try:
            await self.state.servers[target_server_id].send(serialize_message(deliver_msg))
            print(f"[Delivery] Forwarded message from {sender_name} to {target_server_id} for user {recipient_id}")
            return True
        except Exception as e:
            print(f"[Delivery] Failed to forward: {e}")
            return False
    
    async def handle_server_deliver(self, msg):
        """Handle SERVER_DELIVER - message for local user"""
        payload = msg.get("payload", {})
        user_id = payload.get("user_id")
        
        print(f"[Delivery] DEBUG: Received SERVER_DELIVER for user_id={user_id}")
        print(f"[Delivery] DEBUG: is_local_user({user_id}) = {self.state.is_local_user(user_id)}")
        
        if not self.state.is_local_user(user_id):
            print(f"[Delivery] Received message for non-local user {user_id}")
            return
        
        # Reconstruct message for client
        client_msg = {
            "type": "MSG_PRIVATE",
            "from": payload.get("sender"),
            "to": user_id,
            "ts": msg.get("ts"),
            "payload": {
                "ciphertext": payload.get("ciphertext"),
                "content_sig": payload.get("content_sig")
            },
            "sig": ""
        }
        
        try:
            await self.state.local_users[user_id].send(serialize_message(client_msg))
            print(f"[Delivery] Delivered to local user {self.state.usernames.get(user_id, user_id)}")
        except Exception as e:
            print(f"[Delivery] Failed to deliver: {e}")