
# server.py
# Server purpose:
# - Accepts and listens to messages from clients
# - Receives messages from clients and routes them
# - Manages connections, checks who is online, and handles disconnections
# - If message type is USER_HELLO, sends back ACK
import asyncio
import websockets
import time
import base64
import json
from src.utils.json_utils import deserialize_message, serialize_message
from src.crypto import rsa_crpt

# ------------------ Helpers ------------------

def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')

def b64url_decode(data: str) -> bytes:
    rem = len(data) % 4
    if rem:
        data += '=' * (4 - rem)
    return base64.urlsafe_b64decode(data)

def canonical_payload_bytes(payload: dict) -> bytes:
    return json.dumps(payload, separators=(',', ':'), sort_keys=True).encode('utf-8')

# ------------------ Globals ------------------

local_users = {}  # user_id -> websocket
user_keys = {}    # user_id -> pubkey PEM
server_private, server_public = rsa_crpt.generate_rsa_keypair()

# ------------------ Handlers ------------------

async def handler(websocket):
    user_id = None
    try:
        async for message in websocket:
            msg = deserialize_message(message)
            msg_type = msg.get("type")
            sender = msg.get("from")
            ts = msg.get("ts", int(time.time() * 1000))

            print(f"[Server] Received {msg_type} from {sender}")

            if msg_type == "USER_HELLO":
                requested_id = sender
                if requested_id in local_users:
                    err_msg = {
                        "type": "ERROR",
                        "from": "server_1",
                        "to": requested_id,
                        "ts": ts,
                        "payload": {"code": "NAME_IN_USE", "detail": f"{requested_id} already connected"},
                        "sig": ""
                    }
                    await websocket.send(serialize_message(err_msg))
                    print(f"[Server] Rejected duplicate username {requested_id}")
                    return

                user_id = requested_id
                local_users[user_id] = websocket
                user_keys[user_id] = msg["payload"].get("pubkey", "")
                print(f"[Server] {user_id} connected")

                # ACK
                ack_payload = {"msg_ref": "USER_HELLO"}
                ack_msg = {
                    "type": "ACK",
                    "from": "server_1",
                    "to": user_id,
                    "ts": ts,
                    "payload": ack_payload,
                    "sig": b64url_encode(rsa_crpt.sign_message(canonical_payload_bytes(ack_payload), server_private))
                }
                await websocket.send(serialize_message(ack_msg))
                print(f"[Server] Sent ACK to {user_id}")

                # Notify others
                for other_id, other_ws in local_users.items():
                    if other_id != user_id:
                        await other_ws.send(serialize_message(msg))
                        print(f"[Server] Announced {user_id} to {other_id}")

                # Send existing users to newcomer
                for existing_id, existing_pub in user_keys.items():
                    if existing_id != user_id:
                        hello_msg = {
                            "type": "USER_HELLO",
                            "from": existing_id,
                            "to": user_id,
                            "ts": ts,
                            "payload": {"pubkey": existing_pub},
                            "sig": ""
                        }
                        await websocket.send(serialize_message(hello_msg))
                        print(f"[Server] Sent {existing_id}'s pubkey to {user_id}")

            elif msg_type == "MSG_PRIVATE":
                recipient = msg.get("to")
                if recipient in local_users:
                    await local_users[recipient].send(serialize_message(msg))
                    print(f"[Server] Forwarded private msg from {sender} to {recipient}")
                else:
                    err = {
                        "type": "ERROR",
                        "from": "server_1",
                        "to": sender,
                        "ts": ts,
                        "payload": {"code": "USER_NOT_FOUND", "detail": recipient},
                        "sig": ""
                    }
                    await websocket.send(serialize_message(err))

            elif msg_type == "MSG_PUBLIC_CHANNEL":
                shares = msg.get("payload", {}).get("shares", [])
                for share in shares:
                    member = share.get("member")
                    if member in local_users:
                        deliver_msg = {
                            "type": "MSG_PUBLIC_CHANNEL",
                            "from": sender,
                            "to": member,
                            "ts": ts,
                            "payload": {
                                "ciphertext": share.get("ciphertext"),
                                "content_sig": share.get("content_sig"),
                                "sender_pub": user_keys.get(sender)
                            },
                            "sig": ""
                        }
                        await local_users[member].send(serialize_message(deliver_msg))
                        print(f"[Server] Broadcast from {sender} to {member}")

            elif msg_type == "USER_LIST":
                reply = {
                    "type": "USER_LIST_REPLY",
                    "from": "server_1",
                    "to": sender,
                    "ts": ts,
                    "payload": {"users": list(local_users.keys())},
                    "sig": ""
                }
                await websocket.send(serialize_message(reply))
                print(f"[Server] Sent user list to {sender}")

            elif msg_type == "FILE_TRANSFER":
                recipient = msg.get("to")
                if recipient in local_users:
                    await local_users[recipient].send(serialize_message(msg))
                    print(f"[Server] Forwarded file from {sender} to {recipient}")
                else:
                    err = {
                        "type": "ERROR",
                        "from": "server_1",
                        "to": sender,
                        "ts": ts,
                        "payload": {"code": "USER_NOT_FOUND", "detail": recipient},
                        "sig": ""
                    }
                    await websocket.send(serialize_message(err))
                    print(f"[Server] File transfer failed: {recipient} not found")

    finally:
        if user_id:
            local_users.pop(user_id, None)
            user_keys.pop(user_id, None)
            print(f"[Server] {user_id} disconnected")

# ------------------ Run ------------------

async def main():
    async with websockets.serve(handler, "localhost", 8765):
        print("Server started on ws://localhost:8765")
        await asyncio.Future()

if __name__ == "__main__":
    asyncio.run(main())



