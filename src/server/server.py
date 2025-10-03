
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

# ------------------ Global state ------------------

local_users = {}  # user_id -> websocket
user_keys = {}    # user_id -> pubkey PEM

server_private, server_public = rsa_crpt.generate_rsa_keypair()

# ------------------ Handler ------------------

async def handler(websocket):
    user_id = None
    try:
        async for message in websocket:
            try:
                msg = deserialize_message(message)
                msg_type = msg.get("type")
                sender = msg.get("from")
                ts = msg.get("ts", int(time.time() * 1000))

                print(f"[Server] Received {msg_type} from {sender}")

                # --- USER_HELLO ---
                if msg_type == "USER_HELLO":
                    requested_id = sender
                    if requested_id in local_users:
                        # Username taken → reject without touching original
                        err_msg = {
                            "type": "ERROR",
                            "from": "server_1",
                            "to": requested_id,
                            "ts": ts,
                            "payload": {"code": "NAME_IN_USE", "detail": f"{requested_id} already connected"},
                            "sig": ""
                        }
                        await websocket.send(serialize_message(err_msg))
                        print(f"[Server] Username {requested_id} already in use")
                        # IMPORTANT: close connection without setting user_id
                        return

                    # Accept user
                    user_id = requested_id
                    local_users[user_id] = websocket
                    pubkey_pem = msg["payload"].get("pubkey")
                    if pubkey_pem:
                        user_keys[user_id] = pubkey_pem
                        print(f"[Server] Stored public key for {user_id}")

                    # Send ACK
                    ack_payload = {"msg_ref": "USER_HELLO"}
                    ack_msg = {
                        "type": "ACK",
                        "from": "server_1",
                        "to": user_id,
                        "ts": int(time.time() * 1000),
                        "payload": ack_payload,
                        "sig": b64url_encode(rsa_crpt.sign_message(canonical_payload_bytes(ack_payload), server_private))
                    }
                    await websocket.send(serialize_message(ack_msg))
                    print(f"[Server] Sent ACK to {user_id}")

                    # Broadcast new user's HELLO to others
                    for other_id, other_ws in local_users.items():
                        if other_id != user_id:
                            try:
                                await other_ws.send(serialize_message(msg))
                                print(f"[Server] Forwarded USER_HELLO of {user_id} to {other_id}")
                            except Exception:
                                pass

                    # Send existing users' keys to new user
                    for existing_id, existing_pub in user_keys.items():
                        if existing_id != user_id:
                            hello_msg = {
                                "type": "USER_HELLO",
                                "from": existing_id,
                                "to": user_id,
                                "ts": int(time.time() * 1000),
                                "payload": {"pubkey": existing_pub},
                                "sig": ""
                            }
                            try:
                                await websocket.send(serialize_message(hello_msg))
                                print(f"[Server] Sent {existing_id}'s public key to {user_id}")
                            except Exception:
                                pass

                # --- MSG_PRIVATE ---
                elif msg_type == "MSG_PRIVATE":
                    recipient = msg.get("to")
                    if recipient in local_users:
                        await local_users[recipient].send(serialize_message(msg))
                        print(f"[Server] Delivered private message from {sender} to {recipient}")

                # --- MSG_PUBLIC_CHANNEL ---
                elif msg_type == "MSG_PUBLIC_CHANNEL":
                    shares = msg.get("payload", {}).get("shares", [])
                    for share in shares:
                        member = share.get("member")
                        if member in local_users:
                            deliver_msg = {
                                "type": "MSG_PUBLIC_CHANNEL",
                                "from": sender,
                                "to": member,
                                "ts": msg.get("ts", int(time.time() * 1000)),
                                "payload": {
                                    "ciphertext": share.get("ciphertext"),
                                    "content_sig": share.get("content_sig"),
                                    "sender_pub": user_keys.get(sender)
                                },
                                "sig": ""
                            }
                            try:
                                await local_users[member].send(serialize_message(deliver_msg))
                                print(f"[Server] Delivered group message from {sender} to {member}")
                            except Exception:
                                pass  # silently skip offline members

                # --- USER_LIST ---
                elif msg_type == "USER_LIST":
                    reply = {
                        "type": "USER_LIST_REPLY",
                        "from": "server_1",
                        "to": sender,
                        "ts": int(time.time() * 1000),
                        "payload": {"users": list(local_users.keys())},
                        "sig": ""
                    }
                    await websocket.send(serialize_message(reply))
                    print(f"[Server] Sent user list to {sender}")

                # --- Other messages (echo) ---
                else:
                    await websocket.send(serialize_message(msg))
                    print(f"[Server] Echoed message from {sender}")

            except websockets.ConnectionClosed:
                print(f"[Server] Connection closed for {user_id}")
                break

    finally:
        # Cleanup on disconnect
        if user_id:
            local_users.pop(user_id, None)
            user_keys.pop(user_id, None)
            print(f"[Server] {user_id} disconnected")

# ------------------ Main ------------------

async def main():
    async with websockets.serve(handler, "localhost", 8765):
        print("Server started on ws://localhost:8765")
        await asyncio.Future()  # run forever

if __name__ == "__main__":
    asyncio.run(main())
