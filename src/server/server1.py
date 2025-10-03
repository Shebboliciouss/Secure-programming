import asyncio
import websockets
import time
from src.utils.json_utils import deserialize_message, serialize_message
from src.crypto import rsa_crpt

local_users = {}  # user_id -> websocket
user_keys = {}    # user_id -> pubkey PEM

server_private, server_public = rsa_crpt.generate_rsa_keypair()

async def handler(ws):
    user_id = None
    try:
        async for message in ws:
            msg = deserialize_message(message)
            msg_type = msg.get("type")
            sender_id = msg.get("from")

            if msg_type=="USER_HELLO":
                user_id = sender_id
                if user_id in local_users:
                    await ws.send(serialize_message({"type":"ERROR","from":"server_1","to":user_id,"ts":int(time.time()*1000),"payload":{"code":"NAME_IN_USE"}}))
                    continue
                local_users[user_id] = ws
                user_keys[user_id] = msg.get("payload", {}).get("pubkey","")

                # ACK
                ack = {"type":"ACK","from":"server_1","to":user_id,"ts":int(time.time()*1000),"payload":{"msg_ref":"USER_HELLO"},"sig":""}
                await ws.send(serialize_message(ack))

                # Notify others
                for other_id, other_ws in local_users.items():
                    if other_id==user_id: continue
                    await other_ws.send(serialize_message({"type":"USER_HELLO","from":user_id,"to":"all","ts":int(time.time()*1000),"payload":{"pubkey":user_keys[user_id]},"sig":""}))

                # Send existing users to new user
                for existing_id, existing_pub in user_keys.items():
                    if existing_id==user_id: continue
                    await ws.send(serialize_message({"type":"USER_HELLO","from":existing_id,"to":user_id,"ts":int(time.time()*1000),"payload":{"pubkey":existing_pub},"sig":""}))
                continue

            elif msg_type=="USER_LIST":
                await ws.send(serialize_message({"type":"USER_LIST_REPLY","from":"server_1","to":sender_id,"ts":int(time.time()*1000),"payload":{"users": list(local_users.keys())},"sig":""}))
                continue

            elif msg_type=="MSG_PRIVATE":
                recipient = msg.get("to")
                if recipient in local_users:
                    await local_users[recipient].send(serialize_message(msg))
                continue

            elif msg_type=="MSG_PUBLIC_CHANNEL":
                shares = msg.get("payload", {}).get("shares", [])
                for share in shares:
                    member = share.get("member")
                    if member in local_users:
                        await local_users[member].send(serialize_message({
                            "type":"MSG_PUBLIC_CHANNEL",
                            "from": sender_id,
                            "to": member,
                            "ts": msg.get("ts", int(time.time()*1000)),
                            "payload": {"ciphertext": share.get("ciphertext"), "content_sig": share.get("content_sig"), "sender_pub": user_keys.get(sender_id)},
                            "sig":""
                        }))
                continue

    finally:
        if user_id in local_users: del local_users[user_id]
        if user_id in user_keys: del user_keys[user_id]

async def main():
    async with websockets.serve(handler, "localhost", 8765):
        print("Server running at ws://localhost:8765")
        await asyncio.Future()

if __name__=="__main__":
    asyncio.run(main())
