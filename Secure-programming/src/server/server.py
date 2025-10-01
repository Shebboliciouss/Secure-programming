# server purpose
# - accepts and listens to messages from clients
# - receives messages from clients
# - echoes or forwards messages
# - manages connections and online users
# - supports server-to-server routing (peer bootstrap, gossip, forwarding)

import asyncio
import websockets
import time
import sys

from src.utils.protocol import (
    serialize_message, deserialize_message, create_message,
    HELLO_MSG, MSG_PRIVATE, MSG_USER_DELIVER,
    PEER_HELLO_JOIN, PEER_WELCOME, PEER_HELLO_LINK,
    USER_ADVERTISE, USER_REMOVE,
    PEER_DELIVER, HEARTBEAT
)


# Global tables

known_peers = {}        # server_id -> websocket
user_locations = {}     # username -> server_id
local_users = {}        # username -> websocket
self_id = None          # this server's ID



# Helpers

async def broadcast_to_peers(msg):
    serialized = serialize_message(msg)
    for peer in list(known_peers.values()):
        try:
            await peer.send(serialized)
        except:
            print(f"[{self_id}] failed to send to a peer")


async def deliver_to_local(username, text):
    if username in local_users:
        ws = local_users[username]
        msg = create_message(MSG_USER_DELIVER, self_id, username, {"text": text})
        await ws.send(serialize_message(msg))
        print(f"[{self_id}] delivered message to {username}")


async def connect_to_peer(peer_id, host, port):

    try:
        uri = f"ws://{host}:{port}"
        ws = await websockets.connect(uri)
        known_peers[peer_id] = ws
        join_msg = create_message(PEER_HELLO_JOIN, self_id, peer_id, {})
        await ws.send(serialize_message(join_msg))
        print(f"[{self_id}] connected to peer {peer_id} at {uri}")

        async def listen_peer():
            try:
                async for raw in ws:
                    msg = deserialize_message(raw)
                    await handle_peer_message(ws, msg)
            except websockets.ConnectionClosed:
                print(f"[{self_id}] lost connection to {peer_id}")
                known_peers.pop(peer_id, None)

        asyncio.create_task(listen_peer())

    except Exception as e:
        print(f"[{self_id}] failed to connect to peer {peer_id}: {e}")


# Peer message handling

async def handle_peer_message(peer, msg):
    msg_type = msg["type"]

    if msg_type == PEER_HELLO_JOIN:
        server_id = msg["from"]
        known_peers[server_id] = peer
        print(f"[{self_id}] peer {server_id} joined")
        reply = create_message(PEER_WELCOME, self_id, server_id, {"peers": list(known_peers.keys())})
        await peer.send(serialize_message(reply))

    elif msg_type == PEER_WELCOME:
        for pid in msg["payload"]["peers"]:
            if pid not in known_peers and pid != self_id:
                print(f"[{self_id}] discovered peer {pid}")
        reply = create_message(PEER_HELLO_LINK, self_id, msg["from"], {})
        await peer.send(serialize_message(reply))

    elif msg_type == PEER_HELLO_LINK:
        server_id = msg["from"]
        known_peers[server_id] = peer
        print(f"[{self_id}] link established with {server_id}")

    elif msg_type == USER_ADVERTISE:
        user = msg["payload"]["user"]
        server = msg["payload"]["server"]
        user_locations[user] = server
        print(f"[{self_id}] learned {user} is at {server}")

    elif msg_type == USER_REMOVE:
        user = msg["payload"]["user"]
        user_locations.pop(user, None)
        print(f"[{self_id}] removed {user}")

    elif msg_type == PEER_DELIVER:
        to_user = msg["payload"]["to"]
        if to_user in local_users:
            await deliver_to_local(to_user, f"{msg['payload']['from']}: {msg['payload']['text']}")
        else:
            print(f"[{self_id}] user {to_user} not local")

    elif msg_type == HEARTBEAT:
        pass



async def handle_client_message(ws, msg):
    msg_type = msg.get("type")

    if msg_type == HELLO_MSG:
        user_id = msg["from"]
        local_users[user_id] = ws
        user_locations[user_id] = self_id
        print(f"[{self_id}] user {user_id} joined")

        # ACK
        ack = create_message("ACK", self_id, user_id, {"msg_ref": HELLO_MSG})
        await ws.send(serialize_message(ack))

        # gossip to peers
        payload = {"user": user_id, "server": self_id}
        gossip = create_message(USER_ADVERTISE, self_id, "*", payload)
        await broadcast_to_peers(gossip)

    elif msg_type == MSG_PRIVATE:
        sender = msg["from"]
        recipient = msg["to"]
        text = msg["payload"].get("text")

        if recipient in local_users:
            await deliver_to_local(recipient, f"{sender}: {text}")
        elif recipient in user_locations:
            target_server = user_locations[recipient]
            if target_server in known_peers:
                peer = known_peers[target_server]
                fwd = create_message(
                    PEER_DELIVER, self_id, target_server,
                    {"from": sender, "to": recipient, "text": text}
                )
                await peer.send(serialize_message(fwd))
                print(f"[{self_id}] forwarded {sender} -> {recipient} via {target_server}")
            else:
                print(f"[{self_id}] knows {recipient} is at {target_server}, but no connection")
        else:
            error_msg = create_message(
                "ERROR", self_id, sender,
                {"code": "USER_NOT_FOUND", "detail": f"{recipient} not registered"}
            )
            await ws.send(serialize_message(error_msg))
            print(f"[{self_id}] sent ERROR")

    elif msg_type == "USER_LIST":
        user_list = list(local_users.keys())
        reply = create_message("USER_LIST_REPLY", self_id, msg["from"], {"users": user_list})
        await ws.send(serialize_message(reply))
        print(f"[{self_id}] sent user list to {msg['from']}")



async def handler(websocket, path):
    try:
        async for raw in websocket:
            msg = deserialize_message(raw)
            msg_type = msg.get("type")

            if msg_type.startswith("PEER_") or msg_type in (USER_ADVERTISE, USER_REMOVE, PEER_DELIVER, HEARTBEAT):
                await handle_peer_message(websocket, msg)
            else:
                await handle_client_message(websocket, msg)

    except websockets.ConnectionClosed:
        print(f"[{self_id}] connection closed")

    finally:
        remove_ids = [u for u, ws in local_users.items() if ws == websocket]
        for u in remove_ids:
            del local_users[u]
            user_locations.pop(u, None)
            payload = {"user": u}
            gossip = create_message(USER_REMOVE, self_id, "*", payload)
            await broadcast_to_peers(gossip)
            print(f"[{self_id}] removed {u}")



async def main():
    global self_id
    if len(sys.argv) < 3:
        print("Usage: python -m src.server.server <server_id> <port> [--peer <peer_id>:<peer_port>]")
        return

    self_id = sys.argv[1]
    port = int(sys.argv[2])

   
    async with websockets.serve(handler, "localhost", port):
        print(f"[{self_id}] Server started on ws://localhost:{port}")

       
        if len(sys.argv) == 5 and sys.argv[3] == "--peer":
            peer_id, peer_port = sys.argv[4].split(":")
            asyncio.create_task(connect_to_peer(peer_id, "localhost", int(peer_port)))

        await asyncio.Future()


if __name__ == "__main__":
    asyncio.run(main())
