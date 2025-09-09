#server purpose 
# accepts and listens to message from client
#receives messages from clients 
#echos the message back to client 
#manages connections and check who is online and handle disconnction

#if message type os user hello send back aCK

from src.utils.json_utils import deserialize_message
from src.utils.json_utils import serialize_message
#imports asynchio library and websockets server and clients 
import asyncio
import websockets
import time 

local_users = {}  # user_id -> websocket

async def handler(websocket):   
    async for message in websocket:
        try:
            msg = deserialize_message(message)
            print("Received:", msg)

         # Handle USER_HELLO specifically
            if msg["type"] == "USER_HELLO":
                # Create ACK message
                ack = {
                    "type": "ACK",
                    "from": "server_1",
                    "to": msg["from"],  # send back to Alice
                    "ts": int(time.time() * 1000),
                    "payload": {"msg_ref": msg["type"]},
                    "sig": ""  # will add signing later
                }
                await websocket.send(serialize_message(ack))
                print("Sent ACK:", ack)

            elif msg_type == "MSG_PRIVATE":
                recipient = msg["to"]
                if recipient in local_users:
                    # Deliver directly if recipient is local
                    await local_users[recipient].send(serialize_message(msg))
                    print(f"Delivered MSG_PRIVATE to {recipient}")
                else:
                    # For now, just echo back to sender if recipient unknown
                    error_msg = {
                        "type": "ERROR",
                        "from": "server_1",
                        "to": sender,
                        "ts": int(time.time() * 1000),
                        "payload": {"code": "USER_NOT_FOUND", "detail": f"{recipient} not registered"},
                        "sig": ""
                    }
                    await websocket.send(serialize_message(error_msg))
                    print("Sent ERROR:", error_msg)
            else:
                await websocket.send(serialize_message(msg))
                print("Echoed message:", msg)        


        except websockets.ConnectionClosed:
        # Remove user on disconnect
         for user_id, ws in list(local_users.items()):
            if ws == websocket:
                print(f"{user_id} disconnected.")
                del local_users[user_id]
                break

async def main():
    async with websockets.serve(handler, "localhost", 8765):
        print("Server started on ws://localhost:8765")
        await asyncio.Future()  # run forever

asyncio.run(main())