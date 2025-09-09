import asyncio
import websockets
import time 
#define the asynchronouse function hello
#and connect to port 

from src.utils.json_utils import deserialize_message
from src.utils.json_utils import serialize_message

async def client():
    uri = "ws://localhost:8765"
    #send message ti the client 
    async with websockets.connect(uri) as websocket:
        # Build a USER_HELLO message
        msg = {
            "type": "USER_HELLO",
            "from": "Alice",
            "to": "server_1",
            "ts": int(time.time() * 1000),
            "payload": {"client": "cli-v1", "pubkey": "BASE64_PUBKEY"},
            "sig": ""
        }
        # Serialize and send
        await websocket.send(serialize_message(msg))
        print("Sent:", msg)
        #then awaut reply from the server 
        reply = await websocket.recv()

        response=deserialize_message(reply)
        print(f"📩 Reply from server: {response}")

if __name__ == "__main__":
    asyncio.run(client())
