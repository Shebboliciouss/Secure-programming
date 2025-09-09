#server purpose 
# accepts and listens to message from client
#receives messages from clients 
#echos the message back to client 
#manages connections and check who is online and handle disconnction


from src.utils.json_utils import deserialize_message
from src.utils.json_utils import serialize_message
#imports asynchio library and websockets server and clients 
import asyncio
import websockets

async def handler(websocket):
    async for message in websocket:
        try:
            msg = deserialize_message(message)
            print("Received:", msg)

            # Echo for now (later: routing)
            await websocket.send(serialize_message(msg))
            print("Sent back:", msg)

        except Exception as e:
            print("Error handling message:", e)
            await websocket.close(code=1011, reason=str(e))

async def main():
    async with websockets.serve(handler, "localhost", 8765):
        print("Server started on ws://localhost:8765")
        await asyncio.Future()  # run forever

asyncio.run(main())