import asyncio
import websockets
import time 
#define the asynchronouse function hello
#and connect to port 

from src.utils.json_utils import deserialize_message
from src.utils.json_utils import serialize_message

#Client built a USER_HELLO message (Alice introducing herself).

#Client serialized it into JSON → sent to server over WebSocket.

#Server deserialized the JSON → printed it → re-serialized → sent it back.

#Client got the echo → deserialized it → printed the reply.
async def client(user_id, messages_to_send=None):
    uri = "ws://localhost:8765"
    #send message ti the client 
    async with websockets.connect(uri) as websocket:
        # Build a USER_HELLO message
        msg = {
            "type": "USER_HELLO",
            "from": user_id,
            "to": "server_1",
            "ts": int(time.time() * 1000),
            "payload": {"client": "cli-v1", "pubkey": "BASE64_PUBKEY"},
            "sig": ""
        }
        # Serialize and send
        await websocket.send(serialize_message(msg))
        print("Sent:", msg)

        async def send_messages():
            if messages_to_send:
                for msg in messages_to_send:
                    await asyncio.sleep(1)  # slight delay
                    await websocket.send(serialize_message(msg))
                    print(f"[{user_id}] Sent MSG_PRIVATE to {msg['to']}")
        
        async def receive_messages():
            try:
                async for reply in websocket:
                    data = deserialize_message(reply)
                    print(f"[{user_id}] Received: {data}")
            except websockets.ConnectionClosed:
                print(f"[{user_id}] Connection closed")

        await asyncio.gather(send_messages(), receive_messages())
   
# Example usage: Alice sends a private message to Bob
alice_msgs = [
    {
        "type": "MSG_PRIVATE",
        "from": "Alice",
        "to": "Bob",
        "ts": int(time.time() * 1000),
        "payload": {
            "ciphertext": "<b64cipher>",
            "iv": "<b64iv>",
            "tag": "<b64tag>",
            "wrapped_key": "<b64key>"
        },
        "sig": ""
    }
]

# Run two clients concurrently
async def main():
    await asyncio.gather(
        client("Alice", messages_to_send=alice_msgs),
        client("Bob")  # Bob just listens for messages
    )

if __name__ == "__main__":
    asyncio.run(main())
if __name__ == "__main__":
    asyncio.run(client())
