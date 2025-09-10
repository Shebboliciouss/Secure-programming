import asyncio
import websockets
import time 

from src.utils.json_utils import deserialize_message
from src.utils.json_utils import serialize_message

# Function to format messages nicely
def format_message(data):
    msg_type = data.get("type")
    sender = data.get("from")
    recipient = data.get("to")
    payload = data.get("payload", {})

    if msg_type == "MSG_PRIVATE":
        text = payload.get("text", "")
        return f"[{sender} → {recipient}]: {text}"
    elif msg_type == "ACK":
        ref = payload.get("msg_ref", "")
        return f"[Server → {recipient}]: ACK for {ref}"
    elif msg_type == "ERROR":
        code = payload.get("code", "")
        detail = payload.get("detail", "")
        return f" [Server → {recipient}]: ERROR {code} - {detail}"
    elif msg_type == "USER_LIST_REPLY":
        users = payload.get("users", [])
        return f"[Server → {recipient}]: Online users: {', '.join(users)}"
    else:
        return f"[{sender} → {recipient}]: {payload}"
        
async def client(user_id):
    uri = "ws://localhost:8765"
    async with websockets.connect(uri) as websocket:
        # Send USER_HELLO
        msg = {
            "type": "USER_HELLO",
            "from": user_id,
            "to": "server_1",
            "ts": int(time.time() * 1000),
            "payload": {"client": "cli-v1", "pubkey": "BASE64_PUBKEY"},
            "sig": ""
        }
        await websocket.send(serialize_message(msg))
        print("Sent:", msg)

        async def send_messages():
            while True:
                user_input = await asyncio.get_event_loop().run_in_executor(None, input, "")
                if user_input.lower() == "/quit":
                    print(f"[{user_id}] Disconnecting...")
                    await websocket.close()
                    break
                elif user_input.lower() == "/who":
                    msg = {
                        "type": "USER_LIST",
                        "from": user_id,
                        "to": "server_1",
                        "ts": int(time.time() * 1000),
                        "payload": {},
                        "sig": ""
                    }
                    await websocket.send(serialize_message(msg))
                elif ":" in user_input:
                    recipient, text = user_input.split(":", 1)
                    msg = {
                        "type": "MSG_PRIVATE",
                        "from": user_id,
                        "to": recipient.strip(),
                        "ts": int(time.time() * 1000),
                        "payload": {"text": text.strip()},
                        "sig": ""
                    }
                    await websocket.send(serialize_message(msg))
                else:
                    print(" Invalid command. Use <recipient>: <message>, /who, or /quit.")

        async def receive_messages():
            try:
                async for reply in websocket:
                    data = deserialize_message(reply)
                    print("\n📩", format_message(data))
            except websockets.ConnectionClosed:
                print(f"[{user_id}] Connection closed")

        # 👇 Keep both running until /quit or disconnect
        await asyncio.gather(send_messages(), receive_messages())


if __name__ == "__main__":
    username = input("Enter your username: ")
    asyncio.run(client(username))

#Client built a USER_HELLO message (Alice introducing herself).

#Client serialized it into JSON → sent to server over WebSocket.

#Server deserialized the JSON → printed it → re-serialized → sent it back.
