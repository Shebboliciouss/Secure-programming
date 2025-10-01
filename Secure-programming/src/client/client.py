import asyncio
import websockets
import time
from src.utils.protocol import (
    serialize_message, deserialize_message, create_message,
    HELLO_MSG, MSG_PRIVATE
)

# Format messages nicely
def format_message(data):
    msg_type = data.get("type")
    sender = data.get("from")
    recipient = data.get("to")
    payload = data.get("payload", {})

    if msg_type == MSG_PRIVATE or msg_type == "USER_DELIVER":
        text = payload.get("text", "")
        return f"[{sender} → {recipient}]: {text}"
    elif msg_type == "ACK":
        ref = payload.get("msg_ref", "")
        return f"[Server → {recipient}]: ✅ ACK for {ref}"
    elif msg_type == "ERROR":
        code = payload.get("code", "")
        detail = payload.get("detail", "")
        return f"[Server → {recipient}]: ❌ ERROR {code} - {detail}"
    elif msg_type == "USER_LIST_REPLY":
        users = payload.get("users", [])
        return f"[Server → {recipient}]: 👥 Online users: {', '.join(users)}"
    else:
        return f"[{sender} → {recipient}]: {payload}"


async def client(user_id, server_port):
    uri = f"ws://localhost:{server_port}"
    async with websockets.connect(uri) as websocket:
        # Send USER_HELLO
        hello = create_message(
            HELLO_MSG,
            sender=user_id,
            recipient="server_1",
            payload={"client": "cli-v1", "pubkey": "BASE64_PUBKEY"}
        )
        await websocket.send(serialize_message(hello))
        print(f"👋 Sent USER_HELLO as {user_id}")

        async def send_messages():
            while True:
                user_input = await asyncio.get_event_loop().run_in_executor(None, input, "")

                if user_input.lower() == "/quit":
                    print(f"[{user_id}] Disconnecting...")
                    await websocket.close()
                    break

                elif user_input.lower() == "/who":
                    req = create_message("USER_LIST", user_id, "server_1", {})
                    await websocket.send(serialize_message(req))

                elif user_input.lower() == "/help":
                    print("\nCommands:")
                    print("  <recipient>: <message>  → Send private message")
                    print("  /who                   → Show online users")
                    print("  /quit                  → Disconnect")
                    print("  /help                  → Show this help\n")

                elif ":" in user_input:
                    recipient, text = user_input.split(":", 1)
                    msg = create_message(
                        MSG_PRIVATE,
                        sender=user_id,
                        recipient=recipient.strip(),
                        payload={"text": text.strip()}
                    )
                    await websocket.send(serialize_message(msg))
                else:
                    print("⚠️ Invalid command. Use <recipient>: <message>, /who, /quit, or /help.")

        async def receive_messages():
            try:
                async for reply in websocket:
                    data = deserialize_message(reply)
                    print("\n📩", format_message(data))
            except websockets.ConnectionClosed:
                print(f"[{user_id}] Connection closed")

        # Run both tasks until /quit
        await asyncio.gather(send_messages(), receive_messages())


if __name__ == "__main__":
    username = input("Enter your username: ")
    port = int(input("Enter server port (e.g., 8765 or 8766): "))
    asyncio.run(client(username, port))


#Client built a USER_HELLO message (Alice introducing herself).

#Client serialized it into JSON → sent to server over WebSocket.

#Server deserialized the JSON → printed it → re-serialized → sent it back.
