import asyncio
import websockets
import time
import base64
import json
from datetime import datetime
from src.crypto import rsa_crpt
from src.utils.json_utils import deserialize_message, serialize_message

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

def format_timestamp(ts: int) -> str:
    return datetime.fromtimestamp(ts/1000).strftime("%H:%M:%S")

def format_message(data, user_id):
    msg_type = data.get("type")
    sender = data.get("from")
    recipient = data.get("to")
    payload = data.get("payload", {})
    ts = data.get("ts", int(time.time() * 1000))
    ts_str = format_timestamp(ts)

    if msg_type == "ACK":
        ref = payload.get("msg_ref", "")
        return f"[{ts_str}] [Server → {recipient}]: ACK for {ref}"
    elif msg_type == "ERROR":
        code = payload.get("code", "")
        detail = payload.get("detail", "")
        if code == "NAME_IN_USE":
            return f"[{ts_str}] [System] Username already taken. Try another."
        elif code == "USER_NOT_FOUND":
            return f"[{ts_str}] [System] User not found: {detail}"
        else:
            return f"[{ts_str}] [System] ERROR {code} - {detail}"
    elif msg_type == "USER_LIST_REPLY":
        users = payload.get("users", [])
        return f"[{ts_str}] [Server → {recipient}]: Online users: {', '.join(users)}"
    else:
        return None

# ------------------ Global Keys ------------------

private_key, public_key = rsa_crpt.generate_rsa_keypair()
known_pubkeys = {}  # username -> RSA public key

# ------------------ Client ------------------

async def client(username):
    uri = "ws://localhost:8765"

    async with websockets.connect(uri) as websocket:
        # Send USER_HELLO
        hello_payload = {
            "client": "cli-v1",
            "pubkey": b64url_encode(rsa_crpt.export_public_key(public_key))
        }
        ts = int(time.time() * 1000)
        hello_msg = {
            "type": "USER_HELLO",
            "from": username,
            "to": "server_1",
            "ts": ts,
            "payload": hello_payload,
            "sig": b64url_encode(rsa_crpt.sign_message(canonical_payload_bytes(hello_payload), private_key))
        }
        await websocket.send(serialize_message(hello_msg))
        print(f"[{username}] Sent signed USER_HELLO with public key")

        # Wait for ACK or ERROR
        while True:
            data = deserialize_message(await websocket.recv())
            if data.get("type") == "ERROR" and data["payload"].get("code") == "NAME_IN_USE":
                print(f"[System] Username '{username}' already taken. Please try another.")
                return False
            elif data.get("type") == "ACK":
                print(f"[{username}] Connected successfully!")
                known_pubkeys[username] = public_key
                break

        await asyncio.gather(
            send_messages(username, websocket),
            receive_messages(username, websocket)
        )
        return True

# ------------------ Send ------------------

async def send_messages(user_id, websocket):
    while True:
        user_input = await asyncio.get_event_loop().run_in_executor(None, input, "")
        if not user_input:
            continue

        ts = int(time.time() * 1000)

        if user_input.lower() == "/quit":
            await websocket.close()
            print(f"[{user_id}] Disconnected")
            break

        elif user_input.lower() == "/help":
            print("[System] Available commands:")
            print("  /list               List online users")
            print("  /tell <user> <msg>  Send private message")
            print("  /all <msg>          Send message to all users")
            print("  /file <user> <path> Send file to a user")
            print("  /quit               Disconnect")
            continue

        elif user_input.lower() == "/list":
            msg = {"type": "USER_LIST", "from": user_id, "to": "server_1", "ts": ts, "payload": {}, "sig": ""}
            await websocket.send(serialize_message(msg))

        elif user_input.lower().startswith("/tell "):
            parts = user_input.split(" ", 2)
            if len(parts) < 3:
                print("[System] Usage: /tell <recipient> <message>")
                continue
            recipient, text = parts[1], parts[2]
            recipient_pub = known_pubkeys.get(recipient)
            if not recipient_pub:
                print(f"[System] No public key for {recipient}. Wait until they connect.")
                continue

            ciphertext = rsa_crpt.encrypt_message(recipient_pub, text)
            ciphertext_b64 = b64url_encode(ciphertext)
            content_bytes = (ciphertext_b64 + user_id + recipient + str(ts)).encode('utf-8')
            sig_b64 = b64url_encode(rsa_crpt.sign_message(content_bytes, private_key))

            msg = {
                "type": "MSG_PRIVATE",
                "from": user_id,
                "to": recipient,
                "ts": ts,
                "payload": {"ciphertext": ciphertext_b64, "content_sig": sig_b64},
                "sig": "",
            }
            await websocket.send(serialize_message(msg))
            print(f"[{format_timestamp(ts)}] [you → {recipient}]: {text}")

        elif user_input.lower().startswith("/all "):
            text = user_input[len("/all "):].strip()
            if not text:
                print("[System] Usage: /all <message>")
                continue

            shares = []
            for member, member_pub in known_pubkeys.items():
                if member == user_id:
                    continue
                ciphertext = rsa_crpt.encrypt_message(member_pub, text)
                ciphertext_b64 = b64url_encode(ciphertext)
                content_bytes = (ciphertext_b64 + user_id + member + str(ts)).encode('utf-8')
                sig_b64 = b64url_encode(rsa_crpt.sign_message(content_bytes, private_key))
                shares.append({"member": member, "ciphertext": ciphertext_b64, "content_sig": sig_b64})

            msg = {
                "type": "MSG_PUBLIC_CHANNEL",
                "from": user_id,
                "to": "all",
                "ts": ts,
                "payload": {"shares": shares},
                "sig": ""
            }
            await websocket.send(serialize_message(msg))
            print(f"[{format_timestamp(ts)}] #all [you → all]: {text}")

        elif user_input.lower().startswith("/file "):
            parts = user_input.split(" ", 2)
            if len(parts) < 3:
                print("[System] Usage: /file <recipient> <path>")
                continue
            recipient, path = parts[1], parts[2]
            try:
                with open(path, "rb") as f:
                    data = f.read()
                b64_data = b64url_encode(data)
                msg = {
                    "type": "FILE_TRANSFER",
                    "from": user_id,
                    "to": recipient,
                    "ts": ts,
                    "payload": {"filename": path.split("/")[-1], "data": b64_data},
                    "sig": ""
                }
                await websocket.send(serialize_message(msg))
                print(f"[{format_timestamp(ts)}] [you → {recipient}] Sent file: {path}")
            except Exception as e:
                print(f"[System] File error: {e}")

# ------------------ Receive ------------------

async def receive_messages(user_id, websocket):
    try:
        async for reply in websocket:
            data = deserialize_message(reply)
            msg_type = data.get("type")
            sender = data.get("from")
            ts = data.get("ts", int(time.time() * 1000))

            if msg_type == "USER_HELLO":
                pubkey_b64 = data["payload"].get("pubkey")
                if pubkey_b64 and sender != user_id:
                    known_pubkeys[sender] = rsa_crpt.load_public_key(b64url_decode(pubkey_b64))
                    print(f"[System] {sender} joined! (stored public key)")

            elif msg_type == "MSG_PRIVATE":
                ciphertext_b64 = data["payload"].get("ciphertext")
                sig_b64 = data["payload"].get("content_sig")
                sender_pub = known_pubkeys.get(sender)
                if ciphertext_b64 and sig_b64 and sender_pub:
                    try:
                        content_bytes = (ciphertext_b64 + sender + user_id + str(ts)).encode('utf-8')
                        rsa_crpt.verify_signature(sender_pub, content_bytes, b64url_decode(sig_b64))
                        plaintext = rsa_crpt.decrypt_message(private_key, b64url_decode(ciphertext_b64))
                        print(f"[{format_timestamp(ts)}] [{sender} → you]: {plaintext}")
                    except Exception:
                        print(f"[System] Failed to verify/decrypt private msg from {sender}")

            elif msg_type == "MSG_PUBLIC_CHANNEL":
                payload = data.get("payload", {})
                sender_pub_pem = payload.get("sender_pub")
                sender_pub = rsa_crpt.load_public_key(b64url_decode(sender_pub_pem)) if sender_pub_pem else None
                ciphertext_b64 = payload.get("ciphertext")
                sig_b64 = payload.get("content_sig")
                if sender_pub and ciphertext_b64 and sig_b64:
                    try:
                        content_bytes = (ciphertext_b64 + sender + user_id + str(ts)).encode('utf-8')
                        rsa_crpt.verify_signature(sender_pub, content_bytes, b64url_decode(sig_b64))
                        plaintext = rsa_crpt.decrypt_message(private_key, b64url_decode(ciphertext_b64))
                        print(f"[{format_timestamp(ts)}] #all [{sender} → all]: {plaintext}")
                    except Exception:
                        print(f"[System] Failed to verify/decrypt broadcast msg from {sender}")

            elif msg_type == "FILE_TRANSFER":
                payload = data.get("payload", {})
                filename = payload.get("filename", "file.bin")
                data_b64 = payload.get("data", "")
                try:
                    with open(f"recv_{filename}", "wb") as f:
                        f.write(b64url_decode(data_b64))
                    print(f"[{format_timestamp(ts)}] [{sender} → you] Received file: recv_{filename}")
                except Exception as e:
                    print(f"[System] Failed to save file: {e}")

            else:
                formatted = format_message(data, user_id)
                if formatted:
                    print(formatted)

    except websockets.ConnectionClosed:
        print(f"[{user_id}] Connection closed")

# ------------------ Run ------------------

async def main():
    while True:
        username = input("Enter your username: ")
        success = await client(username)
        if success:
            break

if __name__ == "__main__":
    asyncio.run(main())



#Client built a USER_HELLO message (Alice introducing herself).
#Client serialized it into JSON → sent to server over WebSocket.
#Server deserialized the JSON → printed it → re-serialized → sent it back.


