import asyncio
import websockets
import time
import base64
import json
from datetime import datetime
from src.crypto import rsa_crpt
from src.utils.json_utils import deserialize_message, serialize_message

def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')

def b64url_decode(data: str) -> bytes:
    rem = len(data) % 4
    if rem: data += "="*(4-rem)
    return base64.urlsafe_b64decode(data)

def canonical_payload_bytes(payload: dict) -> bytes:
    return json.dumps(payload, separators=(',', ':'), sort_keys=True).encode('utf-8')

def format_timestamp(ts:int) -> str:
    return datetime.fromtimestamp(ts/1000).strftime("%H:%M:%S")

private_key, public_key = rsa_crpt.generate_rsa_keypair()
known_pubkeys = {}  # username -> RSA public key

async def client(user_id):
    uri = "ws://localhost:8765"
    async with websockets.connect(uri) as ws:
        known_pubkeys[user_id] = public_key

        # Send USER_HELLO
        payload = {"client":"cli-v1","pubkey":b64url_encode(rsa_crpt.export_public_key(public_key))}
        ts = int(time.time()*1000)
        hello_msg = {
            "type":"USER_HELLO",
            "from":user_id,
            "to":"server_1",
            "ts":ts,
            "payload":payload,
            "sig": b64url_encode(rsa_crpt.sign_message(canonical_payload_bytes(payload), private_key))
        }
        await ws.send(serialize_message(hello_msg))
        print(f"[{user_id}] Sent signed USER_HELLO with public key")

        await asyncio.gather(send_loop(user_id, ws), recv_loop(user_id, ws))


async def send_loop(user_id, ws):
    help_text = "[System] Commands:\n/help\n/who\n/dm <user> <msg>\n/group <msg>\n/quit"
    while True:
        inp = await asyncio.get_event_loop().run_in_executor(None, input, "")
        ts = int(time.time()*1000)
        if not inp: continue

        if inp.lower()=="/quit":
            print(f"[{user_id}] Disconnecting...")
            await ws.close()
            break
        elif inp.lower()=="/help":
            print(help_text)
            continue
        elif inp.lower()=="/who":
            msg = {"type":"USER_LIST","from":user_id,"to":"server_1","ts":ts,"payload":{},"sig":""}
            await ws.send(serialize_message(msg))
            continue
        elif inp.lower().startswith("/dm "):
            parts = inp.split(" ",2)
            if len(parts)<3:
                print("[System] Usage: /dm <user> <message>")
                continue
            recipient, text = parts[1], parts[2]
            if recipient not in known_pubkeys:
                print(f"[System] No public key for {recipient}. Wait for them to join.")
                continue
            pub = known_pubkeys[recipient]
            cipher = rsa_crpt.encrypt_message(pub, text)
            cipher_b64 = b64url_encode(cipher)
            sig = b64url_encode(rsa_crpt.sign_message((cipher_b64+user_id+recipient+str(ts)).encode('utf-8'), private_key))
            msg = {"type":"MSG_PRIVATE","from":user_id,"to":recipient,"ts":ts,"payload":{"ciphertext":cipher_b64,"content_sig":sig},"sig":""}
            await ws.send(serialize_message(msg))
            print(f"[{format_timestamp(ts)}] [you → {recipient}]: {text}")
            continue
        elif inp.lower().startswith("/group "):
            text = inp[len("/group "):].strip()
            if not text: continue
            shares=[]
            for member, pub in known_pubkeys.items():
                if member==user_id: continue
                cipher = rsa_crpt.encrypt_message(pub, text)
                cipher_b64 = b64url_encode(cipher)
                sig = b64url_encode(rsa_crpt.sign_message((cipher_b64+user_id+member+str(ts)).encode('utf-8'), private_key))
                shares.append({"member":member,"ciphertext":cipher_b64,"content_sig":sig})
            msg = {"type":"MSG_PUBLIC_CHANNEL","from":user_id,"to":"g123","ts":ts,"payload":{"shares":shares},"sig":""}
            await ws.send(serialize_message(msg))
            print(f"[{format_timestamp(ts)}] #general [you → all]: {text}")
            continue
        else:
            print("[System] Invalid command. Use /help, /who, /dm, /group, /quit.")


async def recv_loop(user_id, ws):
    try:
        async for reply in ws:
            data = deserialize_message(reply)
            mtype = data.get("type")
            ts = data.get("ts", int(time.time()*1000))
            sender = data.get("from")

            # New user joined
            if mtype=="USER_HELLO":
                pubkey_b64 = data.get("payload",{}).get("pubkey")
                if pubkey_b64 and sender != user_id:
                    new_user = sender not in known_pubkeys
                    known_pubkeys[sender] = rsa_crpt.load_public_key(b64url_decode(pubkey_b64))
                    if new_user:
                        print(f"[System] {sender} joined! (stored public key)")
                continue

            # Private message
            if mtype=="MSG_PRIVATE":
                payload = data.get("payload",{})
                ciphertext_b64 = payload.get("ciphertext")
                sig_b64 = payload.get("content_sig")
                recipient = data.get("to")
                if sender==user_id:
                    continue  # own message already shown
                if sender in known_pubkeys:
                    try:
                        content_bytes = (ciphertext_b64+sender+user_id+str(ts)).encode('utf-8')
                        rsa_crpt.verify_signature(known_pubkeys[sender], content_bytes, b64url_decode(sig_b64))
                        plaintext = rsa_crpt.decrypt_message(private_key, b64url_decode(ciphertext_b64))
                        print(f"[{format_timestamp(ts)}] [{sender} → you]: {plaintext}")
                    except:
                        print(f"[System] Failed to verify/decrypt private msg from {sender}")
                continue

            # Group message
            if mtype=="MSG_PUBLIC_CHANNEL":
                payload = data.get("payload",{})
                shares = [s for s in payload.get("shares",[]) if s["member"]==user_id]
                for share in shares:
                    try:
                        content_bytes = (share["ciphertext"]+sender+user_id+str(ts)).encode('utf-8')
                        rsa_crpt.verify_signature(known_pubkeys[sender], content_bytes, b64url_decode(share["content_sig"]))
                        plaintext = rsa_crpt.decrypt_message(private_key, b64url_decode(share["ciphertext"]))
                        print(f"[{format_timestamp(ts)}] #general [{sender} → all]: {plaintext}")
                    except:
                        print(f"[System] Failed to verify/decrypt group msg from {sender}")
                continue

            # USER_LIST_REPLY
            if mtype=="USER_LIST_REPLY":
                users = data.get("payload",{}).get("users",[])
                print(f"[{format_timestamp(ts)}] [server_1 → {user_id}]: Online users: {', '.join(users)}")
                continue

            # ACK
            if mtype=="ACK":
                ref = data.get("payload",{}).get("msg_ref","")
                print(f"[{format_timestamp(ts)}] [server_1 → {user_id}]: ACK for {ref}")
                continue

            # fallback
            print(f"[{format_timestamp(ts)}] [{sender} → {data.get('to')}]: {data.get('payload')}")

    except websockets.ConnectionClosed:
        print(f"[{user_id}] Connection closed")


if __name__=="__main__":
    username = input("Enter your username: ")
    asyncio.run(client(username))
