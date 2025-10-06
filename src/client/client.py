import asyncio, websockets, time, uuid, os, base64, sys
from datetime import datetime
from src.crypto import rsa_crpt
from src.utils.json_utils import serialize_message, deserialize_message
from .file_transfer_client import send_file, handle_file_message

# ---------------- helpers ----------------
def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')

def b64url_decode(s: str) -> bytes:
    rem = len(s) % 4
    if rem: s += '='*(4-rem)
    return base64.urlsafe_b64decode(s)

def format_timestamp(ts: int) -> str:
    return datetime.fromtimestamp(ts/1000).strftime("%H:%M:%S")

# ---------------- global keys and mapping ----------------
private_key, public_key = rsa_crpt.generate_rsa_keypair()
known_pubkeys = {}    # user_id -> public key
id_to_username = {}   # user_id -> username
username_to_id = {}   # username -> user_id
file_buffers = {}     # for incoming file chunks

# ---------------- client ----------------
async def client(username, server_uri="ws://localhost:8765"):
    uri = server_uri
    user_id = str(uuid.uuid4())  # always generate a fresh UUID

    print(f"[{username}] Connecting to {uri}...")
    
    async with websockets.connect(uri) as ws:
        payload = {
            "client":"cli-v1",
            "pubkey": b64url_encode(rsa_crpt.export_public_key(public_key)),
            "username": username
        }
        ts = int(time.time()*1000)
        hello_msg = {
            "type":"USER_HELLO",
            "from":user_id,
            "to":"server_1",
            "ts":ts,
            "payload":payload,
            "sig": b64url_encode(rsa_crpt.sign_message(rsa_crpt.canonical_payload_bytes(payload), private_key))
        }
        await ws.send(serialize_message(hello_msg))
        print(f"[{username}] Sent USER_HELLO")

        # Wait for ACK
        while True:
            msg = deserialize_message(await ws.recv())
            if msg.get("type")=="ERROR" and msg.get("payload",{}).get("code")=="NAME_IN_USE":
                print(f"[System] Name in use")
                return False
            if msg.get("type")=="ACK":
                print(f"[{username}] Connected to {uri}")
                # Store own info by BOTH UUID and username
                id_to_username[user_id] = username
                username_to_id[username] = user_id
                known_pubkeys[user_id] = public_key
                known_pubkeys[username] = public_key
                break

        await asyncio.gather(send_loop(user_id, ws), recv_loop(user_id, ws))
        return True

# ---------------- send loop ----------------
async def send_loop(user_id, ws):
    while True:
        inp = await asyncio.get_event_loop().run_in_executor(None, input, "")
        if not inp: continue
        ts = int(time.time()*1000)
        cmd = inp.split()[0].lower() if inp.split() else ""

        if cmd=="/quit":
            await ws.close()
            print("Disconnecting...")
            break

        if cmd=="/help":
            print("""Commands:
 /quit
 /list
 /tell <user|username> <msg>
 /all <msg>
 /file <user|username> <path>
 /debug - show local user cache
 /help""")
            continue

        if cmd=="/debug":
            print(f"\n=== DEBUG INFO ===")
            print(f"Known public keys ({len(set(known_pubkeys.values()))} unique):")
            seen_keys = set()
            for identifier, key in known_pubkeys.items():
                if key not in seen_keys:
                    seen_keys.add(key)
                    # Find both UUID and username for this key
                    aliases = [k for k, v in known_pubkeys.items() if v == key]
                    print(f"  ✓ {', '.join(aliases)}")
            print(f"Username mappings: {len(username_to_id)}")
            print(f"==================\n")
            continue

        if cmd=="/list":
            await ws.send(serialize_message({"type":"USER_LIST","from":user_id,"to":"server_1","ts":ts,"payload":{},"sig":""}))
            continue

        if cmd=="/tell":
            parts = inp.split(" ",2)
            if len(parts)<3:
                print("[System] Usage: /tell <user|username> <msg>")
                continue
            recipient_input, text = parts[1], parts[2]
            
            # Try to resolve username to ID first
            recipient_id = username_to_id.get(recipient_input, recipient_input)
            
            # Get public key
            pub = known_pubkeys.get(recipient_id)
            if not pub:
                print(f"[System] User '{recipient_input}' not found or no public key available")
                print(f"[System] Try /list to see available users")
                continue
            
            # Encrypt message
            cipher = rsa_crpt.encrypt_message(pub, text)
            c_b64 = b64url_encode(cipher)
            sig_b64 = b64url_encode(rsa_crpt.sign_message((c_b64+user_id+recipient_id+str(ts)).encode(), private_key))
            
            # Send username when available for federated routing
            recipient_to_send = id_to_username.get(recipient_id, recipient_input)
            
            msg = {
                "type":"MSG_PRIVATE",
                "from":user_id,
                "to":recipient_to_send,
                "ts":ts,
                "payload":{
                    "ciphertext":c_b64,
                    "content_sig":sig_b64
                },
                "sig":""
            }
            await ws.send(serialize_message(msg))
            print(f"[{format_timestamp(ts)}] [you → {id_to_username.get(recipient_id,recipient_input)}]: {text}")
            continue

        if cmd=="/all":
            text = inp[len("/all "):].strip()
            if not text: 
                print("[System] Usage: /all <message>")
                continue
            
            shares=[]
            seen_users = set()
            
            # Iterate over user IDs only to avoid duplicates
            for uid in id_to_username.keys():
                if uid == user_id or uid in seen_users:
                    continue
                
                seen_users.add(uid)
                pub = known_pubkeys.get(uid)
                if not pub:
                    continue
                
                # Encrypt for this member
                cipher = rsa_crpt.encrypt_message(pub, text)
                c_b64 = b64url_encode(cipher)
                sig_b64 = b64url_encode(rsa_crpt.sign_message((c_b64+user_id+uid+str(ts)).encode(), private_key))
                
                # Use username in shares when available
                member_to_send = id_to_username.get(uid, uid)
                shares.append({
                    "member": member_to_send,
                    "ciphertext": c_b64,
                    "content_sig": sig_b64
                })
            
            if not shares:
                print("[System] No other users online to broadcast to")
                continue
            
            msg = {
                "type":"MSG_PUBLIC_CHANNEL",
                "from":user_id,
                "to":"all",
                "ts":ts,
                "payload":{"shares":shares},
                "sig":""
            }
            await ws.send(serialize_message(msg))
            print(f"[{format_timestamp(ts)}] #all [you → all]: {text}")
            continue

        if cmd=="/file":
            parts=inp.split(" ",2)
            if len(parts)<3: 
                print("[System] Usage: /file <user|username> <path>")
                continue
            recipient_input, path = parts[1], parts[2]
            recipient_id = username_to_id.get(recipient_input, recipient_input)
            
            # Get username for sending (consistent with /tell)
            recipient_to_send = id_to_username.get(recipient_id, recipient_input)
            
            pub = known_pubkeys.get(recipient_id)
            if not pub:
                print(f"[System] No pubkey for {recipient_input}")
                continue
            
            # Pass recipient_to_send (username) to send_file
            await send_file(ws, user_id, path, recipient_to_send, pub, lambda b: rsa_crpt.encrypt_bytes(pub, b))
            continue

# ---------------- receive loop ----------------
async def recv_loop(user_id, ws):
    try:
        async for raw in ws:
            data = deserialize_message(raw)
            t = data.get("type")
            sender = data.get("from")
            ts = data.get("ts", int(time.time()*1000))

            if t=="USER_HELLO":
                payload = data.get("payload",{})
                pub_b64 = payload.get("pubkey")
                uname = payload.get("username", sender)
                
                if pub_b64:
                    try:
                        pub_bytes = b64url_decode(pub_b64)
                        pubkey_obj = rsa_crpt.load_public_key(pub_bytes)
                        
                        # Store by BOTH UUID and username for federated messages
                        known_pubkeys[sender] = pubkey_obj
                        known_pubkeys[uname] = pubkey_obj
                        
                        id_to_username[sender] = uname
                        username_to_id[uname] = sender
                        print(f"[System] {uname} joined!")
                    except Exception as e:
                        print(f"[System] Error loading pubkey for {uname}: {e}")
                else:
                    print(f"[System] {uname} joined (no pubkey)")

            elif t=="USER_LIST_REPLY":
                users=data.get("payload",{}).get("users",[])
                print("[System] Online users:")
                for u in users:
                    uid = u.get("uuid")
                    uname = u.get("username")
                    status = "✓" if uid in known_pubkeys else "?"
                    print(f"  - {uname} ({uid}) {status}")

            elif t=="MSG_PRIVATE":
                c_b64=data["payload"].get("ciphertext")
                sig_b64=data["payload"].get("content_sig")
                
                # Try to get pubkey by sender (could be UUID or username for federated messages)
                pub=known_pubkeys.get(sender)
                
                if not pub:
                    sender_name = id_to_username.get(sender, sender[:8] + "..." if len(sender) > 8 else sender)
                    print(f"[System] Cannot decrypt message from {sender_name} - no public key")
                    continue
                try:
                    rsa_crpt.verify_signature(pub,(c_b64+sender+user_id+str(ts)).encode(),b64url_decode(sig_b64))
                    pt=rsa_crpt.decrypt_message(private_key,b64url_decode(c_b64))
                    sender_display = id_to_username.get(sender, sender)
                    print(f"[{format_timestamp(ts)}] [{sender_display} → you]: {pt}")
                except Exception as e:
                    print(f"[System] Failed to verify/decrypt private msg from {sender}: {e}")

            elif t=="MSG_PUBLIC_CHANNEL":
                for share in data.get("payload",{}).get("shares",[]):
                    member = share.get("member")
                    my_username = id_to_username.get(user_id, "")
                    if member != user_id and member != my_username:
                        continue
                    c_b64 = share.get("ciphertext")
                    sig_b64 = share.get("content_sig")
                    pub = known_pubkeys.get(sender)
                    if not pub:
                        print(f"[System] Cannot decrypt group message from {sender} - no public key")
                        continue
                    try:
                        rsa_crpt.verify_signature(pub,(c_b64+sender+user_id+str(ts)).encode(),b64url_decode(sig_b64))
                        pt = rsa_crpt.decrypt_message(private_key,b64url_decode(c_b64))
                        sender_display = id_to_username.get(sender, sender)
                        print(f"[{format_timestamp(ts)}] #all [{sender_display} → all]: {pt}")
                    except Exception as e:
                        print(f"[System] Failed to verify/decrypt group msg from {sender}: {e}")

            elif t in ["FILE_START","FILE_CHUNK","FILE_END"]:
                handle_file_message(data,file_buffers,lambda c: rsa_crpt.decrypt_bytes(private_key,c), id_to_username)

            elif t == "ERROR":
                error_code = data.get("payload", {}).get("code")
                error_detail = data.get("payload", {}).get("detail")
                print(f"[System] Error: {error_code} - {error_detail}")

            else:
                print(f"[System] Unknown message type: {t}")

    except websockets.ConnectionClosed:
        print("[System] Connection closed")
    except Exception as e:
        print(f"[System] Receive loop error: {e}")

# ---------------- run ----------------
async def main():
    # Parse command line arguments
    server_uri = "ws://localhost:8765"  # default
    
    if len(sys.argv) > 1:
        arg = sys.argv[1]
        if arg.startswith("ws://"):
            server_uri = arg
        else:
            server_uri = f"ws://localhost:{arg}"
    
    print(f"Server: {server_uri}")
    
    while True:
        username = input("Enter your username: ")
        if await client(username, server_uri):
            break

if __name__=="__main__":
    asyncio.run(main())
#Client built a USER_HELLO message (Alice introducing herself).
#Client serialized it into JSON → sent to server over WebSocket.
#Server deserialized the JSON → printed it → re-serialized → sent it back.

