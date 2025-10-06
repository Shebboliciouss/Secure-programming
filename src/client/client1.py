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
                id_to_username[user_id] = username
                username_to_id[username] = user_id
                known_pubkeys[user_id] = public_key
                break

        await asyncio.gather(send_loop(user_id, ws), recv_loop(user_id, ws))
        return True

# ---------------- send loop ----------------
async def send_loop(user_id, ws):
    while True:
        inp = await asyncio.get_event_loop().run_in_executor(None, input, "")
        if not inp: continue
        ts = int(time.time()*1000)
        cmd = inp.split()[0].lower()

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
 /help""")
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
            recipient_id = username_to_id.get(recipient_input, recipient_input)
            pub = known_pubkeys.get(recipient_id)
            if not pub:
                print(f"[System] No pubkey for {recipient_input}")
                continue
            cipher = rsa_crpt.encrypt_message(pub,text)
            c_b64 = b64url_encode(cipher)
            sig_b64 = b64url_encode(rsa_crpt.sign_message((c_b64+user_id+recipient_id+str(ts)).encode(), private_key))
            msg = {"type":"MSG_PRIVATE","from":user_id,"to":recipient_id,"ts":ts,"payload":{"ciphertext":c_b64,"content_sig":sig_b64},"sig":""}
            await ws.send(serialize_message(msg))
            print(f"[{format_timestamp(ts)}] [you → {id_to_username.get(recipient_id,recipient_id)}]: {text}")
            continue

        if cmd=="/all":
            text = inp[len("/all "):].strip()
            if not text: continue
            shares=[]
            for member_id,pub in known_pubkeys.items():
                if member_id==user_id: continue
                cipher = rsa_crpt.encrypt_message(pub,text)
                c_b64 = b64url_encode(cipher)
                sig_b64 = b64url_encode(rsa_crpt.sign_message((c_b64+user_id+member_id+str(ts)).encode(), private_key))
                shares.append({"member":member_id,"ciphertext":c_b64,"content_sig":sig_b64})
            msg={"type":"MSG_PUBLIC_CHANNEL","from":user_id,"to":"all","ts":ts,"payload":{"shares":shares},"sig":""}
            await ws.send(serialize_message(msg))
            print(f"[{format_timestamp(ts)}] #all [you → all]: {text}")
            continue

        if cmd=="/file":
            parts=inp.split(" ",2)
            if len(parts)<3: continue
            recipient_input, path = parts[1], parts[2]
            recipient_id = username_to_id.get(recipient_input,recipient_input)
            pub = known_pubkeys.get(recipient_id)
            if not pub:
                print(f"[System] No pubkey for {recipient_input}")
                continue
            await send_file(ws,user_id,path,recipient_id,pub,lambda b: rsa_crpt.encrypt_bytes(pub,b))
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
                if pub_b64: known_pubkeys[sender] = rsa_crpt.load_public_key(b64url_decode(pub_b64))
                id_to_username[sender] = uname
                username_to_id[uname] = sender
                print(f"[System] {uname} joined!")

            elif t=="USER_LIST_REPLY":
                users=data.get("payload",{}).get("users",[])
                print("[System] Online users:")
                for u in users:
                    uid = u.get("uuid")
                    uname = u.get("username")
                    print(f"  - {uname} ({uid})")

            elif t=="MSG_PRIVATE":
                c_b64=data["payload"].get("ciphertext")
                sig_b64=data["payload"].get("content_sig")
                pub=known_pubkeys.get(sender)
                if not pub: continue
                try:
                    rsa_crpt.verify_signature(pub,(c_b64+sender+user_id+str(ts)).encode(),b64url_decode(sig_b64))
                    pt=rsa_crpt.decrypt_message(private_key,b64url_decode(c_b64))
                    print(f"[{format_timestamp(ts)}] [{id_to_username.get(sender,sender)} → you]: {pt}")
                except:
                    print(f"[System] Failed to verify/decrypt private msg from {sender}")

            elif t=="MSG_PUBLIC_CHANNEL":
                for share in data.get("payload",{}).get("shares",[]):
                    member = share.get("member")
                    if member != user_id: continue
                    c_b64 = share.get("ciphertext")
                    sig_b64 = share.get("content_sig")
                    pub = known_pubkeys.get(sender)
                    if not pub: continue
                    try:
                        rsa_crpt.verify_signature(pub,(c_b64+sender+user_id+str(ts)).encode(),b64url_decode(sig_b64))
                        pt = rsa_crpt.decrypt_message(private_key,b64url_decode(c_b64))
                        print(f"[{format_timestamp(ts)}] #all [{id_to_username.get(sender,sender)} → all]: {pt}")
                    except:
                        print(f"[System] Failed to verify/decrypt group msg from {sender}")

            elif t in ["FILE_START","FILE_CHUNK","FILE_END"]:
                handle_file_message(data,file_buffers,lambda c: rsa_crpt.decrypt_bytes(private_key,c), id_to_username)

            elif t == "ERROR":
                error_code = data.get("payload", {}).get("code")
                error_detail = data.get("payload", {}).get("detail")
                print(f"[System] Error: {error_code} - {error_detail}")

            else:
                print("[System] Unknown message type:", t)

    except websockets.ConnectionClosed:
        print("[System] Connection closed")

# ---------------- run ----------------
async def main():
    # Parse command line arguments
    server_uri = "ws://localhost:8765"  # default
    
    if len(sys.argv) > 1:
        # Allow: python client.py ws://localhost:8766
        # Or: python client.py 8766 (shorthand)
        arg = sys.argv[1]
        if arg.startswith("ws://"):
            server_uri = arg
        else:
            # Assume it's just a port number
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


