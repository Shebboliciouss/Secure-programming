import uuid, hashlib, base64, time, os
from src.utils.json_utils import serialize_message

RSA_CHUNK_SIZE = 190

def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')

def b64url_decode(s: str) -> bytes:
    rem = len(s) % 4
    if rem: s += '='*(4-rem)
    return base64.urlsafe_b64decode(s)

async def send_file(ws, user_id: str, filepath: str, recipient_id: str, recipient_pub, rsa_encrypt_func, mode="dm"):
    if not os.path.exists(filepath):
        print(f"[System] File not found: {filepath}")
        return

    file_id = str(uuid.uuid4())
    with open(filepath,"rb") as f: data=f.read()

    sha256sum = hashlib.sha256(data).hexdigest()
    size = len(data)
    filename = os.path.basename(filepath)

    start_msg = {
        "type":"FILE_START",
        "from":user_id,
        "to":recipient_id,
        "ts":int(time.time()*1000),
        "payload":{"file_id":file_id,"name":filename,"size":size,"sha256":sha256sum,"mode":mode},
        "sig":""
    }
    await ws.send(serialize_message(start_msg))
    print(f"[System] FILE_START sent for {filename} ({size} bytes)")

    for idx in range(0,size,RSA_CHUNK_SIZE):
        chunk = data[idx:idx+RSA_CHUNK_SIZE]
        ciphertext = rsa_encrypt_func(chunk)
        c_b64 = b64url_encode(ciphertext)
        chunk_msg = {"type":"FILE_CHUNK","from":user_id,"to":recipient_id,"ts":int(time.time()*1000),
                     "payload":{"file_id":file_id,"index":idx//RSA_CHUNK_SIZE,"ciphertext":c_b64},"sig":""}
        await ws.send(serialize_message(chunk_msg))

    end_msg={"type":"FILE_END","from":user_id,"to":recipient_id,"ts":int(time.time()*1000),"payload":{"file_id":file_id},"sig":""}
    await ws.send(serialize_message(end_msg))
    print(f"[System] FILE_END sent for {filename}")

def handle_file_message(msg, buffer_store, rsa_decrypt_func, id_to_username):
    msg_type = msg.get("type")
    payload = msg.get("payload",{})
    sender_id = msg.get("from")
    sender_name = id_to_username.get(sender_id, sender_id)

    if msg_type=="FILE_START":
        file_id = payload["file_id"]
        buffer_store[file_id] = {"name":payload["name"],"size":payload["size"],"sha256":payload["sha256"],"chunks":{}}
        print(f"[System] Incoming file from {sender_name}: {payload['name']} ({payload['size']} bytes)")

    elif msg_type=="FILE_CHUNK":
        file_id = payload["file_id"]
        idx = payload["index"]
        ciphertext = b64url_decode(payload["ciphertext"])
        try:
            chunk = rsa_decrypt_func(ciphertext)
        except Exception as e:
            print(f"[System] Failed to decrypt chunk idx={idx} from {sender_name}: {e}")
            return
        buffer_store[file_id]["chunks"][idx] = chunk

    elif msg_type=="FILE_END":
        file_id = payload["file_id"]
        info = buffer_store.get(file_id)
        if not info: 
            print("[System] FILE_END for unknown file_id")
            return
        ordered = b''.join(info["chunks"][i] for i in sorted(info["chunks"].keys()))
        if hashlib.sha256(ordered).hexdigest()==info["sha256"]:
            outname=f"recv_{info['name']}"
            with open(outname,"wb") as f: f.write(ordered)
            print(f"[System] File saved: {outname}")
            del buffer_store[file_id]
        else:
            print("[System] hash mismatch.")

