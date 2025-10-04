# client/file_transfer.py
import uuid, hashlib, base64, time
from src.utils.json_utils import serialize_message, deserialize_message

async def send_file(ws, username, filepath, recipient, encrypt_func, mode="dm"):
    file_id = str(uuid.uuid4())
    with open(filepath, "rb") as f:
        data = f.read()

    sha256 = hashlib.sha256(data).hexdigest()
    size = len(data)
    filename = filepath.split("/")[-1]

    # Send FILE_START
    start_msg = {
        "type": "FILE_START",
        "from": username,
        "to": recipient,
        "ts": int(time.time()*1000),
        "payload": {
            "file_id": file_id,
            "name": filename,
            "size": size,
            "sha256": sha256,
            "mode": mode
        },
        "sig": ""
    }
    await ws.send(serialize_message(start_msg))

    # Send FILE_CHUNK
    chunk_size = 16 * 1024
    for idx in range(0, size, chunk_size):
        chunk = data[idx:idx+chunk_size]
        ciphertext = encrypt_func(chunk)  # 🔐 reuse your RSA/AES wrapper
        ciphertext_b64 = base64.urlsafe_b64encode(ciphertext).decode()

        chunk_msg = {
            "type": "FILE_CHUNK",
            "from": username,
            "to": recipient,
            "ts": int(time.time()*1000),
            "payload": {"file_id": file_id, "index": idx//chunk_size, "ciphertext": ciphertext_b64},
            "sig": ""
        }
        await ws.send(serialize_message(chunk_msg))

    # Send FILE_END
    end_msg = {
        "type": "FILE_END",
        "from": username,
        "to": recipient,
        "ts": int(time.time()*1000),
        "payload": {"file_id": file_id},
        "sig": ""
    }
    await ws.send(serialize_message(end_msg))
    print(f"[System] Finished sending {filename} ({size} bytes)")


# Receiver
def handle_file_message(msg, buffer_store, decrypt_func):
    msg_type = msg.get("type")
    payload = msg.get("payload", {})
    sender = msg.get("from")

    if msg_type == "FILE_START":
        file_id = payload["file_id"]
        buffer_store[file_id] = {
            "name": payload["name"],
            "size": payload["size"],
            "sha256": payload["sha256"],
            "chunks": {}
        }
        print(f"[System] Incoming file from {sender}: {payload['name']} ({payload['size']} bytes)")

    elif msg_type == "FILE_CHUNK":
        file_id = payload["file_id"]
        idx = payload["index"]
        ciphertext = base64.urlsafe_b64decode(payload["ciphertext"])
        chunk = decrypt_func(ciphertext)
        buffer_store[file_id]["chunks"][idx] = chunk

    elif msg_type == "FILE_END":
        file_id = payload["file_id"]
        info = buffer_store[file_id]
        ordered = b''.join(info["chunks"][i] for i in sorted(info["chunks"].keys()))
        import hashlib
        if hashlib.sha256(ordered).hexdigest() == info["sha256"]:
            with open(info["name"], "wb") as f:
                f.write(ordered)
            print(f"[System] File saved: {info['name']}")
        else:
            print("[System] File hash mismatch.")
