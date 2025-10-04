# server/file_transfer.py
from src.utils.json_utils import serialize_message

async def handle_file_message(msg, local_users, user_keys):
    msg_type = msg.get("type")
    sender = msg.get("from")
    recipient = msg.get("to")

    # Relay FILE_START / FILE_CHUNK / FILE_END
    if msg_type in ["FILE_START", "FILE_CHUNK", "FILE_END"]:
        if recipient in local_users:
            try:
                await local_users[recipient].send(serialize_message(msg))
                print(f"[Server] Relayed {msg_type} from {sender} to {recipient}")
            except Exception as e:
                print(f"[Server] Failed to relay {msg_type}: {e}")
