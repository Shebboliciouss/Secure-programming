# src/server/file_transfer.py
from src.utils.json_utils import serialize_message

async def handle_file_message(msg, local_users, id_to_username):
    """
    Relay FILE_START / FILE_CHUNK / FILE_END frames to recipient if local.
    Logs usernames instead of UUIDs.
    """
    msg_type = msg.get("type")
    sender_id = msg.get("from")
    recipient_id = msg.get("to")

    sender_name = id_to_username.get(sender_id, sender_id)
    recipient_name = id_to_username.get(recipient_id, recipient_id)

    if msg_type in ["FILE_START", "FILE_CHUNK", "FILE_END"]:
        if recipient_id in local_users:
            try:
                await local_users[recipient_id].send(serialize_message(msg))
                print(f"[Server] Relayed {msg_type} from {sender_name} to {recipient_name}")
            except Exception as e:
                print(f"[Server] Failed to relay {msg_type} from {sender_name} to {recipient_name}: {e}")
        else:
            print(f"[Server] Recipient {recipient_name} not found for {msg_type} from {sender_name}")
