# src/utils/protocol.py

import time
import json

# ==========================
# Client message types
# ==========================
HELLO_MSG = "USER_HELLO"           # User joins
MSG_PRIVATE = "MSG_PRIVATE"        # Direct/private message
MSG_USER_DELIVER = "USER_DELIVER"  # Server delivers message to client

# ==========================
# Peer server-to-server messages
# ==========================
PEER_HELLO_JOIN  = "PEER_HELLO_JOIN"  # Initial join request
PEER_WELCOME     = "PEER_WELCOME"     # Peer acknowledges join
PEER_HELLO_LINK  = "PEER_HELLO_LINK"  # Confirmation link

# ==========================
# Presence information
# ==========================
USER_ADVERTISE   = "USER_ADVERTISE"   # User connected to a server
USER_REMOVE      = "USER_REMOVE"      # User disconnected

# ==========================
# Cross-server message delivery
# ==========================
PEER_DELIVER     = "PEER_DELIVER"     # Deliver message across servers

# ==========================
# Heartbeat
# ==========================
HEARTBEAT        = "HEARTBEAT"

# ==========================
# Serialization / Deserialization
# ==========================
def serialize_message(msg):
    """
    Convert a Python dictionary into a JSON string (newline-terminated for websocket).
    """
    try:
        string_json = json.dumps(msg, separators=(',', ':'), sort_keys=True)
        return string_json + '\n'
    except (TypeError, ValueError) as e:
        raise ValueError(f"Message serialization failed: {e}")

def deserialize_message(string_json):
    """
    Convert a JSON string back into a Python dictionary and validate required keys.
    """
    try:
        string_json = string_json.strip()
        msg = json.loads(string_json)
        required = {"type", "from", "to", "ts", "payload", "sig"}
        missing_flag = required - msg.keys()
        if missing_flag:
            raise ValueError(f"Missing required keys in message: {missing_flag}")
        return msg
    except (json.JSONDecodeError, ValueError) as e:
        raise ValueError(f"Failed to deserialize message: {e}")

def create_message(msg_type, sender, recipient, payload, sig=""):
    """
    Create a structured message dictionary with timestamp.
    """
    return {
        "type": msg_type,
        "from": sender,
        "to": recipient,
        "ts": int(time.time() * 1000),
        "payload": payload,
        "sig": sig
    }
