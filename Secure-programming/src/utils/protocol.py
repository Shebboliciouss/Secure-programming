import json
import time


# User hello when connecting to the server
HELLO_MSG = "USER_HELLO"

# Private message between users
MSG_PRIVATE = "MSG_PRIVATE"

# Server delivers message to a user
MSG_USER_DELIVER = "USER_DELIVER"




# Peer bootstrap messages
PEER_HELLO_JOIN = "PEER_HELLO_JOIN" 
PEER_WELCOME    = "PEER_WELCOME"      
PEER_HELLO_LINK = "PEER_HELLO_LINK"   

# Gossip: user presence
USER_ADVERTISE  = "USER_ADVERTISE"    # Broadcast user online / location
USER_REMOVE     = "USER_REMOVE"       # Broadcast user offline

# Message forwarding between servers
PEER_DELIVER    = "PEER_DELIVER"

# Optional heartbeat
HEARTBEAT       = "HEARTBEAT"


def serialize_message(msg: dict) -> str:
    """
    Serialize a Python dictionary into JSON string.
    Ends with newline for WebSocket text framing.
    """
    try:
        string_json = json.dumps(msg, separators=(',', ':'), sort_keys=True)
        return string_json + '\n'
    except (TypeError, ValueError) as e:
        raise ValueError(f"Message serialization failed: {e}")


def deserialize_message(string_json: str) -> dict:
    """
    Deserialize a JSON string back into Python dictionary.
    Also validates required fields in the message envelope.
    """
    try:
        string_json = string_json.strip()
        msg = json.loads(string_json)

        # Required fields for all messages
        required = {"type", "from", "to", "ts", "payload", "sig"}
        missing_flag = required - msg.keys()
        if missing_flag:
            raise ValueError(f"Missing required keys in message: {missing_flag}")

        return msg
    except (json.JSONDecodeError, ValueError) as e:
        raise ValueError(f"Failed to deserialize message: {e}")


def create_message(msg_type: str, sender: str, recipient: str, payload: dict, sig: str = "") -> dict:
    """
    Create a standardized message dictionary.
    """
    return {
        "type": msg_type,     
        "from": sender,       
        "to": recipient,       
        "ts": int(time.time() * 1000),  # Timestamp in milliseconds
        "payload": payload,    
        "sig": sig            
    }


if __name__ == "__main__":
    # 1. Create USER_HELLO message
    payload_hello = {"client": "cli-v1", "pubkey": "BASE64_PUBKEY"}
    hello_msg = create_message(HELLO_MSG, sender="Alice", recipient="server_1", payload=payload_hello)

    serialized = serialize_message(hello_msg)
    print("Serialized USER_HELLO:", serialized)
    deserialized = deserialize_message(serialized)
    print("Deserialized USER_HELLO:", deserialized)

    # 2. Create MSG_PRIVATE message
    payload_private = {"ciphertext": "<b64cipher>", "iv": "<b64iv>", "tag": "<b64tag>", "wrapped_key": "<b64key>"}
    private_msg = create_message(MSG_PRIVATE, sender="Bob", recipient="Alice", payload=payload_private)

    serialized_private = serialize_message(private_msg)
    print("Serialized MSG_PRIVATE:", serialized_private)
    deserialized_private = deserialize_message(serialized_private)
    print("Deserialized MSG_PRIVATE:", deserialized_private)


    # 3. Create USER_ADVERTISE (server-to-server gossip)
    payload_ad = {"user": "Carol", "server": "srv2"}
    ad_msg = create_message(USER_ADVERTISE, sender="srv2", recipient="*", payload=payload_ad)

    serialized_ad = serialize_message(ad_msg)
    print("Serialized USER_ADVERTISE:", serialized_ad)
    deserialized_ad = deserialize_message(serialized_ad)
    print("Deserialized USER_ADVERTISE:", deserialized_ad)
