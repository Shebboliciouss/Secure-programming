import json 
import time 

#message types for user 

#user ehello for when user connnects 
HELLO_MSG="userHellO"
# msg private for direct message 
MSG_PRIVATE = "MSG_PRIVATE"
#message deliver server delivers message to user 
MSG_USER_DELIVER = "USER_DELIVER"
#message serialisation and deserialisation

def serialize_message (msg):

    #convert strign in to json format 
    #end at newline for websocket text framing 

    try:

        string_json=json.dumps(msg,separators=(',', ':'), sort_keys=True)
        return string_json + '\n'

    except (TypeError, ValueError) as e:

        raise ValueError(f"message serialization faield : {e}")   

def deserialize_message(string_json):

    #convert string back to python dictionary 
    #removes the new line as well

    try:
        string_json=string_json.strip()    
        msg=json.loads(string_json)   
        #check validation using give socp envelope 

        required = {"type", "from", "to", "ts", "payload", "sig"}
        missing_flag = required-msg.keys()
        if missing_flag:
            raise ValueError(f"missing_flag required keys in message: {missing_flag}")
        return msg
    except (json.JSONDecodeError, ValueError) as e:
        raise ValueError(f"Failed to deserialize message: {e}")        

def create_message(msg_type, sender, recipient, payload, sig=""):
  
    return {
        #type of message sent e.g privat peer etc
        "type": msg_type,
        "from": sender,
        "to": recipient,
        #time stamp
        "ts": int(time.time() * 1000),
        #messafe content 
        "payload": payload,
        #message signature 
        "sig": sig
    }

    #TESTING serialisationa nd deserialisation using given data type 

    # --- Example Usage / Test ---
if __name__ == "__main__":
    # 1. Create USER_HELLO message
    payload_hello = {"client": "cli-v1", "pubkey": "BASE64_PUBKEY"}
    hello_msg = create_message(HELLO_MSG, sender="Alice", recipient="server_1", payload=payload_hello)
    
    # Serialize
    serialized = serialize_message(hello_msg)
    print("Serialized USER_HELLO:", serialized)
    
    # Deserialize
    deserialized = deserialize_message(serialized)
    print("Deserialized USER_HELLO:", deserialized)

    # 2. Create a MSG_PRIVATE message
    payload_private = {"ciphertext": "<b64cipher>", "iv": "<b64iv>", "tag": "<b64tag>", "wrapped_key": "<b64key>"}
    private_msg = create_message(MSG_PRIVATE, sender="Bob", recipient="Alice", payload=payload_private)
    
    serialized_private = serialize_message(private_msg)
    print("Serialized MSG_PRIVATE:", serialized_private)
    
    deserialized_private = deserialize_message(serialized_private)
    print("Deserialized MSG_PRIVATE:", deserialized_private)