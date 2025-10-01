#from utils.json_utils import serialize_message, deserialize_message, create_message

import json 
import time 

#add serialisation and deserialisation - to convert python object in to string that can be sent over network 
#and saved 

#convert datastructure in to a format that can be stored 
def serialize_message (msg):

    #convert strign in to json format 
    #end at newline for websocket text framing 

    try:

        string_json=json.dumps(msg,separators=(',', ':'), sort_keys=True)
        return string_json + '\n'

    except (TypeError, ValueError) as e:

        raise ValueError(f"message serialization faield : {e}")   
#convert string back to previous data structure or python object 
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

#data structure in to be stored and serialised 
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

# Example usage:
if __name__ == "__main__":
    message = create_message(
        "USER_HELLO",
        "Alice",
        "server_1",
        #shows the client , and the public key used
        {"client": "cli-v1", "pubkey": "BASE64_PUBKEY"}
    )
    serialized = serialize_message(message)
    print("Serialized:", serialized)

    deserialized = deserialize_message(serialized)
    print("Deserialized:", deserialized)     