import time
from base64 import urlsafe_b64encode, urlsafe_b64decode
from crypto import rsa_crpt

# ------------------ Helpers ------------------

def b64url_encode(data: bytes) -> str:
    return urlsafe_b64encode(data).rstrip(b'=').decode('ascii')

def b64url_decode(data: str) -> bytes:
    rem = len(data) % 4
    if rem:
        data += "=" * (4 - rem)
    return urlsafe_b64decode(data)

# ------------------ Users and Keys ------------------

users = ["Alice", "Bob", "Carol"]
keys = {name: rsa_crpt.generate_rsa_keypair() for name in users}  # name -> (priv, pub)

# ------------------ Test Private Messages ------------------

def send_private(sender, recipient, plaintext):
    sender_priv, sender_pub = keys[sender]
    recipient_priv, recipient_pub = keys[recipient]
    
    ts = int(time.time() * 1000)
    # Encrypt message
    ciphertext = rsa_crpt.encrypt_message(recipient_pub, plaintext)
    ciphertext_b64 = b64url_encode(ciphertext)
    # Sign message
    content_bytes = (ciphertext_b64 + sender + recipient + str(ts)).encode('utf-8')
    sig_b64 = b64url_encode(rsa_crpt.sign_message(content_bytes, sender_priv))
    
    # Recipient verifies & decrypts
    content_bytes_received = (ciphertext_b64 + sender + recipient + str(ts)).encode('utf-8')
    rsa_crpt.verify_signature(sender_pub, content_bytes_received, b64url_decode(sig_b64))
    decrypted = rsa_crpt.decrypt_message(recipient_priv, b64url_decode(ciphertext_b64))
    
    print(f"[PRIVATE] {sender} → {recipient}: {decrypted}")

# Test private messages
send_private("Alice", "Bob", "Hello Bob! This is Alice.")
send_private("Carol", "Alice", "Hi Alice! Carol here.")

# ------------------ Test Group Messages ------------------

def send_group(sender, recipients, plaintext):
    sender_priv, sender_pub = keys[sender]
    ts = int(time.time() * 1000)
    shares = []

    # Encrypt and sign for each recipient
    for recipient in recipients:
        if recipient == sender:
            continue
        recipient_priv, recipient_pub = keys[recipient]
        ciphertext = rsa_crpt.encrypt_message(recipient_pub, plaintext)
        ciphertext_b64 = b64url_encode(ciphertext)
        content_bytes = (ciphertext_b64 + sender + recipient + str(ts)).encode('utf-8')
        sig_b64 = b64url_encode(rsa_crpt.sign_message(content_bytes, sender_priv))
        shares.append((recipient, ciphertext_b64, sig_b64))

    # Each recipient decrypts and verifies
    for recipient, ciphertext_b64, sig_b64 in shares:
        recipient_priv, recipient_pub = keys[recipient]
        content_bytes_received = (ciphertext_b64 + sender + recipient + str(ts)).encode('utf-8')
        rsa_crpt.verify_signature(sender_pub, content_bytes_received, b64url_decode(sig_b64))
        decrypted = rsa_crpt.decrypt_message(recipient_priv, b64url_decode(ciphertext_b64))
        print(f"[GROUP] {sender} → {recipient}: {decrypted}")

# Test group message
send_group("Alice", users, "Hello everyone! This is a group message from Alice.")
