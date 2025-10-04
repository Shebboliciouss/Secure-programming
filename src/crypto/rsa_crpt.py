from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import json

# ---------------- Crypto Helpers ----------------

def canonical_payload_bytes(payload: dict) -> bytes:
    """Convert payload dict into canonical JSON bytes for signing"""
    return json.dumps(payload, separators=(',', ':'), sort_keys=True).encode('utf-8')

# ---------------- RSA Key Handling ----------------

def sign_message(message_bytes: bytes, private_key) -> bytes:
    signature = private_key.sign(
        message_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def verify_signature(public_key, message_bytes: bytes, signature: bytes) -> bool:
    try:
        public_key.verify(
            signature,
            message_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

def generate_rsa_keypair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096
    )
    return private_key, private_key.public_key()

def export_public_key(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def load_public_key(pem_bytes):
    return serialization.load_pem_public_key(pem_bytes)

# ---------------- RSA Encryption ----------------

def encrypt_message(public_key, message: str) -> bytes:
    return public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def decrypt_message(private_key, ciphertext: bytes) -> str:
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    ).decode()
