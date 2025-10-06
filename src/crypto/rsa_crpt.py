# src/crypto/rsa_crpt.py
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import json
import base64

# ---------------- Canonical JSON helper ----------------
def canonical_payload_bytes(payload: dict) -> bytes:
    """Convert payload dict into canonical JSON bytes for signing"""
    return json.dumps(payload, separators=(',', ':'), sort_keys=True).encode('utf-8')

# ---------------- Base64url helpers ----------------
def b64url_encode(data: bytes) -> str:
    """Base64 URL-safe encoding without padding"""
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')

def b64url_decode(data: str) -> bytes:
    """Base64 URL-safe decoding, adds padding if missing"""
    padding_needed = 4 - (len(data) % 4)
    if padding_needed < 4:
        data += "=" * padding_needed
    return base64.urlsafe_b64decode(data)

# ---------------- RSA Key Handling ----------------
def generate_rsa_keypair():
    """Generate RSA-4096 key pair"""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096
    )
    return private_key, private_key.public_key()

def export_public_key(public_key) -> bytes:
    """Export RSA public key as PEM bytes"""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def load_public_key(pem_bytes: bytes):
    """Load RSA public key from PEM bytes"""
    return serialization.load_pem_public_key(pem_bytes)

# ---------------- Signing ----------------
def sign_message(message_bytes: bytes, private_key) -> bytes:
    """Sign bytes using RSASSA-PSS (SHA-256)"""
    return private_key.sign(
        message_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

def verify_signature(public_key, message_bytes: bytes, signature: bytes) -> bool:
    """Verify RSASSA-PSS signature"""
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

# ---------------- Encryption ----------------
def _ensure_bytes(message) -> bytes:
    """Convert str -> bytes or pass through bytes"""
    if isinstance(message, bytes):
        return message
    if isinstance(message, str):
        return message.encode('utf-8')
    raise TypeError("message must be str or bytes")

def encrypt_bytes(public_key, data: bytes) -> bytes:
    """Encrypt arbitrary bytes using RSA-OAEP (SHA-256)"""
    return public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def encrypt_message(public_key, message) -> bytes:
    """Encrypt str or bytes using RSA-OAEP"""
    return encrypt_bytes(public_key, _ensure_bytes(message))

def decrypt_bytes(private_key, ciphertext: bytes) -> bytes:
    """Decrypt ciphertext -> raw bytes"""
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def decrypt_message(private_key, ciphertext: bytes) -> str:
    """Decrypt ciphertext -> UTF-8 string"""
    return decrypt_bytes(private_key, ciphertext).decode('utf-8')
