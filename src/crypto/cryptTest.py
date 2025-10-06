from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import json, base64

# ---------------- CONFIG ----------------
DEBUG_CRYPTO = True  # Set to False in production

# ---------------- Canonical JSON helper ----------------
def canonical_payload_bytes(payload: dict) -> bytes:
    """Convert payload dict into canonical JSON bytes for signing"""
    return json.dumps(payload, separators=(',', ':'), sort_keys=True).encode('utf-8')

# ---------------- RSA Key Handling ----------------
def generate_rsa_keypair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096
    )
    if DEBUG_CRYPTO:
        print("[DEBUG][RSA] Generated new 4096-bit RSA key pair.")
    return private_key, private_key.public_key()

def export_public_key(public_key) -> bytes:
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    if DEBUG_CRYPTO:
        print(f"[DEBUG][RSA] Exported public key ({len(pem)} bytes PEM).")
    return pem

def load_public_key(pem_bytes: bytes):
    if DEBUG_CRYPTO:
        print("[DEBUG][RSA] Loaded public key from PEM.")
    return serialization.load_pem_public_key(pem_bytes)

# ---------------- Signing ----------------
def sign_message(payload: dict, private_key) -> bytes:
    """Sign canonical JSON of payload."""
    message_bytes = canonical_payload_bytes(payload)
    signature = private_key.sign(
        message_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature


def verify_signature(public_key, payload: dict, signature: bytes) -> bool:
    """Verify canonical JSON of payload."""
    message_bytes = canonical_payload_bytes(payload)
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

# ---------------- Encryption helpers ----------------
def _ensure_bytes_for_encrypt(message):
    if isinstance(message, bytes):
        return message
    if isinstance(message, str):
        return message.encode('utf-8')
    raise TypeError("message must be str or bytes")

def encrypt_message(public_key, message: str) -> bytes:
    """Encrypt a text message (str) -> returns bytes ciphertext"""
    if DEBUG_CRYPTO:
        print(f"[DEBUG][ENC] Encrypting message (len={len(message)}): {message[:60]!r}")
    ciphertext = encrypt_bytes(public_key, message.encode('utf-8'))
    if DEBUG_CRYPTO:
        preview = base64.b64encode(ciphertext).decode()[:60]
        print(f"[DEBUG][ENC] → Ciphertext (base64 preview): {preview}...")
    return ciphertext

def encrypt_bytes(public_key, data: bytes) -> bytes:
    """Encrypt arbitrary bytes using RSA-OAEP (public_key is a cryptography object)."""
    ciphertext = public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    if DEBUG_CRYPTO:
        print(f"[DEBUG][ENC] Encrypted {len(data)} bytes → {len(ciphertext)} bytes ciphertext.")
    return ciphertext

def decrypt_message(private_key, ciphertext: bytes) -> str:
    """Decrypt ciphertext (bytes) -> returns decoded UTF-8 string."""
    plaintext = decrypt_bytes(private_key, ciphertext).decode('utf-8')
    if DEBUG_CRYPTO:
        print(f"[DEBUG][DEC] Decrypted ciphertext → {plaintext[:60]!r}")
    return plaintext

def decrypt_bytes(private_key, ciphertext: bytes) -> bytes:
    """Decrypt ciphertext (bytes) -> returns raw bytes."""
    data = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    if DEBUG_CRYPTO:
        print(f"[DEBUG][DEC] Decrypted {len(ciphertext)} → {len(data)} bytes.")
    return data
