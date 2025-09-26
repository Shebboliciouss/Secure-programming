from __future__ import annotations
from typing import Tuple
from base64 import urlsafe_b64encode, urlsafe_b64decode
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pss
from Crypto.Hash import SHA256
from Crypto import Random

# ---- base64url (no padding) ----
def b64u(data: bytes) -> str:
    return urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

def b64u_dec(s: str) -> bytes:
    pad = (-len(s)) % 4
    return urlsafe_b64decode((s + "=" * pad).encode("ascii"))

# ---- RSA-4096 keypair (optional helper) ----
def generate_rsa4096() -> Tuple[bytes, bytes]:
    key = RSA.generate(4096, Random.new().read)
    priv_pem = key.export_key(format="PEM", pkcs=8)
    pub_pem = key.publickey().export_key(format="PEM")
    return priv_pem, pub_pem

# ---- RSA-OAEP(SHA-256) ----
def rsa_oaep_encrypt(pub_pem: bytes, plaintext: bytes) -> bytes:
    pub = RSA.import_key(pub_pem)
    cipher = PKCS1_OAEP.new(pub, hashAlgo=SHA256)
    return cipher.encrypt(plaintext)

def rsa_oaep_decrypt(priv_pem: bytes, ciphertext: bytes) -> bytes:
    priv = RSA.import_key(priv_pem)
    cipher = PKCS1_OAEP.new(priv, hashAlgo=SHA256)
    return cipher.decrypt(ciphertext)

# ---- RSASSA-PSS(SHA-256) ----
def pss_sign(priv_pem: bytes, data: bytes) -> bytes:
    priv = RSA.import_key(priv_pem)
    h = SHA256.new(data)
    return pss.new(priv).sign(h)

def pss_verify(pub_pem: bytes, data: bytes, signature: bytes) -> bool:
    pub = RSA.import_key(pub_pem)
    h = SHA256.new(data)
    try:
        pss.new(pub).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False

# ---- SOCP v1.3: Direct Message build/verify/decrypt ----
def build_dm_payload(sender_id: str, recipient_id: str, ts_ms: int,
                     plaintext: bytes,
                     recipient_pub_pem: bytes,
                     sender_pub_pem: bytes,
                     sender_priv_pem: bytes) -> dict:

    ct = rsa_oaep_encrypt(recipient_pub_pem, plaintext)
    sig_input = ct + sender_id.encode() + recipient_id.encode() + str(ts_ms).encode()
    sig = pss_sign(sender_priv_pem, sig_input)
    return {
        "ciphertext": b64u(ct),
        "sender_pub": b64u(sender_pub_pem),
        "content_sig": b64u(sig),
    }

def decrypt_dm_payload(recipient_priv_pem: bytes,
                       sender_pub_pem: bytes,
                       sender_id: str,
                       recipient_id: str,
                       ts_ms: int,
                       payload: dict) -> bytes:

    ct = b64u_dec(payload["ciphertext"])
    sig = b64u_dec(payload["content_sig"])
    sig_input = ct + sender_id.encode() + recipient_id.encode() + str(ts_ms).encode()
    if not pss_verify(sender_pub_pem, sig_input, sig):
        raise ValueError("content_sig verification failed")
    return rsa_oaep_decrypt(recipient_priv_pem, ct)
