from . import rsa_crpt as rsa

priv, pub = rsa.generate_rsa_keypair()
payload = {"msg": "hello", "time": 123456}

# Convert dict -> canonical JSON bytes
payload_bytes = rsa.canonical_payload_bytes(payload)

# Sign + verify
sig = rsa.sign_message(payload_bytes, priv)
assert rsa.verify_signature(pub, payload_bytes, sig)
print("[TEST] ✅ Canonical signing + base64url ready")

# round-trip encryption
ciphertext = rsa.encrypt_message(pub, "secret text")
print("[DEBUG] ciphertext b64url:", rsa.b64url_encode(ciphertext))
plaintext = rsa.decrypt_message(priv, ciphertext)
assert plaintext == "secret text"
print("[TEST] ✅ RSA-OAEP round trip ok")
