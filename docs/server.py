import asyncio
import websockets
import json
import base64
import hashlib
import time
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import uuid
from typing import Dict, Set, List, Optional

class SecureChatServer:
    def __init__(self, host: str, port: int, server_id: str):
        self.host = host
        self.port = port
        self.server_id = server_id
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.public_key = self.private_key.public_key()
        
        # Peer management
        self.peers: Dict[str, websockets.WebSocketServerProtocol] = {}
        self.peer_public_keys: Dict[str, rsa.RSAPublicKey] = {}
        
        # User management
        self.user_locations: Dict[str, str] = {}  # user_id -> server_id
        self.local_users: Dict[str, websockets.WebSocketServerProtocol] = {}
        
        # Group management
        self.groups: Dict[str, Dict] = {}  # group_id -> group_info
        self.group_members: Dict[str, Set[str]] = {}  # group_id -> set of user_ids
        self.group_versions: Dict[str, int] = {}  # group_id -> version number
        
        # Message queue for offline users
        self.message_queues: Dict[str, List[Dict]] = {}
        
        self.heartbeat_interval = 30
        self.is_running = True

    def get_public_key_pem(self) -> str:
        """Serialize public key to PEM format"""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

    def load_peer_public_key(self, pem_data: str) -> rsa.RSAPublicKey:
        """Load peer public key from PEM string"""
        return serialization.load_pem_public_key(pem_data.encode('utf-8'))

    def rsa_encrypt(self, plaintext: str, public_key: rsa.RSAPublicKey) -> str:
        """Encrypt data with RSA public key"""
        encrypted = public_key.encrypt(
            plaintext.encode('utf-8'),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return base64.b64encode(encrypted).decode('utf-8')

    def rsa_decrypt(self, ciphertext: str) -> str:
        """Decrypt data with RSA private key"""
        encrypted_data = base64.b64decode(ciphertext)
        decrypted = self.private_key.decrypt(
            encrypted_data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted.decode('utf-8')

    def generate_aes_key(self) -> bytes:
        """Generate AES-256 key for group chat"""
        return os.urandom(32)

    def aes_encrypt(self, plaintext: str, key: bytes) -> Dict[str, str]:
        """Encrypt data with AES-256-GCM"""
        iv = os.urandom(12)
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext.encode('utf-8')) + encryptor.finalize()
        return {
            'iv': base64.b64encode(iv).decode('utf-8'),
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
            'tag': base64.b64encode(encryptor.tag).decode('utf-8')
        }

    def aes_decrypt(self, encrypted_data: Dict[str, str], key: bytes) -> str:
        """Decrypt data with AES-256-GCM"""
        iv = base64.b64decode(encrypted_data['iv'])
        ciphertext = base64.b64decode(encrypted_data['ciphertext'])
        tag = base64.b64decode(encrypted_data['tag'])
        
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext.decode('utf-8')

    def sign_message(self, message: str) -> str:
        """Sign message with private key"""
        signature = self.private_key.sign(
            message.encode('utf-8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return base64.b64encode(signature).decode('utf-8')

    def verify_signature(self, message: str, signature: str, public_key: rsa.RSAPublicKey) -> bool:
        """Verify message signature"""
        try:
            signature_bytes = base64.b64decode(signature)
            public_key.verify(
                signature_bytes,
                message.encode('utf-8'),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False