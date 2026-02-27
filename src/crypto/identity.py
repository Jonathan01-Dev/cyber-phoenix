"""Gestion des identites cryptographiques Ed25519."""
import os
from pathlib import Path
from typing import Optional, Tuple

import nacl.exceptions
import nacl.signing
from nacl.public import Box, PrivateKey, PublicKey
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

from src.config import Config


class NodeIdentity:
    """Identite unique d'un noeud Archipel."""

    def __init__(self, private_key_path: Optional[Path] = None):
        self.config = Config()
        self.config.init_dirs()

        if private_key_path is None:
            private_key_path = self.config.KEYS_DIR / "node.key"

        self.private_key_path = private_key_path
        self._load_or_create_keys()

    def _load_or_create_keys(self) -> None:
        """Charge ou genere les paires de cles Ed25519 et X25519."""
        if self.private_key_path.exists():
            with open(self.private_key_path, "rb") as f:
                seed = f.read()
            self.signing_key = nacl.signing.SigningKey(seed)
        else:
            self.signing_key = nacl.signing.SigningKey.generate()
            with open(self.private_key_path, "wb") as f:
                f.write(self.signing_key.encode())
            try:
                os.chmod(self.private_key_path, 0o600)
            except OSError:
                pass

        self.verify_key = self.signing_key.verify_key
        self.node_id = self.verify_key.encode()  # 32 bytes

        self.private_x25519 = PrivateKey(self.signing_key.encode()[:32])
        self.public_x25519 = self.private_x25519.public_key

    @property
    def node_id_hex(self) -> str:
        return self.node_id.hex()

    def sign(self, message: bytes) -> bytes:
        """Signe un message avec Ed25519."""
        return self.signing_key.sign(message).signature

    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        """Verifie une signature."""
        try:
            verify_key = nacl.signing.VerifyKey(public_key)
            verify_key.verify(message, signature)
            return True
        except nacl.exceptions.BadSignatureError:
            return False

    def derive_session_key(self, peer_public_x25519: PublicKey) -> bytes:
        """Derive une cle de session via X25519 ECDH + HKDF."""
        shared = Box(self.private_x25519, peer_public_x25519).shared_key()
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"archipel-v1",
        )
        return hkdf.derive(shared)


class EncryptedSession:
    """Session chiffree entre deux noeuds avec Forward Secrecy."""

    def __init__(self, session_key: bytes):
        self.session_key = session_key
        self.message_counter = 0

    def encrypt(self, plaintext: bytes) -> Tuple[bytes, bytes, bytes]:
        """Chiffre avec AES-256-GCM."""
        nonce = self.message_counter.to_bytes(4, "big") + get_random_bytes(8)
        self.message_counter += 1

        cipher = AES.new(self.session_key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        return nonce, ciphertext, tag

    def decrypt(self, nonce: bytes, ciphertext: bytes, tag: bytes) -> bytes:
        """Dechiffre avec AES-256-GCM."""
        cipher = AES.new(self.session_key, AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag)

    @staticmethod
    def generate_ephemeral_keys() -> Tuple[PrivateKey, PublicKey]:
        """Genere des cles ephemeres pour le handshake."""
        private_key = PrivateKey.generate()
        return private_key, private_key.public_key
