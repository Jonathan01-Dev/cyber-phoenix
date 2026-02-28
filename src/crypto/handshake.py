"""Protocole de handshake Archipel (inspire Noise Protocol)."""
import hashlib
import struct
import time
from dataclasses import dataclass
from typing import Optional, Tuple

from nacl.public import Box, PrivateKey, PublicKey

from src.config import Config, PacketType
from src.crypto.identity import EncryptedSession, NodeIdentity


@dataclass
class HandshakeMessage:
    ephemeral_pub: bytes
    timestamp: int
    signature: Optional[bytes] = None
    node_id: Optional[bytes] = None

    def serialize(self) -> bytes:
        data = struct.pack(">Q", self.timestamp) + self.ephemeral_pub
        if self.signature:
            data += self.signature
        if self.node_id:
            data += self.node_id
        return data

    @classmethod
    def parse(
        cls, data: bytes, has_signature: bool = False, has_node_id: bool = False
    ) -> "HandshakeMessage":
        timestamp = struct.unpack(">Q", data[:8])[0]
        ephemeral_pub = data[8:40]
        offset = 40

        signature = None
        if has_signature:
            signature = data[offset : offset + 64]
            offset += 64

        node_id = None
        if has_node_id:
            node_id = data[offset : offset + 32]

        return cls(ephemeral_pub, timestamp, signature, node_id)


class HandshakeProtocol:
    """Implemente le handshake Archipel pour etablir une session securisee."""

    def __init__(self, identity: NodeIdentity):
        self.identity = identity
        self.config = Config()
        self.sessions = {}

    def initiate_handshake(self) -> Tuple[bytes, PrivateKey]:
        e_private, e_public = EncryptedSession.generate_ephemeral_keys()

        msg = HandshakeMessage(ephemeral_pub=e_public.encode(), timestamp=int(time.time()))

        packet = self._build_packet(PacketType.HANDSHAKE_HELLO, msg.serialize())
        return packet, e_private

    def respond_to_handshake(self, hello_data: bytes) -> Tuple[bytes, bytes, EncryptedSession]:
        msg = HandshakeMessage.parse(hello_data)
        if not self._is_fresh(msg.timestamp):
            raise ValueError("Handshake HELLO timestamp out of accepted window")

        e_private, e_public = EncryptedSession.generate_ephemeral_keys()
        e_remote = PublicKey(msg.ephemeral_pub)
        shared = Box(e_private, e_remote).shared_key()

        session = EncryptedSession(self._derive_key(shared))

        shared_hash = hashlib.sha256(shared).digest()
        signature = self.identity.sign(shared_hash)

        reply = HandshakeMessage(
            ephemeral_pub=e_public.encode(),
            timestamp=int(time.time()),
            signature=signature,
            node_id=self.identity.node_id,
        )

        packet = self._build_packet(PacketType.HANDSHAKE_REPLY, reply.serialize())
        return packet, msg.ephemeral_pub, session

    def complete_handshake(
        self, reply_data: bytes, e_private: PrivateKey, expected_node_id: bytes
    ) -> Optional[EncryptedSession]:
        msg = HandshakeMessage.parse(reply_data, has_signature=True, has_node_id=True)
        if not self._is_fresh(msg.timestamp):
            return None

        if msg.node_id != expected_node_id:
            return None

        e_remote = PublicKey(msg.ephemeral_pub)
        shared = Box(e_private, e_remote).shared_key()

        shared_hash = hashlib.sha256(shared).digest()
        if not self.identity.verify(shared_hash, msg.signature, msg.node_id):
            return None

        return EncryptedSession(self._derive_key(shared))

    def _derive_key(self, shared_secret: bytes) -> bytes:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF

        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"archipel-v1",
        )
        return hkdf.derive(shared_secret)

    def _build_packet(self, pkt_type: int, payload: bytes) -> bytes:
        from src.network.packet import PacketBuilder

        return PacketBuilder.build(pkt_type, self.identity.node_id, payload)

    def _is_fresh(self, remote_ts: int) -> bool:
        now = int(time.time())
        return abs(now - int(remote_ts)) <= self.config.HANDSHAKE_MAX_SKEW
