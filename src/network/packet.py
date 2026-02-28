"""Format de paquet binaire Archipel."""
import hashlib
import hmac
import struct
from dataclasses import dataclass
from typing import Optional

from src.config import ARCHIPEL_MAGIC


@dataclass
class ArchipelPacket:
    magic: bytes
    pkt_type: int
    node_id: bytes
    payload_len: int
    payload: bytes
    signature: bytes

    HEADER_SIZE = 4 + 1 + 32 + 4
    SIGNATURE_SIZE = 32
    TOTAL_OVERHEAD = HEADER_SIZE + SIGNATURE_SIZE

    def serialize(self) -> bytes:
        header = struct.pack(
            ">4sB32sI", self.magic, self.pkt_type, self.node_id, len(self.payload)
        )
        return header + self.payload + self.signature

    @classmethod
    def parse(cls, data: bytes) -> Optional["ArchipelPacket"]:
        if len(data) < cls.HEADER_SIZE:
            return None

        magic, pkt_type, node_id, payload_len = struct.unpack(
            ">4sB32sI", data[: cls.HEADER_SIZE]
        )

        if magic != ARCHIPEL_MAGIC:
            return None

        expected_len = cls.HEADER_SIZE + payload_len + cls.SIGNATURE_SIZE
        if len(data) < expected_len:
            return None

        payload = data[cls.HEADER_SIZE : cls.HEADER_SIZE + payload_len]
        signature = data[cls.HEADER_SIZE + payload_len : expected_len]

        return cls(magic, pkt_type, node_id, payload_len, payload, signature)


class PacketBuilder:
    """Constructeur de paquets Archipel."""

    @staticmethod
    def build(
        pkt_type: int, node_id: bytes, payload: bytes, signing_key: Optional[bytes] = None
    ) -> bytes:
        header = struct.pack(">4sB32sI", ARCHIPEL_MAGIC, pkt_type, node_id, len(payload))

        if signing_key:
            signature = PacketBuilder._compute_hmac(signing_key, header + payload)
        else:
            signature = b"\x00" * 32

        return header + payload + signature

    @staticmethod
    def build_encrypted(session, pkt_type: int, node_id: bytes, plaintext: bytes) -> bytes:
        nonce, ciphertext, tag = session.encrypt(plaintext)
        payload = nonce + tag + ciphertext
        return PacketBuilder.build(pkt_type, node_id, payload, signing_key=session.session_key)

    @staticmethod
    def verify_signature(packet: ArchipelPacket, signing_key: bytes) -> bool:
        header = struct.pack(
            ">4sB32sI",
            packet.magic,
            packet.pkt_type,
            packet.node_id,
            len(packet.payload),
        )
        expected = PacketBuilder._compute_hmac(signing_key, header + packet.payload)
        return hmac.compare_digest(packet.signature, expected)

    @staticmethod
    def decrypt_payload(session, payload: bytes) -> Optional[bytes]:
        if len(payload) < 28:
            return None

        nonce = payload[:12]
        tag = payload[12:28]
        ciphertext = payload[28:]

        try:
            return session.decrypt(nonce, ciphertext, tag)
        except Exception:
            return None

    @staticmethod
    def _compute_hmac(signing_key: bytes, data: bytes) -> bytes:
        return hmac.new(signing_key, data, hashlib.sha256).digest()
