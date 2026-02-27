"""Configuration globale d'Archipel."""
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Config:
    # Reseau
    MULTICAST_ADDR = "239.255.42.99"
    MULTICAST_PORT = 6000
    DEFAULT_TCP_PORT = 7777
    CHUNK_SIZE = 524288  # 512 KB

    # Temps
    HELLO_INTERVAL = 30  # secondes
    PEER_TIMEOUT = 90    # secondes
    KEEPALIVE_INTERVAL = 15

    # Chemins
    DATA_DIR = Path.home() / ".archipel"
    KEYS_DIR = DATA_DIR / "keys"
    CHUNKS_DIR = DATA_DIR / "chunks"
    INDEX_DB = DATA_DIR / "index.db"

    @classmethod
    def init_dirs(cls) -> None:
        cls.DATA_DIR.mkdir(exist_ok=True)
        cls.KEYS_DIR.mkdir(exist_ok=True)
        cls.CHUNKS_DIR.mkdir(exist_ok=True)


class PacketType:
    HELLO = 0x01
    PEER_LIST = 0x02
    MSG = 0x03
    CHUNK_REQ = 0x04
    CHUNK_DATA = 0x05
    MANIFEST = 0x06
    ACK = 0x07
    HANDSHAKE_HELLO = 0x08
    HANDSHAKE_REPLY = 0x09
    AUTH = 0x0A
    AUTH_OK = 0x0B


ARCHIPEL_MAGIC = b"ARCH"
