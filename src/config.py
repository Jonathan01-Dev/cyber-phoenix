"""Configuration globale d'Archipel."""
import os
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Config:
    # Runtime
    ENV_PATH = Path(".env")

    # Reseau
    MULTICAST_ADDR = "239.255.42.99"
    MULTICAST_PORT = 6000
    DEFAULT_TCP_PORT = 7777
    MIN_PARALLEL_CONNECTIONS = 10
    MAX_CONNECTIONS = 64
    CHUNK_SIZE = 524288  # 512 KB

    # Temps
    HELLO_INTERVAL = 30  # secondes
    PEER_TIMEOUT = 90    # secondes
    KEEPALIVE_INTERVAL = 15
    KEEPALIVE_TIMEOUT = 45
    HANDSHAKE_MAX_SKEW = 120
    DISCOVERY_BROADCAST_FALLBACK = True
    DISCOVERY_LOCALHOST_FALLBACK = True
    INTERFACE_IP = ""

    # Chemins
    DATA_DIR = Path.home() / ".archipel"
    KEYS_DIR = DATA_DIR / "keys"
    CHUNKS_DIR = DATA_DIR / "chunks"
    INDEX_DB = DATA_DIR / "index.db"
    PEERS_DB = DATA_DIR / "peers.json"
    TRUST_DB = DATA_DIR / "trust.json"

    @classmethod
    def init_dirs(cls) -> None:
        cls.DATA_DIR.mkdir(exist_ok=True)
        cls.KEYS_DIR.mkdir(exist_ok=True)
        cls.CHUNKS_DIR.mkdir(exist_ok=True)

    @classmethod
    def load_env(cls) -> None:
        """Charge .env puis variables d'environnement pour la configuration runtime."""
        if cls.ENV_PATH.exists():
            for line in cls.ENV_PATH.read_text(encoding="utf-8").splitlines():
                stripped = line.strip()
                if not stripped or stripped.startswith("#") or "=" not in stripped:
                    continue
                key, value = stripped.split("=", 1)
                key = key.strip()
                value = value.strip().strip('"').strip("'")
                os.environ.setdefault(key, value)

        cls.DEFAULT_TCP_PORT = int(os.getenv("ARCHIPEL_TCP_PORT", cls.DEFAULT_TCP_PORT))
        cls.HELLO_INTERVAL = int(os.getenv("ARCHIPEL_HELLO_INTERVAL", cls.HELLO_INTERVAL))
        cls.PEER_TIMEOUT = int(os.getenv("ARCHIPEL_PEER_TIMEOUT", cls.PEER_TIMEOUT))
        cls.KEEPALIVE_INTERVAL = int(
            os.getenv("ARCHIPEL_KEEPALIVE_INTERVAL", cls.KEEPALIVE_INTERVAL)
        )
        cls.KEEPALIVE_TIMEOUT = int(
            os.getenv("ARCHIPEL_KEEPALIVE_TIMEOUT", cls.KEEPALIVE_TIMEOUT)
        )
        cls.HANDSHAKE_MAX_SKEW = int(
            os.getenv("ARCHIPEL_HANDSHAKE_MAX_SKEW", cls.HANDSHAKE_MAX_SKEW)
        )
        cls.MAX_CONNECTIONS = int(os.getenv("ARCHIPEL_MAX_CONNECTIONS", cls.MAX_CONNECTIONS))
        cls.DISCOVERY_BROADCAST_FALLBACK = os.getenv(
            "ARCHIPEL_DISCOVERY_BROADCAST_FALLBACK",
            str(cls.DISCOVERY_BROADCAST_FALLBACK),
        ).lower() in ("1", "true", "yes", "on")
        cls.DISCOVERY_LOCALHOST_FALLBACK = os.getenv(
            "ARCHIPEL_DISCOVERY_LOCALHOST_FALLBACK",
            str(cls.DISCOVERY_LOCALHOST_FALLBACK),
        ).lower() in ("1", "true", "yes", "on")
        cls.INTERFACE_IP = os.getenv("ARCHIPEL_INTERFACE_IP", cls.INTERFACE_IP).strip()


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
    PING = 0x0C
    PONG = 0x0D


ARCHIPEL_MAGIC = b"ARCH"
