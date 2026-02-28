"""Decouverte de pairs via UDP Multicast."""
import asyncio
import json
import socket
import struct
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Optional, Set

from src.config import Config, PacketType
from src.crypto.identity import NodeIdentity
from src.crypto.tofu import TrustStore
from src.network.packet import ArchipelPacket, PacketBuilder


@dataclass
class PeerInfo:
    node_id: str
    ip: str
    tcp_port: int
    last_seen: float = field(default_factory=time.time)
    shared_files: Set[str] = field(default_factory=set)
    reputation: float = 1.0

    def is_alive(self, timeout: int = Config.PEER_TIMEOUT) -> bool:
        return (time.time() - self.last_seen) < timeout


class PeerTable:
    """Table de routage P2P."""

    def __init__(self, self_node_id: Optional[str] = None):
        self.config = Config()
        self.config.init_dirs()
        self.storage_path = self.config.PEERS_DB
        self.peers: Dict[str, PeerInfo] = {}
        self.callbacks: list[Callable] = []
        self.self_node_id = self_node_id
        self._load_from_disk()

    def upsert(self, node_id: str, ip: str, tcp_port: int) -> bool:
        if self.self_node_id and node_id == self.self_node_id:
            return False

        is_new = node_id not in self.peers
        existing = self.peers.get(node_id)

        if existing:
            existing.ip = ip
            existing.tcp_port = tcp_port
            existing.last_seen = time.time()
        else:
            self.peers[node_id] = PeerInfo(node_id, ip, tcp_port, time.time())

        if is_new:
            for cb in self.callbacks:
                cb("peer_joined", node_id, ip, tcp_port)
        self._save_to_disk()
        return is_new

    def remove_stale_peers(self) -> None:
        stale = [nid for nid, p in self.peers.items() if not p.is_alive()]
        for nid in stale:
            del self.peers[nid]
            for cb in self.callbacks:
                cb("peer_left", nid)
        if stale:
            self._save_to_disk()

    def get_peer(self, node_id: str) -> Optional[PeerInfo]:
        return self.peers.get(node_id)

    def get_all_peers(self) -> list[PeerInfo]:
        return list(self.peers.values())

    def on_change(self, callback: Callable) -> None:
        self.callbacks.append(callback)

    def merge_peer_list(self, peers_data: list[dict[str, Any]]) -> None:
        for peer in peers_data:
            try:
                node_id = str(peer["node_id"])
                ip = str(peer["ip"])
                tcp_port = int(peer.get("port", peer.get("tcp_port")))
                if node_id:
                    self.upsert(node_id, ip, tcp_port)
            except (KeyError, TypeError, ValueError):
                continue

    def as_serializable(self) -> list[dict[str, Any]]:
        return [
            {
                "node_id": p.node_id,
                "ip": p.ip,
                "tcp_port": p.tcp_port,
                "last_seen": p.last_seen,
                "shared_files": sorted(p.shared_files),
                "reputation": p.reputation,
            }
            for p in self.get_all_peers()
        ]

    def _load_from_disk(self) -> None:
        if not self.storage_path.exists():
            return

        try:
            raw = json.loads(self.storage_path.read_text(encoding="utf-8"))
            for item in raw:
                node_id = str(item["node_id"])
                if self.self_node_id and node_id == self.self_node_id:
                    continue
                self.peers[node_id] = PeerInfo(
                    node_id=node_id,
                    ip=str(item["ip"]),
                    tcp_port=int(item["tcp_port"]),
                    last_seen=float(item.get("last_seen", time.time())),
                    shared_files=set(item.get("shared_files", [])),
                    reputation=float(item.get("reputation", 1.0)),
                )
        except Exception:
            self.peers = {}

    def _save_to_disk(self) -> None:
        data = self.as_serializable()
        self.storage_path.write_text(json.dumps(data, indent=2), encoding="utf-8")


class DiscoveryService:
    """Service de decouverte multicast."""

    def __init__(
        self,
        identity: NodeIdentity,
        tcp_port: int,
        peer_table: PeerTable,
        trust_store: Optional[TrustStore] = None,
    ):
        self.identity = identity
        self.tcp_port = tcp_port
        self.peer_table = peer_table
        self.trust_store = trust_store
        self.config = Config()
        self.running = False
        self.sock: Optional[socket.socket] = None
        self.interface_ip = self._detect_interface_ip(self.config.INTERFACE_IP)

    async def start(self) -> None:
        self.running = True

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except (AttributeError, OSError):
            pass
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.sock.bind(("", self.config.MULTICAST_PORT))
        self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
        self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)
        self.sock.setsockopt(
            socket.IPPROTO_IP,
            socket.IP_MULTICAST_IF,
            socket.inet_aton(self.interface_ip),
        )

        mreq = struct.pack(
            "=4s4s",
            socket.inet_aton(self.config.MULTICAST_ADDR),
            socket.inet_aton(self.interface_ip),
        )
        self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        self.sock.setblocking(True)
        print(f"[DISCOVERY] interface={self.interface_ip}")

        await asyncio.gather(
            self._send_hello_loop(), self._receive_loop(), self._cleanup_loop()
        )

    async def _send_hello_loop(self) -> None:
        while self.running:
            try:
                hello_payload = json.dumps(
                    {"tcp_port": self.tcp_port, "timestamp": time.time()}
                ).encode()

                packet = PacketBuilder.build(
                    PacketType.HELLO, self.identity.node_id, hello_payload
                )

                self.sock.sendto(
                    packet, (self.config.MULTICAST_ADDR, self.config.MULTICAST_PORT)
                )
                if self.config.DISCOVERY_BROADCAST_FALLBACK:
                    self.sock.sendto(packet, ("255.255.255.255", self.config.MULTICAST_PORT))
                if self.config.DISCOVERY_LOCALHOST_FALLBACK:
                    self.sock.sendto(packet, ("127.0.0.1", self.config.MULTICAST_PORT))
                print(
                    f"[DISCOVERY] HELLO sent node={self.identity.node_id_hex[:12]} "
                    f"port={self.tcp_port}"
                )

                await asyncio.sleep(self.config.HELLO_INTERVAL)
            except Exception as e:
                print(f"Erreur envoi HELLO: {e}")
                await asyncio.sleep(5)

    async def _receive_loop(self) -> None:
        while self.running:
            try:
                data, addr = await asyncio.to_thread(self.sock.recvfrom, 2048)
                await self._handle_packet(data, addr[0])
            except OSError:
                if not self.running:
                    return
                await asyncio.sleep(0.1)

    async def _handle_packet(self, data: bytes, sender_ip: str) -> None:
        packet = ArchipelPacket.parse(data)
        if not packet:
            return

        if packet.node_id == self.identity.node_id:
            return

        node_id_hex = packet.node_id.hex()

        if packet.pkt_type == PacketType.HELLO:
            try:
                payload = json.loads(packet.payload)
                tcp_port = payload["tcp_port"]
                if self.trust_store:
                    endpoint = f"{sender_ip}:{tcp_port}"
                    if not self.trust_store.trust_endpoint(endpoint, node_id_hex):
                        known = self.trust_store.get_node_id(endpoint)
                        print(
                            f"[TOFU] reject endpoint={endpoint} "
                            f"known={known[:12] if known else 'unknown'} "
                            f"seen={node_id_hex[:12]}"
                        )
                        return
                is_new = self.peer_table.upsert(node_id_hex, sender_ip, tcp_port)
                print(f"[DISCOVERY] HELLO recv node={node_id_hex[:12]} ip={sender_ip}:{tcp_port}")

                if is_new:
                    await self._send_peer_list(sender_ip, tcp_port)
            except (json.JSONDecodeError, KeyError):
                return

    async def _send_peer_list(self, target_ip: str, target_port: int) -> None:
        peers_data = [
            {"node_id": p.node_id, "ip": p.ip, "port": p.tcp_port}
            for p in self.peer_table.get_all_peers()
        ]

        payload = json.dumps(peers_data).encode()
        packet = PacketBuilder.build(PacketType.PEER_LIST, self.identity.node_id, payload)

        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(target_ip, target_port), timeout=5.0
            )
            frame = self._tlv_pack(PacketType.PEER_LIST, packet)
            writer.write(frame)
            await writer.drain()
            writer.close()
            await writer.wait_closed()
        except Exception:
            return

    async def _cleanup_loop(self) -> None:
        while self.running:
            self.peer_table.remove_stale_peers()
            await asyncio.sleep(30)

    def stop(self) -> None:
        self.running = False
        if self.sock:
            self.sock.close()

    @staticmethod
    def _tlv_pack(tlv_type: int, value: bytes) -> bytes:
        return struct.pack(">BI", tlv_type, len(value)) + value

    @staticmethod
    def _detect_interface_ip(preferred_ip: str = "") -> str:
        if preferred_ip:
            return preferred_ip

        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            probe.connect(("8.8.8.8", 80))
            ip = probe.getsockname()[0]
            if ip and not ip.startswith("127."):
                return ip
        except OSError:
            pass
        finally:
            probe.close()

        # Fallback sans trafic externe.
        try:
            host_ips = socket.gethostbyname_ex(socket.gethostname())[2]
            for ip in host_ips:
                if ip and not ip.startswith("127."):
                    return ip
        except OSError:
            pass

        return "127.0.0.1"
