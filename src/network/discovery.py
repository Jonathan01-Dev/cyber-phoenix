"""Decouverte de pairs via UDP Multicast."""
import asyncio
import json
import socket
import struct
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, Optional, Set

from src.config import Config, PacketType
from src.crypto.identity import NodeIdentity
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

    def __init__(self):
        self.peers: Dict[str, PeerInfo] = {}
        self.callbacks: list[Callable] = []

    def upsert(self, node_id: str, ip: str, tcp_port: int) -> bool:
        is_new = node_id not in self.peers
        self.peers[node_id] = PeerInfo(node_id, ip, tcp_port, time.time())

        if is_new:
            for cb in self.callbacks:
                cb("peer_joined", node_id, ip, tcp_port)
        return is_new

    def remove_stale_peers(self) -> None:
        stale = [nid for nid, p in self.peers.items() if not p.is_alive()]
        for nid in stale:
            del self.peers[nid]
            for cb in self.callbacks:
                cb("peer_left", nid)

    def get_peer(self, node_id: str) -> Optional[PeerInfo]:
        return self.peers.get(node_id)

    def get_all_peers(self) -> list[PeerInfo]:
        return list(self.peers.values())

    def on_change(self, callback: Callable) -> None:
        self.callbacks.append(callback)


class DiscoveryService:
    """Service de decouverte multicast."""

    def __init__(self, identity: NodeIdentity, tcp_port: int, peer_table: PeerTable):
        self.identity = identity
        self.tcp_port = tcp_port
        self.peer_table = peer_table
        self.config = Config()
        self.running = False
        self.sock: Optional[socket.socket] = None

    async def start(self) -> None:
        self.running = True

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("", self.config.MULTICAST_PORT))

        mreq = struct.pack(
            "4sL", socket.inet_aton(self.config.MULTICAST_ADDR), socket.INADDR_ANY
        )
        self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        self.sock.setblocking(False)

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

                await asyncio.sleep(self.config.HELLO_INTERVAL)
            except Exception as e:
                print(f"Erreur envoi HELLO: {e}")
                await asyncio.sleep(5)

    async def _receive_loop(self) -> None:
        loop = asyncio.get_event_loop()

        while self.running:
            try:
                data, addr = await loop.sock_recvfrom(self.sock, 2048)
                await self._handle_packet(data, addr[0])
            except Exception:
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
                is_new = self.peer_table.upsert(node_id_hex, sender_ip, tcp_port)

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
            writer.write(packet)
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
