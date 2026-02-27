"""Serveur TCP pour les connexions P2P."""
import asyncio
import struct
from dataclasses import dataclass
from typing import Callable, Dict, Optional

from src.config import PacketType
from src.crypto.handshake import HandshakeProtocol
from src.crypto.identity import NodeIdentity
from src.network.packet import ArchipelPacket, PacketBuilder


@dataclass
class PeerConnection:
    node_id: Optional[str]
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    session: Optional[object] = None
    handshake_complete: bool = False


class TCPServer:
    """Serveur TCP gerant les connexions P2P."""

    def __init__(self, identity: NodeIdentity, port: int, message_handler: Callable):
        self.identity = identity
        self.port = port
        self.message_handler = message_handler
        self.handshake = HandshakeProtocol(identity)
        self.connections: Dict[str, PeerConnection] = {}
        self.server: Optional[asyncio.Server] = None
        self.running = False

    async def start(self) -> None:
        self.server = await asyncio.start_server(self._handle_client, "0.0.0.0", self.port)
        self.running = True

        async with self.server:
            await self.server.serve_forever()

    async def _handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        addr = writer.get_extra_info("peername")
        conn = PeerConnection(None, reader, writer)

        try:
            while self.running:
                header = await reader.readexactly(ArchipelPacket.HEADER_SIZE)
                _, _, _, payload_len = struct.unpack(">4sB32sI", header)

                remaining = payload_len + 32
                data = await reader.readexactly(remaining)

                packet = ArchipelPacket.parse(header + data)
                if not packet:
                    continue

                await self._process_packet(packet, conn)

        except asyncio.IncompleteReadError:
            pass
        except Exception as e:
            print(f"Erreur connexion {addr}: {e}")
        finally:
            writer.close()
            await writer.wait_closed()
            if conn.node_id and conn.node_id in self.connections:
                del self.connections[conn.node_id]

    async def _process_packet(self, packet: ArchipelPacket, conn: PeerConnection) -> None:
        if packet.pkt_type == PacketType.HANDSHAKE_HELLO:
            reply, _, session = self.handshake.respond_to_handshake(packet.payload)
            conn.session = session
            conn.writer.write(reply)
            await conn.writer.drain()

        elif packet.pkt_type == PacketType.AUTH:
            conn.handshake_complete = True
            conn.node_id = packet.node_id.hex()
            self.connections[conn.node_id] = conn

            ack = PacketBuilder.build(PacketType.AUTH_OK, self.identity.node_id, b"OK")
            conn.writer.write(ack)
            await conn.writer.drain()

        elif packet.pkt_type == PacketType.MSG and conn.handshake_complete:
            plaintext = PacketBuilder.decrypt_payload(conn.session, packet.payload)
            if plaintext:
                await self.message_handler(conn.node_id, plaintext)

        elif packet.pkt_type == PacketType.CHUNK_REQ:
            return

    async def connect_to_peer(self, ip: str, port: int, node_id: str) -> bool:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=10.0
            )

            hello_packet, e_private = self.handshake.initiate_handshake()
            writer.write(hello_packet)
            await writer.drain()

            header = await reader.readexactly(ArchipelPacket.HEADER_SIZE)
            _, _, _, payload_len = struct.unpack(">4sB32sI", header)
            data = await reader.readexactly(payload_len + 32)

            reply_packet = ArchipelPacket.parse(header + data)
            if not reply_packet or reply_packet.pkt_type != PacketType.HANDSHAKE_REPLY:
                return False

            session = self.handshake.complete_handshake(
                reply_packet.payload, e_private, bytes.fromhex(node_id)
            )
            if not session:
                return False

            auth = PacketBuilder.build(
                PacketType.AUTH,
                self.identity.node_id,
                self.identity.sign(b"AUTH"),
                self.identity.node_id,
            )
            writer.write(auth)
            await writer.drain()

            header = await reader.readexactly(ArchipelPacket.HEADER_SIZE)
            _, _, _, payload_len = struct.unpack(">4sB32sI", header)
            await reader.readexactly(payload_len + 32)

            conn = PeerConnection(node_id, reader, writer, session, True)
            self.connections[node_id] = conn
            asyncio.create_task(self._read_loop(conn))
            return True

        except Exception as e:
            print(f"Echec connexion a {ip}:{port}: {e}")
            return False

    async def _read_loop(self, conn: PeerConnection) -> None:
        try:
            while self.running and conn.handshake_complete:
                header = await conn.reader.readexactly(ArchipelPacket.HEADER_SIZE)
                _, _, _, payload_len = struct.unpack(">4sB32sI", header)
                data = await conn.reader.readexactly(payload_len + 32)

                packet = ArchipelPacket.parse(header + data)
                if packet:
                    await self._process_packet(packet, conn)
        except Exception:
            return
        finally:
            if conn.node_id in self.connections:
                del self.connections[conn.node_id]

    async def send_message(self, node_id: str, message: bytes) -> bool:
        conn = self.connections.get(node_id)
        if not conn or not conn.session:
            return False

        try:
            packet = PacketBuilder.build_encrypted(
                conn.session, PacketType.MSG, self.identity.node_id, message
            )
            conn.writer.write(packet)
            await conn.writer.drain()
            return True
        except Exception:
            return False

    def stop(self) -> None:
        self.running = False
        for conn in self.connections.values():
            conn.writer.close()
