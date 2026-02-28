"""Serveur TCP pour les connexions P2P."""
import asyncio
import json
import struct
import time
from dataclasses import dataclass
from typing import Callable, Dict, Optional

from src.config import Config, PacketType
from src.crypto.handshake import HandshakeProtocol
from src.crypto.identity import NodeIdentity
from src.crypto.tofu import TrustStore
from src.network.discovery import PeerTable
from src.network.packet import ArchipelPacket, PacketBuilder


@dataclass
class PeerConnection:
    node_id: Optional[str]
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    session: Optional[object] = None
    handshake_complete: bool = False
    last_ping_sent: float = 0.0
    last_pong_recv: float = 0.0
    keepalive_task: Optional[asyncio.Task] = None


class TCPServer:
    """Serveur TCP gerant les connexions P2P."""

    def __init__(
        self,
        identity: NodeIdentity,
        port: int,
        message_handler: Callable,
        peer_table: Optional[PeerTable] = None,
        trust_store: Optional[TrustStore] = None,
    ):
        self.identity = identity
        self.port = port
        self.message_handler = message_handler
        self.peer_table = peer_table
        self.trust_store = trust_store
        self.config = Config()
        self.handshake = HandshakeProtocol(identity)
        self.connections: Dict[str, PeerConnection] = {}
        self._client_slots = asyncio.Semaphore(self.config.MAX_CONNECTIONS)
        self.server: Optional[asyncio.Server] = None
        self.running = False

    async def start(self) -> None:
        self.server = await asyncio.start_server(
            self._handle_client,
            "0.0.0.0",
            self.port,
            backlog=max(self.config.MAX_CONNECTIONS, self.config.MIN_PARALLEL_CONNECTIONS),
        )
        self.running = True

        async with self.server:
            await self.server.serve_forever()

    async def _handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        async with self._client_slots:
            addr = writer.get_extra_info("peername")
            conn = PeerConnection(None, reader, writer, last_pong_recv=time.time())

            try:
                while self.running:
                    tlv_type, value = await self._read_tlv(reader)
                    if tlv_type is None or value is None:
                        break

                    if tlv_type == PacketType.PEER_LIST:
                        await self._process_peer_list_tlv(value)
                        continue

                    packet = ArchipelPacket.parse(value)
                    if packet:
                        await self._process_packet(packet, conn)

            except asyncio.IncompleteReadError:
                pass
            except Exception as e:
                print(f"Erreur connexion {addr}: {e}")
            finally:
                if conn.keepalive_task:
                    conn.keepalive_task.cancel()
                writer.close()
                await writer.wait_closed()
                if conn.node_id and conn.node_id in self.connections:
                    del self.connections[conn.node_id]

    async def _process_packet(self, packet: ArchipelPacket, conn: PeerConnection) -> None:
        if packet.pkt_type == PacketType.HANDSHAKE_HELLO:
            reply, _, session = self.handshake.respond_to_handshake(packet.payload)
            conn.session = session
            conn.writer.write(self._tlv_pack(PacketType.HANDSHAKE_REPLY, reply))
            await conn.writer.drain()

        elif packet.pkt_type == PacketType.AUTH:
            if conn.session is None:
                conn.writer.close()
                return
            if not self.identity.verify(b"AUTH", packet.payload, packet.node_id):
                conn.writer.close()
                return
            conn.handshake_complete = True
            conn.node_id = packet.node_id.hex()
            conn.last_pong_recv = time.time()
            self.connections[conn.node_id] = conn

            ack = PacketBuilder.build(
                PacketType.AUTH_OK,
                self.identity.node_id,
                b"OK",
                signing_key=conn.session.session_key,
            )
            conn.writer.write(self._tlv_pack(PacketType.AUTH_OK, ack))
            await conn.writer.drain()
            if not conn.keepalive_task:
                conn.keepalive_task = asyncio.create_task(self._keepalive_loop(conn))

        elif packet.pkt_type == PacketType.MSG and conn.handshake_complete:
            if conn.session is None or not PacketBuilder.verify_signature(
                packet, conn.session.session_key
            ):
                conn.writer.close()
                return
            plaintext = PacketBuilder.decrypt_payload(conn.session, packet.payload)
            if plaintext:
                await self.message_handler(conn.node_id, plaintext)

        elif packet.pkt_type == PacketType.PING and conn.handshake_complete:
            if conn.session is None or not PacketBuilder.verify_signature(
                packet, conn.session.session_key
            ):
                conn.writer.close()
                return
            pong = PacketBuilder.build(
                PacketType.PONG,
                self.identity.node_id,
                b"PONG",
                signing_key=conn.session.session_key,
            )
            conn.writer.write(self._tlv_pack(PacketType.PONG, pong))
            await conn.writer.drain()

        elif packet.pkt_type == PacketType.PONG and conn.handshake_complete:
            if conn.session is None or not PacketBuilder.verify_signature(
                packet, conn.session.session_key
            ):
                conn.writer.close()
                return
            conn.last_pong_recv = time.time()

        elif packet.pkt_type == PacketType.CHUNK_REQ:
            return

    async def connect_to_peer(self, ip: str, port: int, node_id: str) -> bool:
        try:
            if self.trust_store:
                endpoint = f"{ip}:{port}"
                if not self.trust_store.trust_endpoint(endpoint, node_id):
                    known = self.trust_store.get_node_id(endpoint)
                    print(
                        f"[TOFU] reject endpoint={endpoint} "
                        f"known={known[:12] if known else 'unknown'} seen={node_id[:12]}"
                    )
                    return False

            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=10.0
            )

            hello_packet, e_private = self.handshake.initiate_handshake()
            writer.write(self._tlv_pack(PacketType.HANDSHAKE_HELLO, hello_packet))
            await writer.drain()

            tlv_type, value = await self._read_tlv(reader)
            if tlv_type != PacketType.HANDSHAKE_REPLY or value is None:
                return False
            reply_packet = ArchipelPacket.parse(value)
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
            )
            writer.write(self._tlv_pack(PacketType.AUTH, auth))
            await writer.drain()

            tlv_type, value = await self._read_tlv(reader)
            if tlv_type != PacketType.AUTH_OK or value is None:
                return False
            auth_ok = ArchipelPacket.parse(value)
            if not auth_ok or auth_ok.pkt_type != PacketType.AUTH_OK:
                return False
            if not PacketBuilder.verify_signature(auth_ok, session.session_key):
                return False

            conn = PeerConnection(
                node_id=node_id,
                reader=reader,
                writer=writer,
                session=session,
                handshake_complete=True,
                last_pong_recv=time.time(),
            )
            self.connections[node_id] = conn
            conn.keepalive_task = asyncio.create_task(self._keepalive_loop(conn))
            asyncio.create_task(self._read_loop(conn))
            return True

        except Exception as e:
            print(f"Echec connexion a {ip}:{port}: {e}")
            return False

    async def _read_loop(self, conn: PeerConnection) -> None:
        try:
            while self.running and conn.handshake_complete:
                tlv_type, value = await self._read_tlv(conn.reader)
                if tlv_type is None or value is None:
                    break

                if tlv_type == PacketType.PEER_LIST:
                    await self._process_peer_list_tlv(value)
                    continue

                packet = ArchipelPacket.parse(value)
                if packet:
                    await self._process_packet(packet, conn)
        except Exception:
            return
        finally:
            if conn.keepalive_task:
                conn.keepalive_task.cancel()
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
            conn.writer.write(self._tlv_pack(PacketType.MSG, packet))
            await conn.writer.drain()
            return True
        except Exception:
            return False

    async def _keepalive_loop(self, conn: PeerConnection) -> None:
        while self.running and conn.handshake_complete:
            await asyncio.sleep(self.config.KEEPALIVE_INTERVAL)
            if not conn.handshake_complete:
                break
            if conn.session is None:
                conn.writer.close()
                return

            if (time.time() - conn.last_pong_recv) > self.config.KEEPALIVE_TIMEOUT:
                conn.writer.close()
                return

            ping = PacketBuilder.build(
                PacketType.PING,
                self.identity.node_id,
                b"PING",
                signing_key=conn.session.session_key,
            )
            conn.last_ping_sent = time.time()
            conn.writer.write(self._tlv_pack(PacketType.PING, ping))
            await conn.writer.drain()

    async def _process_peer_list_tlv(self, value: bytes) -> None:
        packet = ArchipelPacket.parse(value)
        if not packet or packet.pkt_type != PacketType.PEER_LIST or not self.peer_table:
            return

        try:
            peers_data = json.loads(packet.payload)
            if isinstance(peers_data, list):
                self.peer_table.merge_peer_list(peers_data)
        except json.JSONDecodeError:
            return

    @staticmethod
    def _tlv_pack(tlv_type: int, value: bytes) -> bytes:
        return struct.pack(">BI", tlv_type, len(value)) + value

    @staticmethod
    async def _read_tlv(
        reader: asyncio.StreamReader,
    ) -> tuple[Optional[int], Optional[bytes]]:
        header = await reader.readexactly(5)
        tlv_type, length = struct.unpack(">BI", header)
        value = await reader.readexactly(length)
        return tlv_type, value

    def stop(self) -> None:
        self.running = False
        for conn in list(self.connections.values()):
            if conn.keepalive_task:
                conn.keepalive_task.cancel()
            conn.writer.close()
