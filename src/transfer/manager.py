"""Chunk transfer manager for Sprint 3."""
import asyncio
import base64
import hashlib
import json
from pathlib import Path
from typing import Optional

from src.config import Config, PacketType
from src.crypto.identity import NodeIdentity
from src.network.discovery import PeerTable
from src.network.tcp_server import TCPServer
from src.transfer.index import TransferIndex
from src.transfer.manifest import (
    FileManifest,
    chunk_file_path,
    compute_manifest_and_store_chunks,
    expected_chunk_hash,
    verify_manifest_signature,
)


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class TransferManager:
    def __init__(
        self,
        identity: NodeIdentity,
        tcp: TCPServer,
        peer_table: PeerTable,
        index: Optional[TransferIndex] = None,
    ):
        self.identity = identity
        self.tcp = tcp
        self.peer_table = peer_table
        self.config = Config()
        self.index = index or TransferIndex()
        self._pending_chunks: dict[tuple[str, int], asyncio.Future[bytes]] = {}

    async def publish_file(self, file_path: Path) -> Optional[str]:
        if not file_path.exists() or not file_path.is_file():
            return None

        manifest = compute_manifest_and_store_chunks(
            file_path=file_path,
            chunk_size=self.config.CHUNK_SIZE,
            chunks_root=self.config.CHUNKS_DIR,
            identity=self.identity,
        )
        self.index.put_manifest(manifest.as_dict())

        for chunk in manifest.chunks:
            self.index.register_owner(manifest.file_id, int(chunk["index"]), self.identity.node_id_hex)

        payload = json.dumps(manifest.as_dict()).encode("utf-8")
        await self._broadcast(PacketType.MANIFEST, payload)
        return manifest.file_id

    async def announce_loop(self, interval: int = 20) -> None:
        while True:
            await asyncio.sleep(interval)
            for manifest in self.index.list_manifests():
                payload = json.dumps(manifest).encode("utf-8")
                await self._broadcast(PacketType.MANIFEST, payload)

    async def download_file(self, file_id: str, output_path: Path) -> bool:
        raw = self.index.get_manifest(file_id)
        if not raw:
            print(f"[TRANSFER] manifest unknown file_id={file_id[:12]}")
            return False

        manifest = FileManifest.from_dict(raw)
        missing = self._missing_chunks(manifest)
        if missing:
            workers = max(3, min(self.config.MIN_PARALLEL_CONNECTIONS, len(missing)))
            sem = asyncio.Semaphore(workers)
            tasks = [
                asyncio.create_task(self._fetch_chunk_with_retry(manifest, idx, sem))
                for idx in missing
            ]
            results = await asyncio.gather(*tasks)
            if not all(results):
                return False

        return self._assemble_file(manifest, output_path)

    async def handle_packet(self, node_id: str, pkt_type: int, payload: bytes) -> None:
        if pkt_type == PacketType.MANIFEST:
            await self._handle_manifest(node_id, payload)
        elif pkt_type == PacketType.CHUNK_REQ:
            await self._handle_chunk_req(node_id, payload)
        elif pkt_type == PacketType.CHUNK_DATA:
            await self._handle_chunk_data(node_id, payload)
        elif pkt_type == PacketType.ACK:
            await self._handle_ack(node_id, payload)

    async def _handle_manifest(self, node_id: str, payload: bytes) -> None:
        try:
            data = json.loads(payload)
            manifest = FileManifest.from_dict(data)
        except Exception:
            return

        if manifest.sender_id != node_id:
            return
        if not verify_manifest_signature(manifest, self.identity):
            return

        self.index.put_manifest(manifest.as_dict())
        for chunk in manifest.chunks:
            self.index.register_owner(manifest.file_id, int(chunk["index"]), node_id)

        print(
            f"[MANIFEST] file_id={manifest.file_id[:12]} chunks={manifest.nb_chunks} "
            f"from={node_id[:12]}"
        )

    async def _handle_chunk_req(self, node_id: str, payload: bytes) -> None:
        try:
            req = json.loads(payload)
            file_id = str(req["file_id"])
            chunk_idx = int(req["chunk_idx"])
            requester = str(req["requester"])
        except Exception:
            return

        if requester != node_id:
            return

        manifest_raw = self.index.get_manifest(file_id)
        if not manifest_raw:
            await self._send_ack(node_id, file_id, chunk_idx, 0x02)
            return

        cpath = chunk_file_path(self.config.CHUNKS_DIR, file_id, chunk_idx)
        if not cpath.exists():
            await self._send_ack(node_id, file_id, chunk_idx, 0x02)
            return

        chunk_data = cpath.read_bytes()
        chunk_hash = _sha256_hex(chunk_data)
        expected = expected_chunk_hash(FileManifest.from_dict(manifest_raw), chunk_idx)
        if not expected or expected != chunk_hash:
            await self._send_ack(node_id, file_id, chunk_idx, 0x01)
            return

        signature = self.identity.sign(bytes.fromhex(chunk_hash)).hex()
        pkt = {
            "file_id": file_id,
            "chunk_idx": chunk_idx,
            "chunk_hash": chunk_hash,
            "data": base64.b64encode(chunk_data).decode("ascii"),
            "signature": signature,
        }
        await self.tcp.send_encrypted_packet(
            node_id,
            PacketType.CHUNK_DATA,
            json.dumps(pkt).encode("utf-8"),
        )

    async def _handle_chunk_data(self, node_id: str, payload: bytes) -> None:
        try:
            data = json.loads(payload)
            file_id = str(data["file_id"])
            chunk_idx = int(data["chunk_idx"])
            chunk_hash = str(data["chunk_hash"])
            chunk_blob = base64.b64decode(data["data"])
            signature = bytes.fromhex(str(data["signature"]))
        except Exception:
            return

        if _sha256_hex(chunk_blob) != chunk_hash:
            await self._send_ack(node_id, file_id, chunk_idx, 0x01)
            return

        if not self.identity.verify(bytes.fromhex(chunk_hash), signature, bytes.fromhex(node_id)):
            await self._send_ack(node_id, file_id, chunk_idx, 0x01)
            return

        cpath = chunk_file_path(self.config.CHUNKS_DIR, file_id, chunk_idx)
        cpath.parent.mkdir(parents=True, exist_ok=True)
        cpath.write_bytes(chunk_blob)
        self.index.register_owner(file_id, chunk_idx, self.identity.node_id_hex)
        self.index.register_owner(file_id, chunk_idx, node_id)

        fut = self._pending_chunks.get((file_id, chunk_idx))
        if fut and not fut.done():
            fut.set_result(chunk_blob)

        await self._send_ack(node_id, file_id, chunk_idx, 0x00)

    async def _handle_ack(self, node_id: str, payload: bytes) -> None:
        try:
            data = json.loads(payload)
            status = int(data.get("status", 0x00))
            chunk_idx = int(data.get("chunk_idx", -1))
            file_id = str(data.get("file_id", ""))
        except Exception:
            return
        if status != 0x00:
            print(
                f"[ACK] from={node_id[:12]} file_id={file_id[:12]} "
                f"chunk={chunk_idx} status=0x{status:02x}"
            )

    async def _send_ack(self, node_id: str, file_id: str, chunk_idx: int, status: int) -> None:
        payload = json.dumps(
            {
                "file_id": file_id,
                "chunk_idx": chunk_idx,
                "status": status,
            }
        ).encode("utf-8")
        await self.tcp.send_encrypted_packet(node_id, PacketType.ACK, payload)

    async def _broadcast(self, pkt_type: int, payload: bytes) -> None:
        for peer_id in list(self.tcp.connections.keys()):
            await self.tcp.send_encrypted_packet(peer_id, pkt_type, payload)

    def _missing_chunks(self, manifest: FileManifest) -> list[int]:
        missing: list[int] = []
        for chunk in manifest.chunks:
            idx = int(chunk["index"])
            cpath = chunk_file_path(self.config.CHUNKS_DIR, manifest.file_id, idx)
            if not cpath.exists():
                missing.append(idx)
        return missing

    async def _fetch_chunk_with_retry(
        self,
        manifest: FileManifest,
        chunk_idx: int,
        sem: asyncio.Semaphore,
        attempts: int = 4,
    ) -> bool:
        async with sem:
            providers = self._providers_for_chunk(manifest.file_id, chunk_idx)
            if not providers:
                return False

            for attempt in range(attempts):
                provider = providers[attempt % len(providers)]
                fut: asyncio.Future[bytes] = asyncio.get_running_loop().create_future()
                self._pending_chunks[(manifest.file_id, chunk_idx)] = fut

                req = {
                    "file_id": manifest.file_id,
                    "chunk_idx": chunk_idx,
                    "requester": self.identity.node_id_hex,
                }
                ok = await self.tcp.send_encrypted_packet(
                    provider,
                    PacketType.CHUNK_REQ,
                    json.dumps(req).encode("utf-8"),
                )
                if not ok:
                    await asyncio.sleep(0.5)
                    continue

                try:
                    await asyncio.wait_for(fut, timeout=8.0)
                    return True
                except asyncio.TimeoutError:
                    continue
                finally:
                    self._pending_chunks.pop((manifest.file_id, chunk_idx), None)

            return False

    def _providers_for_chunk(self, file_id: str, chunk_idx: int) -> list[str]:
        owners = [n for n in self.index.get_owners(file_id, chunk_idx) if n != self.identity.node_id_hex]
        connected = set(self.tcp.connections.keys())
        providers = [n for n in owners if n in connected]
        if providers:
            return providers

        # fallback: any connected peer may still have the chunk
        return [n for n in connected if n != self.identity.node_id_hex]

    def _assemble_file(self, manifest: FileManifest, output_path: Path) -> bool:
        chunks: list[bytes] = []
        for chunk in manifest.chunks:
            idx = int(chunk["index"])
            cpath = chunk_file_path(self.config.CHUNKS_DIR, manifest.file_id, idx)
            if not cpath.exists():
                return False
            blob = cpath.read_bytes()
            if _sha256_hex(blob) != str(chunk["hash"]):
                return False
            chunks.append(blob)

        full = b"".join(chunks)
        if _sha256_hex(full) != manifest.file_id:
            return False

        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_bytes(full)
        return True
