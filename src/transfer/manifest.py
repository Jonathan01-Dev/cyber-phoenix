"""File manifest and chunk utilities for Sprint 3."""
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from src.crypto.identity import NodeIdentity


@dataclass
class FileManifest:
    file_id: str
    filename: str
    size: int
    chunk_size: int
    nb_chunks: int
    chunks: list[dict[str, Any]]
    sender_id: str
    signature: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "file_id": self.file_id,
            "filename": self.filename,
            "size": self.size,
            "chunk_size": self.chunk_size,
            "nb_chunks": self.nb_chunks,
            "chunks": self.chunks,
            "sender_id": self.sender_id,
            "signature": self.signature,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "FileManifest":
        return cls(
            file_id=str(data["file_id"]),
            filename=str(data["filename"]),
            size=int(data["size"]),
            chunk_size=int(data["chunk_size"]),
            nb_chunks=int(data["nb_chunks"]),
            chunks=list(data["chunks"]),
            sender_id=str(data["sender_id"]),
            signature=str(data["signature"]),
        )


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def compute_manifest_and_store_chunks(
    file_path: Path,
    chunk_size: int,
    chunks_root: Path,
    identity: NodeIdentity,
) -> FileManifest:
    file_bytes = file_path.read_bytes()
    file_id = _sha256(file_bytes)
    chunk_dir = chunks_root / file_id
    chunk_dir.mkdir(parents=True, exist_ok=True)

    chunks: list[dict[str, Any]] = []
    offset = 0
    index = 0
    while offset < len(file_bytes):
        block = file_bytes[offset : offset + chunk_size]
        chunk_hash = _sha256(block)
        (chunk_dir / f"{index:08d}.chk").write_bytes(block)
        chunks.append({"index": index, "hash": chunk_hash, "size": len(block)})
        offset += chunk_size
        index += 1

    unsigned = {
        "file_id": file_id,
        "filename": file_path.name,
        "size": len(file_bytes),
        "chunk_size": chunk_size,
        "nb_chunks": len(chunks),
        "chunks": chunks,
        "sender_id": identity.node_id_hex,
    }
    signature = identity.sign(manifest_signing_payload(unsigned)).hex()
    return FileManifest(**unsigned, signature=signature)


def manifest_signing_payload(manifest_data: dict[str, Any]) -> bytes:
    canonical = json.dumps(manifest_data, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).digest()


def verify_manifest_signature(manifest: FileManifest, identity: NodeIdentity) -> bool:
    unsigned = manifest.as_dict().copy()
    unsigned.pop("signature", None)
    try:
        pub = bytes.fromhex(manifest.sender_id)
        sig = bytes.fromhex(manifest.signature)
    except ValueError:
        return False

    return identity.verify(manifest_signing_payload(unsigned), sig, pub)


def chunk_file_path(chunks_root: Path, file_id: str, chunk_idx: int) -> Path:
    return chunks_root / file_id / f"{chunk_idx:08d}.chk"


def expected_chunk_hash(manifest: FileManifest, chunk_idx: int) -> Optional[str]:
    for item in manifest.chunks:
        if int(item.get("index", -1)) == chunk_idx:
            return str(item.get("hash"))
    return None
