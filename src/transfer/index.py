"""Lightweight local index for manifests and chunk ownership."""
import json
from pathlib import Path
from typing import Any, Optional

from src.config import Config


class TransferIndex:
    def __init__(self, storage_path: Optional[Path] = None):
        self.config = Config()
        self.config.init_dirs()
        self.storage_path = storage_path or self.config.INDEX_DB
        self._data: dict[str, Any] = {
            "manifests": {},
            "owners": {},
        }
        self._load()

    def put_manifest(self, manifest: dict[str, Any]) -> None:
        file_id = str(manifest["file_id"])
        self._data["manifests"][file_id] = manifest
        self._data["owners"].setdefault(file_id, {})
        self._save()

    def get_manifest(self, file_id: str) -> Optional[dict[str, Any]]:
        raw = self._data["manifests"].get(file_id)
        if raw is None:
            return None
        return dict(raw)

    def list_manifests(self) -> list[dict[str, Any]]:
        return [dict(v) for v in self._data["manifests"].values()]

    def register_owner(self, file_id: str, chunk_idx: int, node_id: str) -> None:
        owner_map = self._data["owners"].setdefault(file_id, {})
        chunk_key = str(chunk_idx)
        owners = set(owner_map.get(chunk_key, []))
        owners.add(node_id)
        owner_map[chunk_key] = sorted(owners)
        self._save()

    def get_owners(self, file_id: str, chunk_idx: int) -> list[str]:
        owner_map = self._data["owners"].get(file_id, {})
        return list(owner_map.get(str(chunk_idx), []))

    def _load(self) -> None:
        if not self.storage_path.exists():
            return
        try:
            raw = json.loads(self.storage_path.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                self._data.update(raw)
        except Exception:
            self._data = {"manifests": {}, "owners": {}}

    def _save(self) -> None:
        self.storage_path.write_text(
            json.dumps(self._data, indent=2, sort_keys=True),
            encoding="utf-8",
        )
