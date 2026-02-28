"""Trust On First Use (TOFU) store for Archipel peers."""
import json
import time
from pathlib import Path
from typing import Dict, Optional

from src.config import Config


class TrustStore:
    """Persists first-seen identity for an endpoint and rejects identity drift."""

    def __init__(self, storage_path: Optional[Path] = None):
        self.config = Config()
        self.config.init_dirs()
        self.storage_path = storage_path or self.config.TRUST_DB
        self._store: Dict[str, dict] = {}
        self._load()

    def trust_endpoint(self, endpoint: str, node_id: str) -> bool:
        now = time.time()
        current = self._store.get(endpoint)

        if current is None:
            self._store[endpoint] = {
                "node_id": node_id,
                "first_seen": now,
                "last_seen": now,
            }
            self._save()
            return True

        if current.get("node_id") != node_id:
            return False

        current["last_seen"] = now
        self._save()
        return True

    def get_node_id(self, endpoint: str) -> Optional[str]:
        item = self._store.get(endpoint)
        if not item:
            return None
        return str(item.get("node_id"))

    def all_entries(self) -> dict[str, dict]:
        return {k: dict(v) for k, v in self._store.items()}

    def entries_for_node(self, node_id: str) -> list[tuple[str, dict]]:
        out: list[tuple[str, dict]] = []
        for endpoint, meta in self._store.items():
            if str(meta.get("node_id")) == node_id:
                out.append((endpoint, dict(meta)))
        return out

    def _load(self) -> None:
        if not self.storage_path.exists():
            return
        try:
            raw = json.loads(self.storage_path.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                self._store = raw
        except Exception:
            self._store = {}

    def _save(self) -> None:
        self.storage_path.write_text(
            json.dumps(self._store, indent=2, sort_keys=True),
            encoding="utf-8",
        )
