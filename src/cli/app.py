"""Sprint 4 interactive CLI for Archipel."""
from __future__ import annotations

import argparse
import asyncio
import shlex
import signal
from contextlib import suppress
from pathlib import Path
from typing import Optional

from src.ai.gemini import GeminiClient, GeminiConfig
from src.config import Config
from src.crypto.identity import NodeIdentity
from src.crypto.tofu import TrustStore
from src.network.discovery import DiscoveryService, PeerTable
from src.network.tcp_server import TCPServer
from src.transfer.index import TransferIndex
from src.transfer.manager import TransferManager


class ArchipelCliApp:
    def __init__(self, port: int, ai_enabled: bool, api_key: str):
        Config.load_env()
        self.port = port
        self.identity = NodeIdentity(Config.KEYS_DIR / f"node_{port}.key")
        self.trust_store = TrustStore()
        self.peer_table = PeerTable(self_node_id=self.identity.node_id_hex)
        self.peer_table.on_change(self._print_peer_event)
        self.transfer_index = TransferIndex()
        self.history: list[str] = []

        self.gemini = GeminiClient(
            GeminiConfig(enabled=ai_enabled, api_key=api_key)
        )

        self.transfer: Optional[TransferManager] = None

        async def packet_handler(node_id: str, pkt_type: int, payload: bytes) -> None:
            if self.transfer:
                await self.transfer.handle_packet(node_id, pkt_type, payload)

        self.tcp = TCPServer(
            self.identity,
            port,
            self._message_handler,
            peer_table=self.peer_table,
            trust_store=self.trust_store,
            packet_handler=packet_handler,
        )
        self.transfer = TransferManager(
            self.identity,
            self.tcp,
            self.peer_table,
            index=self.transfer_index,
        )
        self.discovery = DiscoveryService(
            self.identity,
            port,
            self.peer_table,
            trust_store=self.trust_store,
        )

        self._tasks: list[asyncio.Task] = []
        self._stop = asyncio.Event()

    async def start(self) -> None:
        self._tasks.append(asyncio.create_task(self.tcp.start()))
        self._tasks.append(asyncio.create_task(self.discovery.start()))
        self._tasks.append(
            asyncio.create_task(self._autoconnect_loop(self.identity.node_id_hex))
        )
        self._tasks.append(asyncio.create_task(self.transfer.announce_loop()))
        self._tasks.append(asyncio.create_task(self._command_loop()))

        loop = asyncio.get_running_loop()
        with suppress(NotImplementedError):
            loop.add_signal_handler(signal.SIGINT, self._stop.set)
            loop.add_signal_handler(signal.SIGTERM, self._stop.set)

        print(
            f"[CLI] started node_id={self.identity.node_id_hex[:12]} port={self.port} "
            "(type 'help')"
        )

        await self._stop.wait()
        self.discovery.stop()
        self.tcp.stop()

        for task in self._tasks:
            task.cancel()
            with suppress(asyncio.CancelledError):
                await task

    async def _command_loop(self) -> None:
        while not self._stop.is_set():
            raw = await asyncio.to_thread(input, "archipel> ")
            line = raw.strip()
            if not line:
                continue
            self.history.append(f"user: {line}")

            if line in {"quit", "exit"}:
                self._stop.set()
                return
            if line == "help":
                self._print_help()
                continue
            if line == "peers":
                self._cmd_peers()
                continue
            if line == "status":
                self._cmd_status()
                continue
            if line == "receive":
                self._cmd_receive()
                continue
            if line.startswith("trust"):
                self._cmd_trust(line)
                continue
            if line.startswith("msg "):
                await self._cmd_msg(line)
                continue
            if line.startswith("send "):
                await self._cmd_send(line)
                continue
            if line.startswith("download "):
                await self._cmd_download(line)
                continue
            if line.startswith("/ask ") or line.startswith("@archipel-ai "):
                await self._cmd_ai(line)
                continue

            print("[CLI] commande inconnue. tape 'help'.")

    async def _message_handler(self, node_id: str, payload: bytes) -> None:
        text = payload.decode("utf-8", errors="replace")
        self.history.append(f"peer:{node_id[:12]} {text}")
        print(f"\n[MSG] {node_id[:12]}: {text}")

    def _print_peer_event(self, event: str, *args) -> None:
        if event == "peer_joined":
            node_id, ip, port = args
            print(f"\n[PEER] joined node={node_id[:12]} ip={ip}:{port}")
        elif event == "peer_left":
            (node_id,) = args
            print(f"\n[PEER] left node={node_id[:12]}")

    async def _autoconnect_loop(self, self_node_id: str, interval: int = 5) -> None:
        retry_after: dict[str, float] = {}
        while not self._stop.is_set():
            await asyncio.sleep(interval)
            now = asyncio.get_running_loop().time()
            for peer in self.peer_table.get_all_peers():
                if peer.node_id == self_node_id:
                    continue
                if peer.node_id in self.tcp.connections:
                    continue
                if now < retry_after.get(peer.node_id, 0):
                    continue

                ok = await self.tcp.connect_to_peer(peer.ip, peer.tcp_port, peer.node_id)
                if ok:
                    print(f"\n[TCP] secure session established node={peer.node_id[:12]}")
                else:
                    retry_after[peer.node_id] = now + 10

    def _cmd_peers(self) -> None:
        peers = self.peer_table.get_all_peers()
        print(f"[PEERS] count={len(peers)}")
        for p in peers:
            is_connected = p.node_id in self.tcp.connections
            print(
                f"- node={p.node_id[:12]} ip={p.ip}:{p.tcp_port} "
                f"connected={is_connected}"
            )

    def _cmd_status(self) -> None:
        print(f"[STATUS] node_id={self.identity.node_id_hex}")
        print(f"[STATUS] tcp_port={self.port}")
        print(f"[STATUS] connected={len(self.tcp.connections)}")
        print(f"[STATUS] manifests={len(self.transfer_index.list_manifests())}")

    def _cmd_receive(self) -> None:
        manifests = self.transfer_index.list_manifests()
        print(f"[FILES] count={len(manifests)}")
        for m in manifests:
            print(
                f"- file_id={str(m.get('file_id', ''))[:12]} "
                f"name={m.get('filename', '?')} chunks={m.get('nb_chunks', '?')}"
            )

    def _cmd_trust(self, line: str) -> None:
        parts = shlex.split(line)
        if len(parts) == 1:
            entries = self.trust_store.all_entries()
            print(f"[TRUST] endpoints={len(entries)}")
            for endpoint, meta in entries.items():
                print(f"- {endpoint} -> {str(meta.get('node_id', ''))[:12]}")
            return

        target = parts[1]
        node_id = self._resolve_node_id(target)
        if not node_id:
            print("[TRUST] node introuvable")
            return

        entries = self.trust_store.entries_for_node(node_id)
        print(f"[TRUST] node={node_id[:12]} endpoints={len(entries)}")
        for endpoint, _ in entries:
            print(f"- {endpoint}")

    async def _cmd_msg(self, line: str) -> None:
        parts = shlex.split(line)
        if len(parts) < 3:
            print("usage: msg <node_id> <text>")
            return

        node_id = self._resolve_node_id(parts[1])
        if not node_id:
            print("[MSG] node introuvable")
            return

        text = " ".join(parts[2:])
        ok = await self.tcp.send_message(node_id, text.encode("utf-8"))
        if ok:
            print("[MSG] envoye")
        else:
            print("[MSG] echec envoi")

    async def _cmd_send(self, line: str) -> None:
        parts = shlex.split(line)
        if len(parts) == 2:
            file_path = Path(parts[1])
        elif len(parts) >= 3:
            # format de demo: send <node_id> <filepath>
            file_path = Path(parts[2])
        else:
            print("usage: send <filepath> | send <node_id> <filepath>")
            return

        file_id = await self.transfer.publish_file(file_path)
        if not file_id:
            print("[TRANSFER] partage impossible")
            return
        print(f"[TRANSFER] shared file_id={file_id}")

    async def _cmd_download(self, line: str) -> None:
        parts = shlex.split(line)
        if len(parts) < 2:
            print("usage: download <file_id> [output]")
            return

        file_id = parts[1]
        output = Path(parts[2]) if len(parts) > 2 else Path.cwd() / f"{file_id}.bin"
        ok = await self.transfer.download_file(file_id, output)
        if ok:
            print(f"[TRANSFER] download complete output={output}")
        else:
            print("[TRANSFER] download failed")

    async def _cmd_ai(self, line: str) -> None:
        query = line.split(" ", 1)[1].strip()
        if not query:
            print("[AI] question vide")
            return

        answer = await self.gemini.query(self.history, query)
        self.history.append(f"ai: {answer}")
        print(f"[AI] {answer}")

    def _resolve_node_id(self, prefix_or_id: str) -> Optional[str]:
        if len(prefix_or_id) == 64:
            return prefix_or_id

        candidates = []
        for p in self.peer_table.get_all_peers():
            if p.node_id.startswith(prefix_or_id):
                candidates.append(p.node_id)
        for c in self.tcp.connections.keys():
            if c.startswith(prefix_or_id) and c not in candidates:
                candidates.append(c)

        if len(candidates) == 1:
            return candidates[0]
        return None

    @staticmethod
    def _print_help() -> None:
        print("commands:")
        print("- peers")
        print("- msg <node_id> <text>")
        print("- send <filepath> | send <node_id> <filepath>")
        print("- receive")
        print("- download <file_id> [output]")
        print("- status")
        print("- trust [node_id]")
        print("- /ask <question>  (ou @archipel-ai <question>)")
        print("- exit")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Archipel CLI (Sprint 4)")
    sub = parser.add_subparsers(dest="command", required=True)

    start = sub.add_parser("start", help="Demarrer un noeud CLI interactif")
    start.add_argument("--port", type=int, default=Config.DEFAULT_TCP_PORT)
    start.add_argument("--no-ai", action="store_true", help="Desactiver Gemini")
    start.add_argument("--gemini-api-key", type=str, default="")

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "start":
        app = ArchipelCliApp(
            port=args.port,
            ai_enabled=not args.no_ai,
            api_key=args.gemini_api_key,
        )
        asyncio.run(app.start())


if __name__ == "__main__":
    main()
