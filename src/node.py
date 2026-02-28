"""Entrypoint de noeud Archipel pour Sprint 1."""
import argparse
import asyncio
import signal
from contextlib import suppress
from pathlib import Path

from src.config import Config
from src.crypto.identity import NodeIdentity
from src.crypto.tofu import TrustStore
from src.network.discovery import DiscoveryService, PeerTable
from src.network.tcp_server import TCPServer
from src.transfer.index import TransferIndex
from src.transfer.manager import TransferManager


async def _message_handler(node_id: str, payload: bytes) -> None:
    print(f"[MSG] from={node_id[:12]} bytes={len(payload)}")


def _print_peer_event(event: str, *args) -> None:
    if event == "peer_joined":
        node_id, ip, port = args
        print(f"[PEER] joined node={node_id[:12]} ip={ip}:{port}")
    elif event == "peer_left":
        (node_id,) = args
        print(f"[PEER] left node={node_id[:12]}")


async def _peer_table_reporter(peer_table: PeerTable, interval: int = 10) -> None:
    while True:
        await asyncio.sleep(interval)
        peers = peer_table.get_all_peers()
        print(f"[PEERS] count={len(peers)}")
        for peer in peers:
            print(
                f"- node={peer.node_id[:12]} ip={peer.ip}:{peer.tcp_port} "
                f"last_seen={int(peer.last_seen)} rep={peer.reputation:.2f}"
            )


async def _autoconnect_loop(
    tcp: TCPServer, peer_table: PeerTable, self_node_id: str, interval: int = 5
) -> None:
    retry_after: dict[str, float] = {}
    while True:
        await asyncio.sleep(interval)
        now = asyncio.get_running_loop().time()
        for peer in peer_table.get_all_peers():
            if peer.node_id == self_node_id:
                continue
            if peer.node_id in tcp.connections:
                continue
            if now < retry_after.get(peer.node_id, 0):
                continue

            ok = await tcp.connect_to_peer(peer.ip, peer.tcp_port, peer.node_id)
            if ok:
                print(f"[TCP] secure session established node={peer.node_id[:12]}")
            else:
                retry_after[peer.node_id] = now + 10


async def run_node(
    port: int,
    share_path: Path | None = None,
    download_file_id: str | None = None,
    output_path: Path | None = None,
) -> None:
    Config.load_env()
    identity = NodeIdentity(Config.KEYS_DIR / f"node_{port}.key")
    trust_store = TrustStore()
    peer_table = PeerTable(self_node_id=identity.node_id_hex)
    peer_table.on_change(_print_peer_event)
    transfer_index = TransferIndex()

    transfer: TransferManager | None = None

    async def _packet_handler(node_id: str, pkt_type: int, payload: bytes) -> None:
        if transfer:
            await transfer.handle_packet(node_id, pkt_type, payload)

    tcp = TCPServer(
        identity,
        port,
        _message_handler,
        peer_table=peer_table,
        trust_store=trust_store,
        packet_handler=_packet_handler,
    )
    transfer = TransferManager(identity, tcp, peer_table, index=transfer_index)
    discovery = DiscoveryService(identity, port, peer_table, trust_store=trust_store)

    tcp_task = asyncio.create_task(tcp.start())
    discovery_task = asyncio.create_task(discovery.start())
    reporter_task = asyncio.create_task(_peer_table_reporter(peer_table))
    autoconnect_task = asyncio.create_task(_autoconnect_loop(tcp, peer_table, identity.node_id_hex))
    manifest_task = asyncio.create_task(transfer.announce_loop())

    stop_event = asyncio.Event()

    def _shutdown() -> None:
        stop_event.set()

    loop = asyncio.get_running_loop()
    with suppress(NotImplementedError):
        loop.add_signal_handler(signal.SIGINT, _shutdown)
        loop.add_signal_handler(signal.SIGTERM, _shutdown)

    print(
        f"[NODE] started node_id={identity.node_id_hex[:12]} tcp_port={port} "
        f"multicast={Config.MULTICAST_ADDR}:{Config.MULTICAST_PORT}"
    )

    if share_path:
        await asyncio.sleep(3)
        file_id = await transfer.publish_file(share_path)
        if file_id:
            print(f"[TRANSFER] shared file={share_path.name} file_id={file_id}")
        else:
            print(f"[TRANSFER] cannot share file={share_path}")

    if download_file_id:
        await asyncio.sleep(5)
        destination = output_path or (Path.cwd() / f"{download_file_id}.bin")
        ok = await transfer.download_file(download_file_id, destination)
        if ok:
            print(f"[TRANSFER] download complete output={destination}")
        else:
            print(f"[TRANSFER] download failed file_id={download_file_id[:12]}")

    await stop_event.wait()

    discovery.stop()
    tcp.stop()
    for task in (manifest_task, autoconnect_task, reporter_task, discovery_task, tcp_task):
        task.cancel()
        with suppress(asyncio.CancelledError):
            await task


def main() -> None:
    Config.load_env()

    parser = argparse.ArgumentParser(description="Archipel node runner (Sprint 3)")
    parser.add_argument("--port", type=int, default=Config.DEFAULT_TCP_PORT)
    parser.add_argument("--share", type=Path, default=None, help="Partager un fichier local")
    parser.add_argument(
        "--download", type=str, default=None, help="Telecharger un fichier via son file_id"
    )
    parser.add_argument("--out", type=Path, default=None, help="Chemin de sortie pour --download")
    args = parser.parse_args()

    asyncio.run(run_node(args.port, args.share, args.download, args.out))


if __name__ == "__main__":
    main()
