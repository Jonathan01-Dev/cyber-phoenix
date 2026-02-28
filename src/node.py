"""Entrypoint de noeud Archipel pour Sprint 1."""
import argparse
import asyncio
import signal
from contextlib import suppress

from src.config import Config
from src.crypto.identity import NodeIdentity
from src.crypto.tofu import TrustStore
from src.network.discovery import DiscoveryService, PeerTable
from src.network.tcp_server import TCPServer


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


async def run_node(port: int) -> None:
    Config.load_env()
    identity = NodeIdentity(Config.KEYS_DIR / f"node_{port}.key")
    trust_store = TrustStore()
    peer_table = PeerTable(self_node_id=identity.node_id_hex)
    peer_table.on_change(_print_peer_event)

    tcp = TCPServer(identity, port, _message_handler, peer_table=peer_table, trust_store=trust_store)
    discovery = DiscoveryService(identity, port, peer_table, trust_store=trust_store)

    tcp_task = asyncio.create_task(tcp.start())
    discovery_task = asyncio.create_task(discovery.start())
    reporter_task = asyncio.create_task(_peer_table_reporter(peer_table))
    autoconnect_task = asyncio.create_task(_autoconnect_loop(tcp, peer_table, identity.node_id_hex))

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

    await stop_event.wait()

    discovery.stop()
    tcp.stop()
    for task in (autoconnect_task, reporter_task, discovery_task, tcp_task):
        task.cancel()
        with suppress(asyncio.CancelledError):
            await task


def main() -> None:
    Config.load_env()

    parser = argparse.ArgumentParser(description="Archipel node runner (Sprint 1)")
    parser.add_argument("--port", type=int, default=Config.DEFAULT_TCP_PORT)
    args = parser.parse_args()

    asyncio.run(run_node(args.port))


if __name__ == "__main__":
    main()
