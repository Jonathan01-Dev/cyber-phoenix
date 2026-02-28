# README Sprint 1 - Couche Réseau P2P

## Objectif
Permettre à plusieurs nœuds de se découvrir automatiquement sur le LAN, échanger les métadonnées de pairs, et maintenir une table de routage persistée.

## Modules

### 1.1 Node Discovery
- UDP Multicast: `239.255.42.99:6000`
- `HELLO` envoyé périodiquement
- `PEER_LIST` envoyé en unicast TCP
- Timeout de pair via `PEER_TIMEOUT`

### 1.2 Peer Table
- Structure en mémoire: `node_id`, `ip`, `tcp_port`, `last_seen`, `shared_files`, `reputation`
- Persistance JSON: `~/.archipel/peers.json`
- Evènements: `peer_joined`, `peer_left`

### 1.3 Serveur TCP
- Port configurable via `.env` / `--port`
- Connexions parallèles >= 10 (backlog + semaphore)
- Framing TLV sur le stream TCP
- Keep-alive `PING/PONG`

## Démo S1
Lancer 3 instances sur des ports différents et vérifier la convergence de la peer table en moins de 60 secondes.
