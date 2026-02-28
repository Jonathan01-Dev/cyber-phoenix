# Cyber Phoenix - Archipel

Implémentation Python d'un nœud P2P LAN.

## Sprint 1 livre

- Découverte de pairs UDP multicast `239.255.42.99:6000`
- Emission `HELLO` toutes les 30s
- Réponse `PEER_LIST` en unicast TCP
- Peer table en mémoire + persistance disque (`~/.archipel/peers.json`)
- Serveur TCP avec framing TLV (`Type[1] + Length[4] + Value[n]`)
- Keep-alive `PING/PONG` toutes les 15s
- Port TCP configurable via `.env` (défaut `7777`)

## Sprint 2 livre

- Handshake X25519 ephemere + HKDF-SHA256
- Chiffrement des tunnels TCP via AES-256-GCM
- Verification AUTH (signature Ed25519)
- Integrite HMAC-SHA256 sur les paquets de session
- TOFU persistant (`~/.archipel/trust.json`)
- Auto-connexion TCP vers les pairs decouverts

## Sprint 3 livre

- Manifest signe (SHA-256 fichier + hashes de chunks)
- Segmentation en chunks 512 KB
- Protocole `CHUNK_REQ / CHUNK_DATA / ACK` via tunnel chiffre
- Verification SHA-256 chunk + verification signature fournisseur
- Telechargement parallele multi-sources (min 3 workers)
- Reassemblage du fichier et verification hash final

## Lancer

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

Un nœud:

```bash
python3 -m src.node --port 7777
```

Test Sprint 1 (3 nœuds sur la même machine):

```bash
python3 -m src.node --port 7777
python3 -m src.node --port 7778
python3 -m src.node --port 7779
```

Chaque instance affiche les logs HELLO et la peer table en console.

Exemple Sprint 3:

```bash
# Noeud source
python3 -m src.node --port 7777 --share /chemin/fichier.bin

# Noeud receveur (file_id affiche par le noeud source)
python3 -m src.node --port 7778 --download <file_id> --out ./copie.bin
```
