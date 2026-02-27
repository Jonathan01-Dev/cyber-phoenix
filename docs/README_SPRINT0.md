# README Sprint 0 - Archipel

Ce document synthétise le **Sprint 0 (Bootstrap & Architecture)** selon le document technique `Archipel_Document_Technique_Participants.pdf` et l'état actuel du projet dans `C:\Archipel`.

## 1. Cadre Sprint 0 (référence document)

- Fenêtre: **H+0 -> H+2**
- Livrable clé attendu: **repo actif, proto PKI, spec protocole**
- Focus: **environnement opérationnel** + **décisions d'architecture figées**

### Checklist officielle Sprint 0 (doc)

- Repo cloné et branches créées
- Choix du langage principal + justification dans le README
- Choix de la techno transport local
- Génération des paires de clés pour chaque noeud
- Définition du format de paquet binaire
- Schéma d'architecture (ASCII ou diagramme) dans le README

Recommandation document: **UDP Multicast** pour la découverte + **TCP** pour le transfert.

## 2. Choix techniques Archipel (projet)

- Langage principal: **Python 3.13**
- Modèle réseau local:
  - Découverte: **UDP Multicast** (`239.255.42.99:6000`)
  - Transport pair-à-pair: **TCP** (port par défaut `7777`)
- Crypto:
  - Identité: **Ed25519** (signature)
  - ECDH: **X25519**
  - Session: **AES-256-GCM**
  - Dérivation: **HKDF-SHA256**
- Contraintes:
  - Fonctionnement LAN sans dépendance serveur central
  - Respect de la logique "zéro connexion internet" au runtime protocolaire

## 3. Spécification paquet binaire (implémentée)

Format `ARCHIPEL PACKET v1`:

- `MAGIC`: 4 bytes (`ARCH`)
- `TYPE`: 1 byte
- `NODE_ID`: 32 bytes
- `PAYLOAD_LEN`: 4 bytes (`uint32 big-endian`)
- `PAYLOAD`: longueur variable
- `SIGNATURE`: 32 bytes (HMAC-SHA256 ou placeholder)

Types de paquets:

- `0x01 HELLO`
- `0x02 PEER_LIST`
- `0x03 MSG`
- `0x04 CHUNK_REQ`
- `0x05 CHUNK_DATA`
- `0x06 MANIFEST`
- `0x07 ACK`
- `0x08 HANDSHAKE_HELLO`
- `0x09 HANDSHAKE_REPLY`
- `0x0A AUTH`
- `0x0B AUTH_OK`

Constantes correspondantes: `src/config.py`.

## 4. Architecture Sprint 0 (ASCII)

```text
+-------------------+       +--------------------+
|      CLI          |<----->|   Archipel Node    |
| src/cli/main.py   |       | orchestration      |
+-------------------+       +---------+----------+
                                      |
           +--------------------------+--------------------------+
           |                          |                          |
           v                          v                          v
+-------------------+      +-------------------+      +-------------------+
|  Crypto Layer     |      |  Network Layer    |      |  Transfer Layer   |
| identity.py       |      | discovery.py      |      | chunker.py        |
| handshake.py      |      | tcp_server.py     |      | manifests/chunks  |
+-------------------+      | packet.py         |      +-------------------+
                           +-------------------+
```

## 5. État de conformité Sprint 0

### Valide

- Structure modulaire `src/crypto`, `src/network`, `src/transfer`, `src/cli`
- Configuration centrale et types de paquets (`src/config.py`)
- Format paquet binaire défini et sérialisé (`src/network/packet.py`)
- Base PKI locale (clé noeud créée et persistée) (`src/crypto/identity.py`)
- Décision transport alignée doc (multicast + TCP)

### À finaliser pour clôture stricte Sprint 0

- Tag git `sprint-0` (non vérifiable ici car dossier sans `.git` local)
- Schéma d'architecture du Sprint 0 intégré aussi dans le README racine
- Validation équipe (branches/issues) selon workflow hackathon

## 6. Arborescence cible (Sprint 0+)

```text
archipel/
├── src/
│   ├── crypto/
│   ├── network/
│   ├── transfer/
│   ├── messaging/
│   └── cli/
├── tests/
├── docs/
└── demo/
```

## 7. Commandes de démarrage

```bash
pip install -r requirements.txt
python -m src.cli.main status
python -m src.cli.main start --port 7777
```

## 8. Références projet

- Config globale: `src/config.py`
- Identité/PKI: `src/crypto/identity.py`
- Handshake: `src/crypto/handshake.py`
- Packet format: `src/network/packet.py`
- Discovery LAN: `src/network/discovery.py`
- TCP P2P: `src/network/tcp_server.py`
- CLI: `src/cli/main.py`

---

Document source utilisé: `C:\Users\DELL LATITUDE 7430\Downloads\Archipel_Document_Technique_Participants.pdf` (section Sprint 0 et plan des sprints).
