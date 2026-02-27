<<<<<<< HEAD
Archipel | Sprint 0 : Fondation et Identite Souveraine
1. Presentation

Ce depot contient l'implementation du protocole Archipel, un systeme de communication P2P souverain concu pour operer en environnement deconnecte (Zero-Internet).

Ce Sprint 0 etablit les bases cryptographiques.
2. Architecture du Projet

Conformement aux recommandations du document technique:

Archipel_Team_Name/
├── README.md               # Documentation critique (Sprint 0)
├── .env.example            # Modele des variables (API Gemini, etc.)
├── .gitignore              # Exclusion des cles privees (*.key) et env
├── src/
│   ├── crypto/             # Modules PKI, Ed25519, Handshake X25519
│   ├── network/            # Decouverte Multicast, TCP Server, Packet logic
│   ├── transfer/           # Chunking (512KB), Manifests
│   ├── messaging/          # Logique de chat et integration IA
│   └── cli/                # Interface utilisateur (CLI)
├── tests/                  # Tests unitaires de robustesse
└── config.py               # Constantes globales et types de paquets

3. Choix Techniques et Justifications
Composant	Technologie	Justification
Langage	Python 3.13	Rapidite de prototypage et bibliotheques crypto matures.
Decouverte	UDP Multicast	239.255.42.99:6000 - Standard pour le Zero-Conf LAN.
Transport	TCP	Port 7777 - Garantit l'integrite des transferts de fichiers.
Identite	Ed25519	Signature numerique rapide et securisee.
Chiffrement	AES-256-GCM	Chiffrement authentifie pour prevenir toute alteration.
4. Specification du Paquet Binaire (Archipel v1)

Pour optimiser les echanges sans serveur, nous avons defini un format de paquet binaire strict :
Champ	Taille	Description
MAGIC	4 bytes	Identifiant du protocole (ARCH)
TYPE	1 byte	Type de message (HELLO, MSG, CHUNK, etc.)
NODE_ID	32 bytes	Empreinte publique de l'expediteur
PAYLOAD_LEN	4 bytes	Taille de la donnee (Big-endian)
PAYLOAD	Variable	Donnees chiffrees
SIGNATURE	64 bytes	Signature Ed25519 du paquet
5. Etat d'avancement (Sprint 0)
Realise

    Arborescence conforme : Structure src/ prete et documentee.

    Identite locale : Generation et persistance securisee des cles Ed25519 (src/crypto/identity.py).

    Definition Protocole : Mapping des types de paquets (0x01 a 0x0B) dans config.py.

    Gestionnaire de Paquets : Serialisation et Deserialisation binaire implementee.

En cours / A venir (Sprint 1)

    Initialisation du scan UDP Multicast.

    Gestion de la Peer Table dynamique.

6. Demarrage Rapide

    Installation des dependances :
    Bash

    pip install pynacl pycryptodome

    Initialiser l'identite du noeud :
    Bash

    python -m src.cli.main status
=======
﻿# README Sprint 0 - Cyber Phoenix (Archipel)


`Archipel_Document_Technique_Participants.pdf`, section **SPRINT 0 - BOOTSTRAP & ARCHITECTURE**.

## 1. Cible du Sprint 0

- Fenetre: **H+0 -> H+2**
- Livrable cle: **repo actif + proto PKI + specification protocole**

## 2. Exigences officielles (doc)

- Repository Git en place, branches creees
- Langage principal choisi et justifie dans la documentation
- Technologie de transport local choisie
- Generation des paires de cles par noeud
- Format de paquet binaire defini
- Schema d'architecture present dans le README

Recommandation officielle retenue: **UDP Multicast** (decouverte) + **TCP** (transfert).

## 3. Decisions techniques du projet

- Langage principal: **Python**
- Reseau local:
  - decouverte multicast `239.255.42.99:6000`
  - transport pair-a-pair TCP (port par defaut `7777`)
- Crypto:
  - identite et signatures: Ed25519
  - echange de secret: X25519
  - derivation de cle: HKDF-SHA256
  - session: AES-GCM
- Contrainte architecture: pas de serveur central, logique LAN deconnectee d'Internet

## 4. Specification binaire Archipel v1

- `MAGIC`: 4 bytes (`ARCH`)
- `TYPE`: 1 byte
- `NODE_ID`: 32 bytes
- `PAYLOAD_LEN`: 4 bytes (uint32 big-endian)
- `PAYLOAD`: variable
- `SIGNATURE`: 32 bytes

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

Reference implementation: `src/config.py`, `src/network/packet.py`.

## 5. Architecture Sprint 0 (etat actuel)

```text
cyber-phoenix/
├── src/
│   ├── config.py
│   ├── crypto/
│   │   ├── identity.py
│   │   └── handshake.py
│   └── network/
│       ├── packet.py
│       ├── discovery.py
│       └── tcp_server.py
└── docs/
    └── README_SPRINT0.md
```

## 6. Conformite Sprint 0

Valide:

- configuration protocole centralisee (`src/config.py`)
- couche identite/PKI presente (`src/crypto/identity.py`)
- handshake secure present (`src/crypto/handshake.py`)
- format paquet defini et parse (`src/network/packet.py`)
- base decouverte P2P + serveur TCP presents (`src/network/discovery.py`, `src/network/tcp_server.py`)


## 7. Verification rapide

```bash
python -m compileall src
```


>>>>>>> 6fb9287 (readme)
