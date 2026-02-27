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
