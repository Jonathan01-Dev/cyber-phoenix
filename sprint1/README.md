# Sprint 1 - Couche Reseau P2P (Decouverte & Routage)

Implementation Sprint 1 pour Archipel:

- UDP Multicast discovery `239.255.42.99:6000`
- HELLO emis toutes les 30s
- Reponse `PEER_LIST` en unicast TCP
- Peer table en memoire + persistance disque
- Serveur TCP TLV
- Keep-alive ping/pong toutes les 15s

## Arborescence

```text
sprint1/
├── README.md
├── .env.example
└── src/
    ├── __init__.py
    ├── config.py
    ├── node.py
    └── network/
        ├── __init__.py
        ├── packet.py
        ├── tlv.py
        ├── peer_table.py
        ├── discovery.py
        └── tcp_server.py
```

## Lancer un noeud

```bash
python -m sprint1.src.node --port 7789
```

## Test Sprint 1 (3 noeuds)

Terminal 1:

```bash
python -m sprint1.src.node --port 7789
```

Terminal 2:

```bash
python -m sprint1.src.node --port 7790
```

Terminal 3:

```bash
python -m sprint1.src.node --port 7791
```

Attendu:

- Decouverte automatique < 60 secondes
- Table de pairs affichee en console
- Logs HELLO visibles

