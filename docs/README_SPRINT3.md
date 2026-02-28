# README Sprint 3 - Chunking et Transfert Multi-noeuds

## Objectif
Transferer un fichier en chunks verifies entre pairs Archipel.

## Modules

### 3.1 Manifest de fichier
- Generation d'un manifest signe Ed25519:
  - `file_id` = SHA-256 du fichier complet
  - metadonnees chunks (`index`, `hash`, `size`)
- Diffusion du manifest en paquet `TYPE.MANIFEST` chiffre.

### 3.2 Telechargement parallele
- Requetes `TYPE.CHUNK_REQ` vers plusieurs fournisseurs.
- Pipeline parallele avec semaphore (min 3 workers).
- Retry sur plusieurs providers en cas d'echec/timeout.

### 3.3 Verification d'integrite
- Verification SHA-256 de chaque chunk recu.
- Verification de signature Ed25519 du fournisseur sur le hash de chunk.
- Reassemblage et verification du hash final `file_id`.

### 3.4 Stockage local
- Chunks stores dans `~/.archipel/chunks/<file_id>/`.
- Index local dans `~/.archipel/index.db` (JSON) avec manifests + owners.

## Commandes de demo

```bash
# Source
python3 -m src.node --port 7777 --share /path/to/file.bin

# Receveur
python3 -m src.node --port 7778 --download <file_id> --out ./received.bin
```

## Criteres valides
- Segmentation et transfert chunks via paquets dedies.
- Verification chunk/hash + reassemblage fichier final.
- Telechargement parallelise multi-sources.
