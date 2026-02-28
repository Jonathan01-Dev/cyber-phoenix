# README Sprint 2 - Chiffrement et Authentification

## Objectif
Etablir des sessions E2E entre pairs avec authentification sans CA centrale.

## Elements implementes

- Handshake ephemere X25519 avec derivation HKDF-SHA256.
- Rejet de handshake hors fenetre temporelle (`ARCHIPEL_HANDSHAKE_MAX_SKEW`).
- Tunnel de donnees chiffre en AES-256-GCM.
- Verification de l'authentification `AUTH` (signature Ed25519).
- Integrite par HMAC-SHA256 sur les paquets du tunnel (MSG, PING, PONG, AUTH_OK).
- TOFU (Trust On First Use) persistant dans `~/.archipel/trust.json`.
- Rejet d'un endpoint si l'identite change entre deux connexions.

## Variables d'environnement

- `ARCHIPEL_HANDSHAKE_MAX_SKEW`: derive temporelle max acceptee en secondes.
- `ARCHIPEL_INTERFACE_IP`: interface locale forcee pour la decouverte.
- `ARCHIPEL_DISCOVERY_LOCALHOST_FALLBACK`: fallback local pour tests multi-noeuds sur une machine.

## Verification rapide

1. Lancer 3 noeuds:
   - `python3 -m src.node --port 7777`
   - `python3 -m src.node --port 7778`
   - `python3 -m src.node --port 7779`
2. Verifier les logs:
   - `[TCP] secure session established ...`
   - absence d'erreur de signature/HMAC.
3. Verifier TOFU:
   - `cat ~/.archipel/trust.json`
