# README Sprint 4 - Integration, CLI et Assistant IA

## Objectif
Assembler les sprints precedents dans une interface de demo claire et exploitable.

## CLI interactive
Commande de demarrage:

```bash
python3 -m src.cli.app start --port 7777
```

Commandes disponibles:
- `peers`
- `msg <node_id> <text>`
- `send <filepath>` ou `send <node_id> <filepath>`
- `receive`
- `download <file_id> [output]`
- `status`
- `trust [node_id]`
- `/ask <question>` ou `@archipel-ai <question>`
- `exit`

## Assistant Gemini
- Integration isolee dans `src/ai/gemini.py`.
- Desactivable completement avec `--no-ai`.
- Fallback gracieux si API indisponible ou cle manquante.

Exemple offline:

```bash
python3 -m src.cli.app start --port 7777 --no-ai
```

## Notes demo
- Utiliser 3 terminaux avec ports differents.
- Le mode CLI s'appuie sur discovery + session chiffree + chunking deja implementes.
