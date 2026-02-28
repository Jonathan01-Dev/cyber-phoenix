"""Gemini integration (optional) for Sprint 4."""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Optional
from urllib import error, request


@dataclass
class GeminiConfig:
    enabled: bool = True
    api_key: str = ""
    model: str = "gemini-1.5-flash"


class GeminiClient:
    def __init__(self, config: GeminiConfig):
        self.config = config
        if not self.config.api_key:
            self.config.api_key = os.getenv("GEMINI_API_KEY", "")

    async def query(self, conversation_context: list[str], user_query: str) -> str:
        if not self.config.enabled:
            return "[AI] desactive (--no-ai)."
        if not self.config.api_key:
            return "[AI] GEMINI_API_KEY manquant."

        prompt = self._build_prompt(conversation_context, user_query)
        body = {
            "contents": [
                {
                    "role": "user",
                    "parts": [{"text": prompt}],
                }
            ]
        }

        url = (
            "https://generativelanguage.googleapis.com/v1beta/models/"
            f"{self.config.model}:generateContent?key={self.config.api_key}"
        )

        try:
            req = request.Request(
                url,
                data=json.dumps(body).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with request.urlopen(req, timeout=12) as resp:
                raw = json.loads(resp.read().decode("utf-8"))
            return self._extract_text(raw)
        except error.URLError as exc:
            return f"[AI] indisponible: {exc.reason}"
        except Exception:
            return "[AI] erreur de traitement."

    @staticmethod
    def _build_prompt(conversation_context: list[str], user_query: str) -> str:
        history = "\n".join(conversation_context[-10:])
        return (
            "Tu assistes sur un reseau local P2P Archipel. "
            "Sois concis et technique.\n\n"
            f"Contexte:\n{history}\n\n"
            f"Question: {user_query}"
        )

    @staticmethod
    def _extract_text(raw: dict) -> str:
        candidates = raw.get("candidates", [])
        if not candidates:
            return "[AI] reponse vide."
        parts = candidates[0].get("content", {}).get("parts", [])
        texts = [str(p.get("text", "")) for p in parts if p.get("text")]
        if not texts:
            return "[AI] reponse vide."
        return "\n".join(texts)
