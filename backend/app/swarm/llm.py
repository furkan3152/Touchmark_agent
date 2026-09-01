"""Opsiyonel LLM-as-Judge katmanı.

Anahtar yoksa `available == False` olur ve denetçiler yalnızca heuristik motorla çalışır.
Böylece sistem anahtarsız da tam işlevlidir, anahtar varsa nitel değerlendirme eklenir.
"""

from __future__ import annotations

import json

import httpx

from ..config import Settings


class LlmClient:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    @property
    def available(self) -> bool:
        return self.settings.llm_enabled

    async def judge(self, system: str, user: str, max_tokens: int = 1200) -> dict | None:
        """JSON döndürmesi beklenen bir değerlendirme çağrısı. Hata olursa None."""
        if not self.available:
            return None
        try:
            raw = await self._complete(system, user, max_tokens)
            return self._extract_json(raw)
        except Exception:
            return None

    async def _complete(self, system: str, user: str, max_tokens: int) -> str:
        provider = self.settings.llm_provider.lower()
        if provider == "anthropic":
            url = (self.settings.llm_base_url or "https://api.anthropic.com") + "/v1/messages"
            headers = {
                "x-api-key": self.settings.llm_api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            }
            payload = {
                "model": self.settings.llm_model,
                "max_tokens": max_tokens,
                "system": system,
                "messages": [{"role": "user", "content": user}],
            }
            async with httpx.AsyncClient(timeout=90.0) as client:
                resp = await client.post(url, headers=headers, json=payload)
                resp.raise_for_status()
                data = resp.json()
            return "".join(block.get("text", "") for block in data.get("content", []))

        # openai uyumlu (openai, openrouter, deepseek, yerel vLLM vs.)
        url = self.settings.llm_api_base + "/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.settings.llm_api_key}",
            "content-type": "application/json",
        }
        if provider == "openrouter":
            # OpenRouter isteğe bağlı atıf başlıkları; leaderboard'da uygulama adı görünür.
            headers["HTTP-Referer"] = "https://github.com/agentveritas"
            headers["X-Title"] = "AgentVeritas"
        payload = {
            "model": self.settings.llm_model,
            "max_tokens": max_tokens,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }
        async with httpx.AsyncClient(timeout=90.0) as client:
            resp = await client.post(url, headers=headers, json=payload)
            resp.raise_for_status()
            data = resp.json()
        return data["choices"][0]["message"]["content"]

    @staticmethod
    def _extract_json(text: str) -> dict | None:
        text = text.strip()
        if text.startswith("```"):
            text = text.split("```", 2)[1]
            text = text.removeprefix("json").strip()
        start, end = text.find("{"), text.rfind("}")
        if start == -1 or end <= start:
            return None
        try:
            parsed = json.loads(text[start : end + 1])
            return parsed if isinstance(parsed, dict) else None
        except json.JSONDecodeError:
            return None
