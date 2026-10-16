"""Bounded optional model calls. Configuration never implies a successful review."""
from __future__ import annotations

import asyncio
import json
import math
import time

import httpx

from ..config import Settings


class ProviderResponseError(ValueError):
    """Safe reason code; never includes remote response text or credentials."""


class LlmClient:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.last_call: dict = {"status": "not_called", "request_sent": False}

    @property
    def available(self) -> bool:
        return self.settings.llm_enabled

    async def check_connection(self) -> dict:
        """Explicit, bounded paid canary. Never called by health/capabilities."""
        result = await self.judge(
            'Return JSON only: {"connection":"ok"}. No tools or other content.',
            "Connection check; no customer source is included.", max_tokens=64,
        )
        return {"connection_verified": result == {"connection": "ok"},
                "provider_call": dict(self.last_call)}

    async def judge(self, system: str, user: str, max_tokens: int = 1200) -> dict | None:
        started = time.monotonic()
        limit = min(max_tokens, self.settings.llm_max_output_tokens)
        self.last_call = {
            "status": "not_configured", "request_sent": False,
            "provider": self.settings.llm_provider, "requested_model": self.settings.llm_model,
            "auth_mode": self.settings.llm_auth_mode, "input_bytes": len((system + user).encode()),
            "max_output_tokens": limit, "requests": 0, "automatic_retries": 0,
            "usage": None, "cost_usd": None,
            "cost_source": "unknown; consult provider billing",
        }
        if not self.available:
            return None
        if self.last_call["input_bytes"] > self.settings.llm_max_input_bytes or limit < 1:
            self.last_call["status"] = "input_budget_exceeded"
            return None
        try:
            raw = await asyncio.wait_for(
                self._complete(system, user, limit), timeout=self.settings.llm_timeout_seconds
            )
            result = self._extract_json(raw)
            self.last_call["status"] = "completed" if result is not None else "invalid_json"
            return result
        except httpx.HTTPStatusError as exc:
            code = exc.response.status_code
            self.last_call["http_status"] = code
            self.last_call["status"] = {
                401: "authentication_failed", 403: "permission_denied", 402: "credit_required",
                404: "model_unavailable", 429: "rate_or_budget_limited",
            }.get(code, "provider_unavailable" if code >= 500 else "provider_rejected")
        except (asyncio.TimeoutError, httpx.TimeoutException):
            self.last_call["status"] = "timeout"
        except httpx.RequestError:
            self.last_call["status"] = "connection_failed"
        except ProviderResponseError as exc:
            self.last_call["status"] = str(exc)
        except (ValueError, TypeError, KeyError, IndexError, AttributeError, RecursionError):
            self.last_call["status"] = "invalid_response"
        finally:
            self.last_call["duration_ms"] = round((time.monotonic() - started) * 1000)
        return None

    async def _complete(self, system: str, user: str, max_tokens: int) -> str:
        provider = self.settings.llm_provider.lower()
        base = self.settings.llm_api_base
        if not base:
            raise ProviderResponseError("invalid_provider_configuration")
        credential = self.settings.llm_credential
        payload = {"model": self.settings.llm_model, "max_tokens": max_tokens}
        headers = {"content-type": "application/json"}
        if provider == "anthropic":
            url = base + "/messages"
            headers.update({"x-api-key": credential, "anthropic-version": "2023-06-01"})
            payload.update({"system": system, "messages": [{"role": "user", "content": user}]})
        else:
            url = base + "/chat/completions"
            headers["Authorization"] = f"Bearer {credential}"
            payload.update({"messages": [{"role": "system", "content": system},
                                          {"role": "user", "content": user}],
                            "response_format": {"type": "json_object"}})
        self.last_call.update({"request_sent": True, "requests": 1})
        # Respect the runtime's configured network proxy; do not follow redirects
        # or retry a paid request. Stream into a bounded buffer before parsing JSON.
        async with httpx.AsyncClient(timeout=self.settings.llm_timeout_seconds, follow_redirects=False) as client:
            async with client.stream("POST", url, headers=headers, json=payload) as response:
                response.raise_for_status()
                body = bytearray()
                async for chunk in response.aiter_bytes():
                    body.extend(chunk)
                    if len(body) > self.settings.llm_max_response_bytes:
                        raise ProviderResponseError("response_budget_exceeded")
                data = json.loads(body)
        if not isinstance(data, dict):
            raise ProviderResponseError("invalid_response")
        # Only safe typed metadata. No remote error messages, URLs or raw headers.
        self.last_call["response_model"] = str(data.get("model", ""))[:120]
        self.last_call["usage"] = self._usage(data.get("usage"), provider)
        raw_usage = data.get("usage") or {}
        cost = raw_usage.get("cost") if isinstance(raw_usage, dict) else None
        if type(cost) in (int, float) and math.isfinite(cost) and cost >= 0:
            self.last_call["cost_usd"] = cost
            self.last_call["cost_source"] = "provider_reported"
        if provider == "anthropic":
            if data.get("stop_reason") != "end_turn":
                raise ProviderResponseError("incomplete_response")
            blocks = data.get("content")
            if not isinstance(blocks, list):
                raise ProviderResponseError("invalid_response")
            text = "".join(block.get("text", "") for block in blocks
                           if isinstance(block, dict) and block.get("type") == "text")
        else:
            choice = data["choices"][0]
            if choice.get("finish_reason") != "stop":
                raise ProviderResponseError("incomplete_response")
            message = choice["message"]
            if message.get("refusal") or message.get("tool_calls"):
                raise ProviderResponseError("refused_or_unexpected_tool_call")
            text = message["content"]
        if not isinstance(text, str) or not text.strip():
            raise ProviderResponseError("empty_response")
        return text

    @staticmethod
    def _usage(raw, provider: str) -> dict | None:
        if not isinstance(raw, dict):
            return None
        fields = {"input_tokens": "input_tokens" if provider == "anthropic" else "prompt_tokens",
                  "output_tokens": "output_tokens" if provider == "anthropic" else "completion_tokens",
                  "total_tokens": "total_tokens"}
        usage = {dest: raw[src] for dest, src in fields.items()
                 if type(raw.get(src)) is int and raw[src] >= 0}
        if "total_tokens" not in usage and {"input_tokens", "output_tokens"} <= usage.keys():
            usage["total_tokens"] = usage["input_tokens"] + usage["output_tokens"]
        return usage or None

    @staticmethod
    def _extract_json(text: str) -> dict | None:
        text = text.strip()
        if text.startswith("```json\n") and text.endswith("```"):
            text = text[8:-3].strip()
        elif text.startswith("```\n") and text.endswith("```"):
            text = text[4:-3].strip()
        # Refuse trailing commentary, multiple objects, duplicate keys and NaN.
        def pairs(items):
            result = {}
            for key, value in items:
                if key in result:
                    raise ValueError("duplicate JSON field")
                result[key] = value
            return result
        try:
            parsed = json.loads(text, object_pairs_hook=pairs,
                                parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite JSON")))
            return parsed if isinstance(parsed, dict) else None
        except (ValueError, RecursionError):
            return None


if __name__ == "__main__":
    # Explicit operator action, not a startup probe; output excludes credentials.
    print(json.dumps(asyncio.run(LlmClient(Settings()).check_connection()), indent=2))
