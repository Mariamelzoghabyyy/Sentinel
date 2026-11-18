"""Pluggable LLM backends.

Sentinel is designed to be *useful with no API key at all*: the local backend
returns None, and every agent then falls back to its deterministic analyst
heuristics. Point it at a real model with env vars and the same graph runs
unchanged, with agents doing genuine reasoning + tool calls.

Backends (first match wins):
  SENTINEL_BACKEND=groq|openai|anthropic|ollama|local   (explicit override)
  GROQ_API_KEY            -> https://api.groq.com/openai/v1
  OPENAI_API_KEY          -> configurable via OPENAI_BASE_URL (OpenRouter/Together/vLLM all work)
  ANTHROPIC_API_KEY       -> https://api.anthropic.com
  OLLAMA_HOST             -> http://localhost:11434
  otherwise               -> local (deterministic, no network)

Model override: SENTINEL_MODEL
"""

from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request


class LLMError(RuntimeError):
    pass


class Backend:
    name = "base"
    model = ""

    def complete(self, system: str, user: str, max_tokens: int = 1200) -> str | None:
        raise NotImplementedError

    def available(self) -> bool:
        return True


class LocalBackend(Backend):
    """No-network backend. Signals agents to use their deterministic path."""

    name = "local"
    model = "heuristic"

    def complete(self, system: str, user: str, max_tokens: int = 1200) -> str | None:
        return None

    def available(self) -> bool:
        return True


def _post_json(url: str, payload: dict, headers: dict, timeout: int = 60) -> dict:
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json", **headers},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")[:400]
        raise LLMError(f"HTTP {e.code} from {url}: {body}") from e
    except (urllib.error.URLError, TimeoutError) as e:
        raise LLMError(f"cannot reach {url}: {e}") from e


class _OpenAICompatible(Backend):
    base_url = ""
    api_key_env = ""
    default_model = ""

    def __init__(self):
        self.api_key = os.environ.get(self.api_key_env, "")
        self.model = os.environ.get("SENTINEL_MODEL") or self.default_model
        self.base_url = self.base_url.rstrip("/")

    def available(self) -> bool:
        return bool(self.api_key)

    def complete(self, system: str, user: str, max_tokens: int = 1200) -> str | None:
        data = _post_json(
            f"{self.base_url}/chat/completions",
            {
                "model": self.model,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
                "temperature": 0.1,
                "max_tokens": max_tokens,
            },
            {"Authorization": f"Bearer {self.api_key}"},
        )
        try:
            return data["choices"][0]["message"]["content"]
        except (KeyError, IndexError) as e:
            raise LLMError(f"unexpected response shape: {str(data)[:300]}") from e


class GroqBackend(_OpenAICompatible):
    name = "groq"
    base_url = "https://api.groq.com/openai/v1"
    api_key_env = "GROQ_API_KEY"
    default_model = "llama-3.3-70b-versatile"


class OpenAIBackend(_OpenAICompatible):
    name = "openai"
    api_key_env = "OPENAI_API_KEY"
    default_model = "gpt-4o-mini"

    def __init__(self):
        super().__init__()
        self.base_url = os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1").rstrip("/")


class OllamaBackend(_OpenAICompatible):
    name = "ollama"
    api_key_env = "OLLAMA_API_KEY"      # usually unset; we treat host presence as available
    default_model = "llama3.1"

    def __init__(self):
        super().__init__()
        self.base_url = os.environ.get("OLLAMA_HOST", "http://localhost:11434/r1").rstrip("/")
        if not self.base_url.endswith("/v1"):
            self.base_url = self.base_url.rstrip("/") + "/v1"

    def available(self) -> bool:
        return bool(os.environ.get("OLLAMA_HOST"))


class AnthropicBackend(Backend):
    name = "anthropic"
    default_model = "claude-3-5-haiku-latest"

    def __init__(self):
        self.api_key = os.environ.get("ANTHROPIC_API_KEY", "")
        self.model = os.environ.get("SENTINEL_MODEL") or self.default_model

    def available(self) -> bool:
        return bool(self.api_key)

    def complete(self, system: str, user: str, max_tokens: int = 1200) -> str | None:
        data = _post_json(
            "https://api.anthropic.com/v1/messages",
            {
                "model": self.model,
                "system": system,
                "max_tokens": max_tokens,
                "temperature": 0.1,
                "messages": [{"role": "user", "content": user}],
            },
            {"x-api-key": self.api_key, "anthropic-version": "2023-06-01"},
        )
        try:
            return "".join(b.get("text", "") for b in data["content"])
        except (KeyError, TypeError) as e:
            raise LLMError(f"unexpected response shape: {str(data)[:300]}") from e


def get_backend() -> Backend:
    forced = os.environ.get("SENTINEL_BACKEND", "").lower().strip()
    candidates: list[Backend] = []
    if forced:
        mapping = {
            "groq": GroqBackend, "openai": OpenAIBackend, "anthropic": AnthropicBackend,
            "ollama": OllamaBackend, "local": LocalBackend,
        }
        if forced not in mapping:
            raise LLMError(f"unknown SENTINEL_BACKEND={forced!r}; choose from {sorted(mapping)}")
        return mapping[forced]()
    candidates = [GroqBackend(), OpenAIBackend(), AnthropicBackend(), OllamaBackend(), LocalBackend()]
    for b in candidates:
        if b.available():
            return b
    return LocalBackend()


# --------------------------------------------------------------------------- #
# Robust JSON extraction — LLMs love to wrap JSON in prose or fences.
# --------------------------------------------------------------------------- #
_FENCE = re.compile(r"```(?:json)?\s*(.*?)```", re.S)


def extract_json(text: str | None) -> dict | None:
    if not text:
        return None
    for candidate in [text, *[m.group(1) for m in _FENCE.finditer(text)]]:
        candidate = candidate.strip()
        # Try whichever bracket appears first — a top-level array must not be
        # silently reduced to its first object.
        openers = sorted(
            [(candidate.find(o), o, c) for o, c in (("{", "}"), ("[", "]")) if candidate.find(o) != -1],
            key=lambda t: t[0],
        )
        for start, opener, closer in openers:
            end = candidate.rfind(closer)
            if end > start:
                try:
                    val = json.loads(candidate[start:end + 1])
                    return val if isinstance(val, dict) else {"items": val}
                except json.JSONDecodeError:
                    continue
    return None
