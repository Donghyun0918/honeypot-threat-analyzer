"""LLM provider abstraction for llm-analyzer.

Mirrors the frontend's ``src/lib/llm-providers.ts`` so both the sidecar and
the Next.js UI are configured with the same environment variables and speak
to the same backends.

Selected with ``LLM_PROVIDER`` (ollama | openai | anthropic | gemini).
``LLM_MODEL`` overrides the per-provider default.

Only the standard library is used for HTTP so the image stays small; the
request bodies are small enough that streaming is unnecessary.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

DEFAULT_TIMEOUT = int(os.getenv("LLM_TIMEOUT_SEC", "120"))


class ProviderError(RuntimeError):
    """Raised when the provider call fails or returns an unusable body."""


def _post_json(url: str, payload: dict, headers: dict, timeout: int) -> dict:
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    for k, v in headers.items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:  # noqa: PERF203
        detail = e.read().decode("utf-8", "replace")[:400]
        raise ProviderError(f"HTTP {e.code} from {url}: {detail}") from e
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as e:
        raise ProviderError(f"call to {url} failed: {e}") from e


class Provider:
    """Common interface: ``complete(prompt) -> raw text``."""

    name = "base"
    model = ""

    def complete(self, prompt: str) -> str:  # pragma: no cover - interface
        raise NotImplementedError


class OllamaProvider(Provider):
    name = "ollama"

    def __init__(self) -> None:
        self.host = os.getenv("OLLAMA_HOST", "http://ollama:11434").rstrip("/")
        self.model = os.getenv("LLM_MODEL", "llama3.1:8b")

    def complete(self, prompt: str) -> str:
        data = _post_json(
            f"{self.host}/api/generate",
            {
                "model": self.model,
                "prompt": prompt,
                "stream": False,
                "format": "json",
                "options": {"temperature": 0.2},
            },
            {},
            DEFAULT_TIMEOUT,
        )
        return data.get("response", "")


class OpenAIProvider(Provider):
    name = "openai"

    def __init__(self) -> None:
        self.base = os.getenv("OPENAI_BASE_URL", "https://api.openai.com").rstrip("/")
        self.key = os.getenv("OPENAI_API_KEY", "")
        self.model = os.getenv("LLM_MODEL", "gpt-4o-mini")
        # Some OpenAI-compatible servers reject response_format.
        self.json_mode = os.getenv("OPENAI_JSON_MODE", "true") != "false"

    def complete(self, prompt: str) -> str:
        payload: dict = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.2,
        }
        if self.json_mode:
            payload["response_format"] = {"type": "json_object"}
        data = _post_json(
            f"{self.base}/v1/chat/completions",
            payload,
            {"Authorization": f"Bearer {self.key}"},
            DEFAULT_TIMEOUT,
        )
        return data["choices"][0]["message"]["content"]


class AnthropicProvider(Provider):
    name = "anthropic"

    def __init__(self) -> None:
        self.base = os.getenv("ANTHROPIC_BASE_URL", "https://api.anthropic.com").rstrip("/")
        self.key = os.getenv("ANTHROPIC_API_KEY", "")
        self.model = os.getenv("LLM_MODEL", "claude-3-5-haiku-latest")

    def complete(self, prompt: str) -> str:
        data = _post_json(
            f"{self.base}/v1/messages",
            {
                "model": self.model,
                "max_tokens": 1500,
                "temperature": 0.2,
                "messages": [{"role": "user", "content": prompt}],
            },
            {"x-api-key": self.key, "anthropic-version": "2023-06-01"},
            DEFAULT_TIMEOUT,
        )
        parts = [b.get("text", "") for b in data.get("content", []) if b.get("type") == "text"]
        return "".join(parts)


class GeminiProvider(Provider):
    name = "gemini"

    def __init__(self) -> None:
        self.base = os.getenv("GEMINI_BASE_URL", "https://generativelanguage.googleapis.com").rstrip("/")
        self.key = os.getenv("GEMINI_API_KEY", "")
        self.model = os.getenv("LLM_MODEL", "gemini-2.0-flash")

    def complete(self, prompt: str) -> str:
        data = _post_json(
            f"{self.base}/v1beta/models/{self.model}:generateContent?key={self.key}",
            {
                "contents": [{"parts": [{"text": prompt}]}],
                "generationConfig": {
                    "temperature": 0.2,
                    "responseMimeType": "application/json",
                },
            },
            {},
            DEFAULT_TIMEOUT,
        )
        cands = data.get("candidates") or []
        if not cands:
            raise ProviderError(f"gemini returned no candidates: {str(data)[:300]}")
        parts = cands[0].get("content", {}).get("parts", [])
        return "".join(p.get("text", "") for p in parts)


_REGISTRY = {
    "ollama": OllamaProvider,
    "openai": OpenAIProvider,
    "anthropic": AnthropicProvider,
    "gemini": GeminiProvider,
}


def build_provider() -> Provider:
    """Instantiate the provider named by ``LLM_PROVIDER`` (default: ollama)."""
    name = os.getenv("LLM_PROVIDER", "ollama").strip().lower()
    cls = _REGISTRY.get(name)
    if cls is None:
        raise ProviderError(
            f"unknown LLM_PROVIDER={name!r}; expected one of {sorted(_REGISTRY)}"
        )
    return cls()
