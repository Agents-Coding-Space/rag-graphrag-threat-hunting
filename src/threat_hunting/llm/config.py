"""Configuration for Threat Hunting LLM connectors."""

from __future__ import annotations

from dataclasses import dataclass, field
import os
from typing import Literal


LLMProviderType = Literal["ollama", "openai", "generic_openai"]


@dataclass
class LLMConfig:
    """Configures LLM connection and generation parameters."""

    provider: LLMProviderType = "ollama"
    model_name: str = "llama3.1:8b"
    base_url: str = "http://localhost:11434/v1"
    api_key: str = field(default="")
    temperature: float = 0.0
    max_tokens: int = 2048
    timeout_seconds: float = 60.0
    max_retries: int = 3
    retry_delay_seconds: float = 2.0

    @classmethod
    def from_env(cls) -> LLMConfig:
        """Create LLMConfig from environment variables with sensible defaults."""
        provider_env = os.environ.get("LLM_PROVIDER", "").lower()
        if provider_env in ("openai", "generic_openai", "ollama"):
            provider: LLMProviderType = provider_env  # type: ignore[assignment]
        elif os.environ.get("OPENAI_API_KEY"):
            provider = "openai"
        else:
            provider = "ollama"

        if provider == "ollama":
            host = os.environ.get("OLLAMA_HOST", "http://localhost:11434").rstrip("/")
            base_url = f"{host}/v1"
            model_name = os.environ.get("LLM_MODEL", "llama3.1:8b")
            api_key = os.environ.get("OLLAMA_API_KEY", "ollama")
        else:
            base_url = os.environ.get("LLM_BASE_URL", "https://api.openai.com/v1").rstrip("/")
            model_name = os.environ.get("LLM_MODEL", "gpt-4o-mini")
            api_key = os.environ.get("OPENAI_API_KEY", "")

        timeout_str = os.environ.get("LLM_TIMEOUT_SECONDS", "60.0")
        try:
            timeout_seconds = float(timeout_str)
        except ValueError:
            timeout_seconds = 60.0

        return cls(
            provider=provider,
            model_name=model_name,
            base_url=base_url,
            api_key=api_key,
            temperature=float(os.environ.get("LLM_TEMPERATURE", "0.0")),
            max_tokens=int(os.environ.get("LLM_MAX_TOKENS", "2048")),
            timeout_seconds=timeout_seconds,
            max_retries=int(os.environ.get("LLM_MAX_RETRIES", "3")),
            retry_delay_seconds=float(os.environ.get("LLM_RETRY_DELAY", "2.0")),
        )
