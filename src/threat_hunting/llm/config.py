"""Configuration for Threat Hunting LLM connectors."""

from __future__ import annotations

from dataclasses import dataclass, field
import os
from typing import Literal


LLMProviderType = Literal["ollama", "openai", "generic_openai"]


@dataclass
class LLMConfig:
    """Configures LLM connection and generation parameters."""

    provider: LLMProviderType = "openai"
    model_name: str = "Phong"
    base_url: str = "https://9router.qwen2api.pp.ua/v1"
    api_key: str = field(default="sk-d8d38c4dbe7182c6-5wpch9-c84f2f0a")
    temperature: float = 0.0
    max_tokens: int = 2048
    timeout_seconds: float = 60.0
    max_retries: int = 3
    retry_delay_seconds: float = 2.0

    @classmethod
    def from_env(cls) -> LLMConfig:
        """Create LLMConfig from environment variables with 9router/Phong as default."""
        provider_env = os.environ.get("LLM_PROVIDER", "").lower()
        if provider_env in ("openai", "generic_openai", "ollama"):
            provider: LLMProviderType = provider_env  # type: ignore[assignment]
        else:
            provider = "openai"

        if provider == "ollama":
            host = os.environ.get("OLLAMA_HOST", "http://localhost:11434").rstrip("/")
            base_url = f"{host}/v1"
            model_name = os.environ.get("LLM_MODEL", "ollama/gemma4")
            api_key = os.environ.get("OLLAMA_API_KEY", "ollama")
        else:
            base_url = os.environ.get("LLM_BASE_URL", "https://9router.qwen2api.pp.ua/v1").rstrip("/")
            model_name = os.environ.get("LLM_MODEL", "Phong")
            api_key = os.environ.get("LLM_API_KEY") or os.environ.get("OPENAI_API_KEY") or "sk-d8d38c4dbe7182c6-5wpch9-c84f2f0a"

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
