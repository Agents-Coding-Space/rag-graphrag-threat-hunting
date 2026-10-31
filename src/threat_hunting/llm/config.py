"""Configuration for Threat Hunting LLM connectors."""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
from typing import Literal

from dotenv import load_dotenv


ROOT = Path(__file__).resolve().parents[3]
load_dotenv(ROOT / ".env", override=True)

LLMProviderType = Literal["ollama", "openai", "generic_openai"]


@dataclass
class LLMConfig:
    """Configures LLM connection and generation parameters."""

    provider: LLMProviderType = "generic_openai"
    model_name: str = ""
    base_url: str = "http://127.0.0.1:20128/v1"
    api_key: str = ""
    temperature: float = 0.0
    max_tokens: int = 2048
    timeout_seconds: float = 120.0
    max_retries: int = 1
    retry_delay_seconds: float = 2.0

    @classmethod
    def from_env(cls) -> LLMConfig:
        """Load configuration from .env or environment variables."""
        provider = os.environ.get(
            "LLM_PROVIDER", "generic_openai"
        ).strip().lower()

        if provider not in ("openai", "generic_openai", "ollama"):
            raise ValueError("Invalid LLM_PROVIDER")

        model_name = os.environ.get("LLM_MODEL", "").strip()
        if not model_name:
            raise ValueError("Missing LLM_MODEL in .env")

        if provider == "ollama":
            host = os.environ.get(
                "OLLAMA_HOST", "http://localhost:11434"
            ).strip().rstrip("/")
            base_url = f"{host}/v1"
            api_key = os.environ.get("OLLAMA_API_KEY", "ollama").strip()
        else:
            base_url = os.environ.get(
                "LLM_BASE_URL", "http://127.0.0.1:20128/v1"
            ).strip().rstrip("/")
            api_key = os.environ.get("LLM_API_KEY", "").strip()

            if not api_key:
                raise ValueError("Missing LLM_API_KEY in .env")

        return cls(
            provider=provider,
            model_name=model_name,
            base_url=base_url,
            api_key=api_key,
            temperature=float(os.environ.get("LLM_TEMPERATURE", "0.0")),
            max_tokens=int(os.environ.get("LLM_MAX_TOKENS", "2048")),
            timeout_seconds=float(
                os.environ.get("LLM_TIMEOUT_SECONDS", "120")
            ),
            max_retries=int(os.environ.get("LLM_MAX_RETRIES", "1")),
            retry_delay_seconds=float(
                os.environ.get("LLM_RETRY_DELAY", "2.0")
            ),
        )