"""Threat Hunting LLM integration package."""

from .client import LLMClient, LLMClientError, LLMConnectionError, LLMTimeoutError, extract_json_text
from .config import LLMConfig
from .guardrail import GuardrailResult, HallucinationGuardrail, extract_context_anchors
from .prompt import SYSTEM_PROMPT, ThreatHuntingPromptBuilder, format_context_for_prompt
from .schema import AttackStep, MitreTechniqueMatch, ThreatHuntingReport


__all__ = [
    "LLMConfig",
    "LLMClient",
    "LLMClientError",
    "LLMConnectionError",
    "LLMTimeoutError",
    "extract_json_text",
    "AttackStep",
    "MitreTechniqueMatch",
    "ThreatHuntingReport",
    "SYSTEM_PROMPT",
    "ThreatHuntingPromptBuilder",
    "format_context_for_prompt",
    "HallucinationGuardrail",
    "GuardrailResult",
    "extract_context_anchors",
]
