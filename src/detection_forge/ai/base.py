"""Provider abstraction so the toolkit is never married to one vendor.

A provider takes a system prompt + user prompt and returns the model's raw text.
The ``dryrun`` provider returns deterministic canned output so the pipeline,
tests, and CI all run with no API key and no network.
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod

from detection_forge.config import AISettings


class AIProvider(ABC):
    """Minimal text-completion interface."""

    @abstractmethod
    def complete(self, system: str, user: str) -> str:
        """Return the model's response text for the given prompts."""
        raise NotImplementedError


class DryRunProvider(AIProvider):
    """Offline provider. Returns a valid (but generic) enrichment JSON.

    This keeps the end-to-end pipeline runnable without credentials, which is
    what CI uses. It does *not* call any network service.
    """

    def complete(self, system: str, user: str) -> str:
        return json.dumps(
            {
                "summary": (
                    "[dry-run] No LLM was called. Set DETFORGE_AI_PROVIDER to "
                    "openai, azure, or anthropic for a real analysis."
                ),
                "attack": [],
                "false_positives": [
                    "[dry-run] Enable an AI provider to generate these."
                ],
                "tuning": [
                    "[dry-run] Enable an AI provider to generate these."
                ],
                "severity_rationale": "[dry-run]",
                "investigation_steps": [
                    "[dry-run] Enable an AI provider to generate these."
                ],
            }
        )


def get_provider(settings: AISettings) -> AIProvider:
    """Return the provider selected by ``settings.provider``.

    Provider SDKs are imported lazily inside each concrete provider, so the
    core toolkit imports cleanly even if ``openai``/``anthropic`` aren't present.
    """
    provider = settings.provider
    if provider == "dryrun":
        return DryRunProvider()
    if provider in ("openai", "azure"):
        from detection_forge.ai.openai_provider import OpenAIProvider

        return OpenAIProvider(settings)
    if provider == "anthropic":
        from detection_forge.ai.anthropic_provider import AnthropicProvider

        return AnthropicProvider(settings)
    raise ValueError(
        f"Unknown DETFORGE_AI_PROVIDER={provider!r}. "
        "Expected one of: dryrun, openai, azure, anthropic."
    )
