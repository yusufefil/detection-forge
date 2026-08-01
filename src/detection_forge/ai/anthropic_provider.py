"""Anthropic (Claude) provider, using the official ``anthropic`` SDK."""

from __future__ import annotations

from detection_forge.ai.base import AIProvider
from detection_forge.config import AISettings


class AnthropicProvider(AIProvider):
    def __init__(self, settings: AISettings) -> None:
        self._settings = settings
        try:
            from anthropic import Anthropic
        except ImportError as exc:  # pragma: no cover
            raise ImportError(
                "The 'anthropic' package is required for the anthropic provider. "
                "Install it with: pip install anthropic"
            ) from exc

        if not settings.anthropic_api_key:
            raise ValueError("ANTHROPIC_API_KEY is not set.")
        self._client = Anthropic(api_key=settings.anthropic_api_key)
        self._model = settings.anthropic_model

    def complete(self, system: str, user: str) -> str:
        # Nudge the model toward a bare JSON object by prefilling '{'.
        resp = self._client.messages.create(
            model=self._model,
            max_tokens=1500,
            temperature=0.1,
            system=system,
            messages=[
                {"role": "user", "content": user},
                {"role": "assistant", "content": "{"},
            ],
        )
        text = "".join(block.text for block in resp.content if block.type == "text")
        return "{" + text  # restore the prefilled brace
