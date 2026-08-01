"""Pluggable LLM providers (OpenAI, Azure OpenAI, Anthropic) + an offline DryRun."""

from detection_forge.ai.base import AIProvider, get_provider

__all__ = ["AIProvider", "get_provider"]
