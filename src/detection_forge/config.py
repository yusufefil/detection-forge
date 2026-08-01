"""Runtime configuration, driven entirely by environment variables.

Nothing here is hard-coded to a single vendor. The toolkit ships defaulting to
the ``dryrun`` provider so it runs (and CI passes) with zero credentials. To use
a real model, set ``DETFORGE_AI_PROVIDER`` and the matching key(s).

    OpenAI:      DETFORGE_AI_PROVIDER=openai   OPENAI_API_KEY=...   [OPENAI_MODEL=gpt-4o-mini]
    Azure OpenAI:DETFORGE_AI_PROVIDER=azure    AZURE_OPENAI_API_KEY=...
                 AZURE_OPENAI_ENDPOINT=https://<resource>.openai.azure.com
                 AZURE_OPENAI_DEPLOYMENT=<deployment-name>
                 [AZURE_OPENAI_API_VERSION=2024-06-01]
    Anthropic:   DETFORGE_AI_PROVIDER=anthropic ANTHROPIC_API_KEY=...
                 [ANTHROPIC_MODEL=claude-sonnet-4-20250514]
"""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class AISettings:
    provider: str
    openai_api_key: str | None
    openai_model: str
    azure_api_key: str | None
    azure_endpoint: str | None
    azure_deployment: str | None
    azure_api_version: str
    anthropic_api_key: str | None
    anthropic_model: str


def load_ai_settings() -> AISettings:
    """Read AI settings from the environment (and a local .env if present)."""
    _load_dotenv()
    return AISettings(
        provider=os.getenv("DETFORGE_AI_PROVIDER", "dryrun").strip().lower(),
        openai_api_key=os.getenv("OPENAI_API_KEY"),
        openai_model=os.getenv("OPENAI_MODEL", "gpt-4o-mini"),
        azure_api_key=os.getenv("AZURE_OPENAI_API_KEY"),
        azure_endpoint=os.getenv("AZURE_OPENAI_ENDPOINT"),
        azure_deployment=os.getenv("AZURE_OPENAI_DEPLOYMENT"),
        azure_api_version=os.getenv("AZURE_OPENAI_API_VERSION", "2024-06-01"),
        anthropic_api_key=os.getenv("ANTHROPIC_API_KEY"),
        anthropic_model=os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-20250514"),
    )


def _load_dotenv(path: str = ".env") -> None:
    """Minimal .env loader so we don't depend on python-dotenv.

    Lines of the form ``KEY=value`` are loaded into ``os.environ`` unless the
    key is already set (real environment variables win over the file).
    """
    if not os.path.isfile(path):
        return
    with open(path, "r", encoding="utf-8") as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key, value = key.strip(), value.strip().strip('"').strip("'")
            os.environ.setdefault(key, value)
