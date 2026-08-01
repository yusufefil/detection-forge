"""OpenAI and Azure OpenAI provider.

Both are served by the official ``openai`` SDK (>=1.0). The same class handles
plain OpenAI and Azure OpenAI; the distinction is the ``azure`` provider value,
which routes through ``AzureOpenAI`` with endpoint/deployment from settings.
"""

from __future__ import annotations

from detection_forge.ai.base import AIProvider
from detection_forge.config import AISettings


class OpenAIProvider(AIProvider):
    def __init__(self, settings: AISettings) -> None:
        self._settings = settings
        try:
            import openai  # noqa: F401
        except ImportError as exc:  # pragma: no cover
            raise ImportError(
                "The 'openai' package is required for the openai/azure providers. "
                "Install it with: pip install openai"
            ) from exc

        if settings.provider == "azure":
            self._init_azure()
        else:
            self._init_openai()

    def _init_openai(self) -> None:
        from openai import OpenAI

        if not self._settings.openai_api_key:
            raise ValueError("OPENAI_API_KEY is not set.")
        self._client = OpenAI(api_key=self._settings.openai_api_key)
        self._model = self._settings.openai_model

    def _init_azure(self) -> None:
        from openai import AzureOpenAI

        s = self._settings
        missing = [
            name
            for name, val in (
                ("AZURE_OPENAI_API_KEY", s.azure_api_key),
                ("AZURE_OPENAI_ENDPOINT", s.azure_endpoint),
                ("AZURE_OPENAI_DEPLOYMENT", s.azure_deployment),
            )
            if not val
        ]
        if missing:
            raise ValueError(f"Missing Azure OpenAI settings: {', '.join(missing)}")
        self._client = AzureOpenAI(
            api_key=s.azure_api_key,
            azure_endpoint=s.azure_endpoint,
            api_version=s.azure_api_version,
        )
        # For Azure, the "model" passed to the SDK is the *deployment* name.
        self._model = s.azure_deployment

    def complete(self, system: str, user: str) -> str:
        resp = self._client.chat.completions.create(
            model=self._model,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            temperature=0.1,
            response_format={"type": "json_object"},
        )
        return resp.choices[0].message.content or ""
