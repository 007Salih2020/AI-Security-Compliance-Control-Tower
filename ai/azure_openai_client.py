from __future__ import annotations

import json
from typing import Any, Type

from pydantic import BaseModel

from app.config import get_settings

try:
    from openai import AzureOpenAI
except ImportError:  # pragma: no cover - optional at runtime
    AzureOpenAI = None


class AzureOpenAIWrapper:
    def __init__(self) -> None:
        self.settings = get_settings()
        self.client = None
        if (
            AzureOpenAI is not None
            and self.settings.azure_openai_endpoint
            and self.settings.azure_openai_api_key
            and self.settings.azure_openai_deployment
        ):
            self.client = AzureOpenAI(
                api_key=self.settings.azure_openai_api_key,
                azure_endpoint=self.settings.azure_openai_endpoint,
                api_version=self.settings.azure_openai_api_version,
            )

    def available(self) -> bool:
        return self.client is not None

    def generate_structured(self, prompt: str, response_model: Type[BaseModel]) -> BaseModel:
        if not self.available():
            raise RuntimeError("Azure OpenAI is not configured.")

        response = self.client.chat.completions.create(
            model=self.settings.azure_openai_deployment,
            temperature=0.1,
            response_format={"type": "json_object"},
            messages=[
                {"role": "system", "content": "Return valid JSON only."},
                {"role": "user", "content": prompt},
            ],
        )
        payload: Any = json.loads(response.choices[0].message.content or "{}")
        return response_model.model_validate(payload)
