from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any

from ai_web_auditor.config import AIConfig
from ai_web_auditor.errors import AIError


class OpenAIProvider:
    name = "openai"

    def __init__(self, config: AIConfig) -> None:
        self.config = config

    def analyze(self, prompt: str, *, model: str | None = None) -> tuple[str, dict[str, Any]]:
        api_key = os.environ.get(self.config.api_key_env)
        if not api_key:
            raise AIError(f"Missing API key. Set environment variable {self.config.api_key_env}")

        payload = {
            "model": model or self.config.model,
            "input": prompt,
            "store": self.config.store,
        }
        request = urllib.request.Request(
            self.config.endpoint,
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
                "User-Agent": "AI-Web-Auditor/0.4",
            },
            method="POST",
        )

        try:
            with urllib.request.urlopen(request, timeout=self.config.timeout_seconds) as response:
                body = response.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise AIError(f"OpenAI API request failed with HTTP {exc.code}: {detail}") from exc
        except urllib.error.URLError as exc:
            raise AIError(f"OpenAI API request failed: {exc.reason}") from exc

        data = json.loads(body)
        return _extract_output_text(data), data


def _extract_output_text(response: dict[str, Any]) -> str:
    output_text = response.get("output_text")
    if isinstance(output_text, str):
        return output_text

    chunks: list[str] = []
    for item in response.get("output", []):
        if not isinstance(item, dict):
            continue
        for content in item.get("content", []):
            if not isinstance(content, dict):
                continue
            text = content.get("text")
            if isinstance(text, str):
                chunks.append(text)
    if chunks:
        return "\n".join(chunks)

    raise AIError("OpenAI response did not include text output")
