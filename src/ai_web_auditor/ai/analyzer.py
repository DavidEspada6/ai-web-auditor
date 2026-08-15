from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Protocol

from ai_web_auditor import __version__
from ai_web_auditor.config import AIConfig, AuditConfig
from ai_web_auditor.errors import AIError
from ai_web_auditor.models import AIAnalysisResult, utc_now

from .openai_provider import OpenAIProvider
from .prompting import build_analysis_prompt
from .redaction import redact_scan_data


class AIProvider(Protocol):
    name: str

    def analyze(self, prompt: str, *, model: str | None = None) -> tuple[str, dict[str, Any]]:
        ...


def analyze_scan_file(
    scan_path: Path,
    config: AuditConfig,
    *,
    provider_name: str | None = None,
    model: str | None = None,
    provider: AIProvider | None = None,
    dry_run: bool = False,
) -> AIAnalysisResult:
    scan_data = json.loads(scan_path.read_text(encoding="utf-8"))
    return analyze_scan_data(
        scan_data,
        config,
        source=str(scan_path),
        provider_name=provider_name,
        model=model,
        provider=provider,
        dry_run=dry_run,
    )


def analyze_scan_data(
    scan_data: dict[str, Any],
    config: AuditConfig,
    *,
    source: str = "memory",
    provider_name: str | None = None,
    model: str | None = None,
    provider: AIProvider | None = None,
    dry_run: bool = False,
) -> AIAnalysisResult:
    sanitized = redact_scan_data(scan_data)
    ai_config = config.ai
    selected_provider = provider_name or ai_config.provider
    selected_model = model or ai_config.model
    prompt = build_analysis_prompt(
        sanitized,
        max_chars=ai_config.max_input_chars,
        language=ai_config.language,
    )

    if dry_run:
        return AIAnalysisResult(
            tool="ai-web-auditor",
            version=__version__,
            generated_at=utc_now(),
            provider=selected_provider,
            model=selected_model,
            source_file=source,
            status="dry_run",
            analysis={"prompt": prompt, "prompt_chars": len(prompt)},
            raw_text=prompt,
        )

    provider = provider or _provider_for(selected_provider, ai_config)
    raw_text, _raw_response = provider.analyze(prompt, model=selected_model)
    parsed = _parse_model_json(raw_text)
    status = "completed" if parsed else "completed_unstructured"

    return AIAnalysisResult(
        tool="ai-web-auditor",
        version=__version__,
        generated_at=utc_now(),
        provider=selected_provider,
        model=selected_model,
        source_file=source,
        status=status,
        analysis=parsed or {"text": raw_text},
        raw_text=raw_text,
    )


def _provider_for(name: str, config: AIConfig) -> AIProvider:
    normalized = name.lower()
    if normalized == "openai":
        return OpenAIProvider(config)
    raise AIError(f"Unsupported AI provider: {name}")


def _parse_model_json(text: str) -> dict[str, Any] | None:
    try:
        parsed = json.loads(text)
        return parsed if isinstance(parsed, dict) else None
    except json.JSONDecodeError:
        pass

    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end <= start:
        return None

    try:
        parsed = json.loads(text[start : end + 1])
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, dict) else None
