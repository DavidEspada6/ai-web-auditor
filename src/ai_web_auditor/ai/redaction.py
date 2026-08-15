from __future__ import annotations

import re
from typing import Any


SENSITIVE_EXACT_KEYS = {
    "api_key",
    "apikey",
    "authorization",
    "cookie",
    "password",
    "secret",
    "session",
    "set-cookie",
    "token",
}

SENSITIVE_KEY_SUFFIXES = (
    "_api_key",
    "_apikey",
    "_authorization",
    "_cookie",
    "_password",
    "_secret",
    "_session",
    "_token",
)

SENSITIVE_QUERY_RE = re.compile(
    r"([?&](?:api[_-]?key|auth|access[_-]?token|password|secret|session|token)=)([^&#\s]+)",
    flags=re.IGNORECASE,
)


def redact_scan_data(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            str(key): "[REDACTED]" if _is_sensitive_key(str(key)) else redact_scan_data(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact_scan_data(item) for item in value]
    if isinstance(value, str):
        return redact_text(value)
    return value


def redact_text(value: str) -> str:
    return SENSITIVE_QUERY_RE.sub(r"\1[REDACTED]", value)


def _is_sensitive_key(key: str) -> bool:
    normalized = key.lower().replace(" ", "_")
    return normalized in SENSITIVE_EXACT_KEYS or normalized.endswith(SENSITIVE_KEY_SUFFIXES)
