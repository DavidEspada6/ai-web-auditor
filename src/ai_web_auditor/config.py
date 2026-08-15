from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field, is_dataclass
from pathlib import Path
from typing import Any

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python < 3.11 fallback path.
    tomllib = None  # type: ignore[assignment]


@dataclass
class ScopeConfig:
    allowed_hosts: list[str] = field(default_factory=list)
    allow_subdomains: bool = True
    allow_private_networks: bool = False
    resolve_dns: bool = True


@dataclass
class HTTPConfig:
    timeout_seconds: float = 10.0
    max_redirects: int = 10
    user_agent: str = "AI-Web-Auditor/0.1"
    verify_tls: bool = True
    check_http_counterpart: bool = True


@dataclass
class ModuleConfig:
    scope: bool = True
    http: bool = True
    security_headers: bool = True
    cookies: bool = True
    basic_auth: bool = True
    http_methods: bool = True
    tls: bool = True


@dataclass
class AuditConfig:
    scope: ScopeConfig = field(default_factory=ScopeConfig)
    http: HTTPConfig = field(default_factory=HTTPConfig)
    modules: ModuleConfig = field(default_factory=ModuleConfig)

    @classmethod
    def load(cls, path: Path | None = None) -> "AuditConfig":
        config = cls()
        if path is None:
            return config

        data = _load_mapping(path)
        _merge_dataclass(config, data)
        return config

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _load_mapping(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")

    raw = path.read_text(encoding="utf-8")
    if not raw.strip():
        return {}

    suffix = path.suffix.lower()
    if suffix == ".json":
        data = json.loads(raw)
    elif suffix == ".toml":
        if tomllib is None:
            raise ValueError("TOML config requires Python 3.11 or newer; use JSON on Python 3.10")
        data = tomllib.loads(raw)
    else:
        raise ValueError("Config file must be .json or .toml")

    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ValueError("Config root must be an object")
    return data


def _merge_dataclass(instance: object, values: dict[str, Any]) -> None:
    for key, value in values.items():
        if not hasattr(instance, key):
            raise ValueError(f"Unknown config key: {key}")

        current = getattr(instance, key)
        if is_dataclass(current) and isinstance(value, dict):
            _merge_dataclass(current, value)
        else:
            setattr(instance, key, value)
