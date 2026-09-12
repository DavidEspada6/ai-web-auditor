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
class TargetConfig:
    url: str = ""


@dataclass
class ScopeConfig:
    allowed_hosts: list[str] = field(default_factory=list)
    allow_subdomains: bool = True
    allow_private_networks: bool = False
    resolve_dns: bool = True
    include_paths: list[str] = field(default_factory=lambda: ["/"])
    exclude_paths: list[str] = field(default_factory=list)


@dataclass
class HTTPConfig:
    timeout_seconds: float = 10.0
    max_redirects: int = 10
    user_agent: str = "AI-Web-Auditor/0.24"
    verify_tls: bool = True
    check_http_counterpart: bool = True


@dataclass
class AuthProfileConfig:
    id: str = "public"
    name: str = "Public"
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    notes: str = ""


@dataclass
class AuthConfig:
    active_profile: str = "public"
    profiles: list[AuthProfileConfig] = field(default_factory=lambda: [AuthProfileConfig()])


@dataclass
class EvidenceCaptureConfig:
    enabled: bool = True
    capture_request_headers: bool = True
    capture_response_headers: bool = True
    capture_response_body_sample: bool = True
    max_body_chars: int = 4000
    text_content_types: list[str] = field(
        default_factory=lambda: [
            "text/",
            "application/json",
            "application/xml",
            "application/xhtml+xml",
            "application/javascript",
            "application/x-javascript",
            "application/problem+json",
            "application/ld+json",
        ]
    )


@dataclass
class AIConfig:
    provider: str = "openai"
    model: str = "gpt-5.6"
    api_key_env: str = "OPENAI_API_KEY"
    endpoint: str = "https://api.openai.com/v1/responses"
    timeout_seconds: float = 45.0
    max_input_chars: int = 60000
    store: bool = False
    language: str = "es"


@dataclass
class FingerprintConfig:
    max_body_bytes: int = 262144
    detect_versions: bool = True
    public_paths: list[str] = field(
        default_factory=lambda: [
            "/robots.txt",
            "/.well-known/security.txt",
            "/security.txt",
            "/sitemap.xml",
        ]
    )


@dataclass
class CrawlerConfig:
    max_depth: int = 1
    max_pages: int = 25
    delay_seconds: float = 0.0
    max_body_bytes: int = 262144
    include_query_strings: bool = False
    use_robots_txt: bool = True
    use_sitemap_xml: bool = True
    use_well_known: bool = True
    follow_sitemap_urls: bool = True
    follow_robots_paths: bool = False
    metadata_max_urls: int = 100
    well_known_paths: list[str] = field(
        default_factory=lambda: [
            "/.well-known/security.txt",
            "/security.txt",
            "/.well-known/change-password",
            "/.well-known/openid-configuration",
            "/.well-known/oauth-authorization-server",
            "/.well-known/webfinger",
            "/.well-known/assetlinks.json",
            "/.well-known/apple-app-site-association",
        ]
    )
    ignored_extensions: list[str] = field(
        default_factory=lambda: [
            ".7z",
            ".avi",
            ".css",
            ".gif",
            ".gz",
            ".ico",
            ".jpeg",
            ".jpg",
            ".js",
            ".mov",
            ".mp3",
            ".mp4",
            ".pdf",
            ".png",
            ".rar",
            ".svg",
            ".tar",
            ".webm",
            ".webp",
            ".zip",
        ]
    )


@dataclass
class JavaScriptAnalysisConfig:
    max_pages: int = 10
    max_scripts: int = 25
    max_body_bytes: int = 262144
    include_inline: bool = True
    fetch_external_scripts: bool = True


@dataclass
class SubdomainConfig:
    candidates: list[str] = field(
        default_factory=lambda: [
            "www",
            "app",
            "api",
            "portal",
            "admin",
            "login",
            "dev",
            "test",
            "staging",
            "pre",
            "beta",
            "docs",
            "status",
            "cdn",
            "static",
            "assets",
            "mail",
            "vpn",
        ]
    )
    max_candidates: int = 25
    timeout_seconds: float = 2.0


@dataclass
class PortScanConfig:
    ports: list[int] = field(default_factory=lambda: [80, 443, 8080, 8443, 8000, 3000, 5000, 9000])
    max_ports: int = 20
    timeout_seconds: float = 1.0


@dataclass
class ModuleConfig:
    scope: bool = True
    http: bool = True
    security_headers: bool = True
    cookies: bool = True
    basic_auth: bool = True
    http_methods: bool = True
    tls: bool = True
    fingerprinting: bool = True
    crawler: bool = True
    javascript: bool = True
    subdomains: bool = False
    ports: bool = False


@dataclass
class AuditConfig:
    target: TargetConfig = field(default_factory=TargetConfig)
    scope: ScopeConfig = field(default_factory=ScopeConfig)
    http: HTTPConfig = field(default_factory=HTTPConfig)
    ai: AIConfig = field(default_factory=AIConfig)
    fingerprinting: FingerprintConfig = field(default_factory=FingerprintConfig)
    crawler: CrawlerConfig = field(default_factory=CrawlerConfig)
    javascript: JavaScriptAnalysisConfig = field(default_factory=JavaScriptAnalysisConfig)
    subdomains: SubdomainConfig = field(default_factory=SubdomainConfig)
    ports: PortScanConfig = field(default_factory=PortScanConfig)
    auth: AuthConfig = field(default_factory=AuthConfig)
    evidence: EvidenceCaptureConfig = field(default_factory=EvidenceCaptureConfig)
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

    def write_json(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_dict(), indent=2, ensure_ascii=True) + "\n", encoding="utf-8")


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
