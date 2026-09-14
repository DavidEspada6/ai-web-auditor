from __future__ import annotations

from copy import deepcopy
from typing import Any

from .auth import active_auth_profile, auth_profile_metadata
from .config import AuditConfig
from .evidence import sanitize_url
from .scope import validate_target


def build_scan_plan(raw_target: str, config: AuditConfig) -> dict[str, Any]:
    """Validate configuration without DNS, HTTP, TLS or TCP connections."""
    config.validate()
    if config.auth.active_profile != "public" and active_auth_profile(config) is None:
        raise ValueError(f"auth.active_profile: unknown profile {config.auth.active_profile}")
    scope = deepcopy(config.scope)
    scope.resolve_dns = False
    target = validate_target(raw_target, scope)
    settings = config.to_dict()
    return {
        "target": sanitize_url(target.normalized_url),
        "allowed_hosts": list(scope.allowed_hosts) or [target.host],
        "include_paths": list(scope.include_paths) or ["/"],
        "exclude_paths": list(scope.exclude_paths),
        "allow_subdomains": scope.allow_subdomains,
        "allow_private_networks": scope.allow_private_networks,
        "resolve_dns": config.scope.resolve_dns,
        "modules": [name for name, enabled in settings["modules"].items() if enabled],
        "http": {
            "timeout_seconds": config.http.timeout_seconds,
            "max_redirects": config.http.max_redirects,
            "verify_tls": config.http.verify_tls,
            "check_http_counterpart": config.http.check_http_counterpart,
        },
        "crawler": {
            **settings["crawler"],
            "enabled": config.modules.crawler,
        },
        "javascript": {
            **settings["javascript"],
            "enabled": config.modules.javascript,
        },
        "subdomains": {
            **settings["subdomains"],
            "enabled": config.modules.subdomains,
        },
        "ports": {
            "enabled": config.modules.ports,
            "max_ports": config.ports.max_ports,
            "ports": list(dict.fromkeys(config.ports.ports))[:config.ports.max_ports],
            "timeout_seconds": config.ports.timeout_seconds,
        },
        "auth_profile": auth_profile_metadata(config),
        "fingerprinting": settings["fingerprinting"],
        "evidence": settings["evidence"],
        "validation": "offline",
        "notes": [
            "La resolucion DNS y la disponibilidad se comprueban al ejecutar.",
            "Los limites de paginas y scripts son por modulo; no son un presupuesto total de peticiones.",
        ],
    }
