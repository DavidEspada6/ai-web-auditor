from __future__ import annotations

from . import __version__
from .config import AuditConfig
from .context import ScanContext
from .models import Evidence, Finding, HTTPRequestRecord, ModuleResult, ScanResult, utc_now
from .modules import (
    BasicAuthModule,
    CookiesModule,
    HTTPMethodsModule,
    HTTPRedirectsModule,
    ScopeModule,
    SecurityHeadersModule,
    TLSBasicModule,
)
from .modules.base import AuditModule
from .scope import validate_target


def run_scan(raw_target: str, config: AuditConfig) -> ScanResult:
    target = validate_target(raw_target, config.scope)
    requests: list[HTTPRequestRecord] = []

    modules = _enabled_modules(config)
    results: list[ModuleResult] = []
    context = ScanContext(target=target, config=config, requests=requests)
    for module in modules:
        try:
            results.append(module.run(context))
        except Exception as exc:  # Defensive isolation between modules.
            results.append(
                ModuleResult(
                    name=module.name,
                    status="error",
                    summary=f"Module {module.name} failed unexpectedly.",
                    findings=[
                        Finding(
                            id=f"MODULE-{module.name.upper()}-FAILED",
                            title=f"Module {module.name} failed",
                            severity="info",
                            category="tooling",
                            description="The audit module raised an unexpected error and was isolated from the rest of the scan.",
                            recommendation="Run with the same target again and inspect the module error.",
                            module=module.name,
                            target=target.normalized_url,
                            evidence=[Evidence("error", f"{exc.__class__.__name__}: {exc}")],
                        )
                    ],
                )
            )

    status = "completed_with_errors" if any(item.status == "error" for item in results) else "completed"
    return ScanResult(
        tool="ai-web-auditor",
        version=__version__,
        generated_at=utc_now(),
        status=status,
        target=target,
        modules=results,
        requests=requests,
    )


def _enabled_modules(config: AuditConfig) -> list[AuditModule]:
    candidates: list[tuple[bool, AuditModule]] = [
        (config.modules.scope, ScopeModule()),
        (config.modules.http, HTTPRedirectsModule()),
        (config.modules.security_headers, SecurityHeadersModule()),
        (config.modules.cookies, CookiesModule()),
        (config.modules.basic_auth, BasicAuthModule()),
        (config.modules.http_methods, HTTPMethodsModule()),
        (config.modules.tls, TLSBasicModule()),
    ]
    return [module for enabled, module in candidates if enabled]
