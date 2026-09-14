from __future__ import annotations

from . import __version__
from .auth import auth_profile_metadata
from .config import AuditConfig
from .context import ScanContext
from .models import Evidence, Finding, HTTPRequestRecord, ModuleResult, ScanResult, utc_now
from .modules import (
    BasicAuthModule,
    CookiesModule,
    CrawlerModule,
    FingerprintingModule,
    HTTPMethodsModule,
    HTTPRedirectsModule,
    JavaScriptAnalysisModule,
    PortsModule,
    ScopeModule,
    SecurityHeadersModule,
    SubdomainModule,
    TLSBasicModule,
)
from .modules.base import AuditModule
from .scope import validate_target
from .planning import build_scan_plan


def run_scan(raw_target: str, config: AuditConfig) -> ScanResult:
    execution = build_scan_plan(raw_target, config)
    target = validate_target(raw_target, config.scope)
    if not config.scope.allowed_hosts:
        config.scope.allowed_hosts = [target.host]
    requests: list[HTTPRequestRecord] = []

    modules = _enabled_modules(config)
    results: list[ModuleResult] = []
    context = ScanContext(target=target, config=config, requests=requests, module_results=results)
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
        auth_profile=auth_profile_metadata(config),
        requests=requests,
        execution=execution,
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
        (config.modules.subdomains, SubdomainModule()),
        (config.modules.ports, PortsModule()),
        (config.modules.fingerprinting, FingerprintingModule()),
        (config.modules.crawler, CrawlerModule()),
        (config.modules.javascript, JavaScriptAnalysisModule()),
    ]
    return [module for enabled, module in candidates if enabled]
