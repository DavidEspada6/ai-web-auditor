from __future__ import annotations

from ai_web_auditor.context import ScanContext
from ai_web_auditor.errors import ProbeError
from ai_web_auditor.http_probe import SimpleResponse
from ai_web_auditor.models import Evidence, Finding, ModuleResult


RISKY_METHODS = {
    "TRACE": ("high", "TRACE can expose request data and is rarely needed."),
    "CONNECT": ("high", "CONNECT is normally only expected on explicit proxies."),
    "PUT": ("medium", "PUT may allow content upload if authorization is weak."),
    "DELETE": ("medium", "DELETE may allow destructive actions if authorization is weak."),
}


class HTTPMethodsModule:
    name = "http_methods"

    def run(self, context: ScanContext) -> ModuleResult:
        if context.final_response is None and context.response_error:
            return ModuleResult(
                name=self.name,
                status="skipped",
                summary="HTTP methods check skipped because no HTTP response is available.",
                artifacts={"error": context.response_error},
            )

        try:
            options_url = context.final_response.url if context.final_response is not None else context.target.normalized_url
            response = context.probe.request("OPTIONS", options_url, follow_redirects=False)
        except ProbeError as exc:
            return ModuleResult(
                name=self.name,
                status="error",
                summary="OPTIONS request failed.",
                artifacts={"error": str(exc)},
            )

        methods = _extract_methods(response)
        findings: list[Finding] = []
        for method in sorted(methods):
            if method not in RISKY_METHODS:
                continue
            severity, description = RISKY_METHODS[method]
            findings.append(
                Finding(
                    id=f"METHOD-{method}-ADVERTISED",
                    title=f"HTTP method {method} is advertised",
                    severity=severity,
                    category="http-methods",
                    description=description,
                    recommendation="Disable unnecessary HTTP methods or enforce strict authorization before use.",
                    module=self.name,
                    target=response.url,
                    evidence=[
                        Evidence("allow", response.get_header("allow", "missing") or "missing"),
                        Evidence("access-control-allow-methods", response.get_header("access-control-allow-methods", "missing") or "missing"),
                    ],
                )
            )

        return ModuleResult(
            name=self.name,
            status="warning" if findings else "passed",
            summary="HTTP methods advertised by OPTIONS checked.",
            findings=findings,
            artifacts={
                "status_code": response.status_code,
                "allow": response.get_header("allow"),
                "access_control_allow_methods": response.get_header("access-control-allow-methods"),
                "methods": sorted(methods),
            },
        )


def _extract_methods(response: SimpleResponse) -> set[str]:
    values = [
        response.get_header("allow", "") or "",
        response.get_header("access-control-allow-methods", "") or "",
    ]
    methods: set[str] = set()
    for value in values:
        for item in value.split(","):
            method = item.strip().upper()
            if method:
                methods.add(method)
    return methods
