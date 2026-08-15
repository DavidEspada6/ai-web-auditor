from __future__ import annotations

from ai_web_auditor.context import ScanContext
from ai_web_auditor.errors import ProbeError
from ai_web_auditor.models import Evidence, Finding, ModuleResult


class SecurityHeadersModule:
    name = "security_headers"

    def run(self, context: ScanContext) -> ModuleResult:
        response = context.final_response
        if response is None and context.response_error:
            return ModuleResult(
                name=self.name,
                status="skipped",
                summary="Security header check skipped because no HTTP response is available.",
                artifacts={"error": context.response_error},
            )

        if response is None:
            try:
                response = context.probe.request("GET", context.target.normalized_url, follow_redirects=False)
                context.final_response = response
            except ProbeError as exc:
                return ModuleResult(
                    name=self.name,
                    status="error",
                    summary="Could not retrieve headers.",
                    artifacts={"error": str(exc)},
                )

        headers = response.headers_dict()
        findings: list[Finding] = []
        url = response.url
        is_https = response.scheme == "https"
        csp = headers.get("content-security-policy", "")

        if is_https:
            hsts = headers.get("strict-transport-security")
            if not hsts:
                findings.append(_missing_header("Strict-Transport-Security", "medium", self.name, url))
            elif _hsts_max_age(hsts) < 15552000:
                findings.append(
                    Finding(
                        id="HEADER-HSTS-MAX-AGE-LOW",
                        title="HSTS max-age is low",
                        severity="low",
                        category="security-headers",
                        description="The HSTS header is present but its max-age is lower than 180 days.",
                        recommendation="Use an HSTS max-age of at least 15552000 seconds after HTTPS is stable.",
                        module=self.name,
                        target=url,
                        evidence=[Evidence("strict-transport-security", hsts)],
                    )
                )

        if not csp:
            findings.append(_missing_header("Content-Security-Policy", "medium", self.name, url))

        if "x-frame-options" not in headers and "frame-ancestors" not in csp.lower():
            findings.append(
                Finding(
                    id="HEADER-CLICKJACKING-MISSING",
                    title="Clickjacking protection header is missing",
                    severity="low",
                    category="security-headers",
                    description="The response does not include X-Frame-Options or a CSP frame-ancestors directive.",
                    recommendation="Set frame-ancestors in Content-Security-Policy or use X-Frame-Options where appropriate.",
                    module=self.name,
                    target=url,
                )
            )

        xcto = headers.get("x-content-type-options", "")
        if xcto.lower() != "nosniff":
            findings.append(
                Finding(
                    id="HEADER-NOSNIFF-MISSING",
                    title="X-Content-Type-Options nosniff is missing",
                    severity="low",
                    category="security-headers",
                    description="The browser may try to infer content types when nosniff is absent.",
                    recommendation="Set X-Content-Type-Options: nosniff.",
                    module=self.name,
                    target=url,
                    evidence=[Evidence("x-content-type-options", xcto or "missing")],
                )
            )

        if "referrer-policy" not in headers:
            findings.append(_missing_header("Referrer-Policy", "low", self.name, url))

        if "permissions-policy" not in headers:
            findings.append(_missing_header("Permissions-Policy", "info", self.name, url))

        relevant_headers = {
            key: headers[key]
            for key in sorted(headers)
            if key
            in {
                "content-security-policy",
                "permissions-policy",
                "referrer-policy",
                "strict-transport-security",
                "x-content-type-options",
                "x-frame-options",
            }
        }

        return ModuleResult(
            name=self.name,
            status="warning" if findings else "passed",
            summary="Security headers checked.",
            findings=findings,
            artifacts={"headers": relevant_headers},
        )


def _missing_header(header: str, severity: str, module: str, target: str) -> Finding:
    header_id = header.upper().replace("-", "_")
    return Finding(
        id=f"HEADER-{header_id}-MISSING",
        title=f"{header} header is missing",
        severity=severity,
        category="security-headers",
        description=f"The response does not include the {header} header.",
        recommendation=f"Define an appropriate {header} header for this application.",
        module=module,
        target=target,
    )


def _hsts_max_age(value: str) -> int:
    for item in value.split(";"):
        item = item.strip()
        if item.lower().startswith("max-age="):
            try:
                return int(item.split("=", 1)[1])
            except ValueError:
                return 0
    return 0
