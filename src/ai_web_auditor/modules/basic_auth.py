from __future__ import annotations

import re

from ai_web_auditor.context import ScanContext
from ai_web_auditor.errors import ProbeError
from ai_web_auditor.models import Evidence, Finding, ModuleResult


class BasicAuthModule:
    name = "basic_auth"

    def run(self, context: ScanContext) -> ModuleResult:
        response = context.final_response
        if response is None and context.response_error:
            return ModuleResult(
                name=self.name,
                status="skipped",
                summary="Basic Auth check skipped because no HTTP response is available.",
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
                    summary="Could not check authentication challenge.",
                    artifacts={"error": str(exc)},
                )

        findings: list[Finding] = []
        challenges = []
        for item in [*response.history, response]:
            for header in item.get_headers("www-authenticate"):
                if not _contains_basic(header):
                    continue
                challenges.append({"url": item.url, "status_code": item.status_code, "www_authenticate": header})
                findings.append(
                    Finding(
                        id="AUTH-BASIC-OVER-HTTP" if item.scheme == "http" else "AUTH-BASIC-DETECTED",
                        title="HTTP Basic Authentication over HTTP" if item.scheme == "http" else "HTTP Basic Authentication detected",
                        severity="high" if item.scheme == "http" else "info",
                        category="authentication",
                        description=(
                            "The server requests Basic Authentication over unencrypted HTTP."
                            if item.scheme == "http"
                            else "The server requests HTTP Basic Authentication. This is mainly risky when used without TLS."
                        ),
                        recommendation=(
                            "Force HTTPS before authentication and enable HSTS after validation."
                            if item.scheme == "http"
                            else "Keep Basic Authentication behind HTTPS and avoid reusing sensitive credentials."
                        ),
                        module=self.name,
                        target=item.url,
                        evidence=[
                            Evidence("status_code", str(item.status_code)),
                            Evidence("www-authenticate", header),
                        ],
                    )
                )

        return ModuleResult(
            name=self.name,
            status="warning" if any(f.severity == "high" for f in findings) else "passed",
            summary="HTTP authentication challenge checked.",
            findings=findings,
            artifacts={"challenges": challenges},
        )


def _contains_basic(header: str) -> bool:
    return bool(re.search(r"(^|,|\s)basic(\s|$)", header, flags=re.IGNORECASE))
