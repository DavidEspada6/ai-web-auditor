from __future__ import annotations

from urllib.parse import urljoin, urlsplit, urlunsplit

from ai_web_auditor.context import ScanContext
from ai_web_auditor.errors import ProbeError
from ai_web_auditor.http_probe import SimpleResponse
from ai_web_auditor.models import Evidence, Finding, ModuleResult
from ai_web_auditor.scope import is_host_allowed, is_path_allowed


REDIRECT_STATUSES = {301, 302, 303, 307, 308}


class HTTPRedirectsModule:
    name = "http"

    def run(self, context: ScanContext) -> ModuleResult:
        findings: list[Finding] = []
        artifacts: dict[str, object] = {}

        try:
            response, blocked_redirect_url = _request_following_scope(context, "GET", context.target.normalized_url)
        except ProbeError as exc:
            context.response_error = str(exc)
            return ModuleResult(
                name=self.name,
                status="error",
                summary="Initial HTTP request failed.",
                findings=[
                    Finding(
                        id="HTTP-REQUEST-FAILED",
                        title="Initial HTTP request failed",
                        severity="info",
                        category="availability",
                        description="The target could not be reached with the configured HTTP client.",
                        recommendation="Confirm the target is reachable and that the URL is correct.",
                        module=self.name,
                        target=context.target.normalized_url,
                        evidence=[Evidence("error", str(exc))],
                    )
                ],
            )

        context.final_response = response
        chain = _redirect_chain(response)
        artifacts["initial_status_code"] = response.history[0].status_code if response.history else response.status_code
        artifacts["final_status_code"] = response.status_code
        artifacts["final_url"] = response.url
        artifacts["redirect_chain"] = chain
        if blocked_redirect_url:
            artifacts["blocked_redirect_url"] = blocked_redirect_url
            findings.append(
                Finding(
                    id="HTTP-REDIRECT-OUT-OF-SCOPE",
                    title="Redirect points outside the configured scope",
                    severity="medium",
                    category="redirects",
                    description="The target returned a redirect to a host outside the configured audit scope. The redirect was recorded but not followed.",
                    recommendation="Confirm whether the redirected host should be included in the authorized scope before scanning it.",
                    module=self.name,
                    target=context.target.normalized_url,
                    evidence=[Evidence("blocked_redirect_url", blocked_redirect_url)],
                )
            )

        initial_scheme = context.target.scheme
        final_scheme = response.scheme
        blocked_scheme = urlsplit(blocked_redirect_url).scheme if blocked_redirect_url else None
        if initial_scheme == "http" and final_scheme != "https" and blocked_scheme != "https":
            findings.append(
                Finding(
                    id="HTTP-NO-HTTPS-REDIRECT",
                    title="HTTP is not redirected to HTTPS",
                    severity="high",
                    category="transport-security",
                    description="The requested HTTP URL remains available without being upgraded to HTTPS.",
                    recommendation="Redirect all HTTP traffic to HTTPS and consider enabling HSTS after verification.",
                    module=self.name,
                    target=context.target.normalized_url,
                    evidence=[
                        Evidence("initial_url", context.target.normalized_url),
                        Evidence("final_url", response.url),
                        Evidence("status_code", str(response.status_code)),
                    ],
                )
            )

        if response.host and response.host.lower() != context.target.host.lower():
            findings.append(
                Finding(
                    id="HTTP-CROSS-HOST-REDIRECT",
                    title="Redirect leaves the original host",
                    severity="low",
                    category="redirects",
                    description="The redirect chain finishes on a host different from the configured target host.",
                    recommendation="Confirm this redirect is intended and covered by the authorized audit scope.",
                    module=self.name,
                    target=context.target.normalized_url,
                    evidence=[
                        Evidence("original_host", context.target.host),
                        Evidence("final_host", response.host or ""),
                    ],
                )
            )

        if context.config.http.check_http_counterpart and context.target.scheme == "https":
            artifacts["http_counterpart"] = self._check_http_counterpart(context, findings)

        status = "warning" if findings else "passed"
        return ModuleResult(
            name=self.name,
            status=status,
            summary="HTTP/HTTPS reachability and redirects checked.",
            findings=findings,
            artifacts=artifacts,
        )

    def _check_http_counterpart(self, context: ScanContext, findings: list[Finding]) -> dict[str, object]:
        url = _with_scheme(context.target.normalized_url, "http")
        try:
            response, blocked_redirect_url = _request_following_scope(context, "GET", url)
        except ProbeError as exc:
            return {"url": url, "reachable": False, "error": str(exc)}

        artifact = {
            "url": url,
            "reachable": True,
            "status_code": response.status_code,
            "final_url": response.url,
            "redirect_chain": _redirect_chain(response),
        }
        if blocked_redirect_url:
            artifact["blocked_redirect_url"] = blocked_redirect_url
            findings.append(
                Finding(
                    id="HTTP-COUNTERPART-REDIRECT-OUT-OF-SCOPE",
                    title="HTTP counterpart redirects outside scope",
                    severity="medium",
                    category="redirects",
                    description="The HTTP version redirects to a host outside the configured scope. The redirect was not followed.",
                    recommendation="Confirm whether the redirected host should be included in the authorized scope before scanning it.",
                    module=self.name,
                    target=url,
                    evidence=[Evidence("blocked_redirect_url", blocked_redirect_url)],
                )
            )

        blocked_scheme = urlsplit(blocked_redirect_url).scheme if blocked_redirect_url else None
        if response.status_code < 400 and response.scheme != "https" and blocked_scheme != "https":
            findings.append(
                Finding(
                    id="HTTP-COUNTERPART-OPEN",
                    title="HTTP endpoint is reachable without HTTPS upgrade",
                    severity="high",
                    category="transport-security",
                    description="The HTTP version of the target responds successfully and does not redirect to HTTPS.",
                    recommendation="Redirect HTTP to HTTPS for the same host and path.",
                    module=self.name,
                    target=url,
                    evidence=[
                        Evidence("final_url", response.url),
                        Evidence("status_code", str(response.status_code)),
                    ],
                )
            )
        return artifact


def _request_following_scope(
    context: ScanContext,
    method: str,
    url: str,
) -> tuple[SimpleResponse, str | None]:
    history: list[SimpleResponse] = []
    current_url = url
    current_method = method

    for _ in range(context.config.http.max_redirects + 1):
        response = context.probe.request(current_method, current_url, follow_redirects=False)
        if response.status_code not in REDIRECT_STATUSES:
            response.history = history
            return response, None

        location = response.get_header("location")
        if not location:
            response.history = history
            return response, None

        next_url = urljoin(current_url, location)
        parsed = urlsplit(next_url)
        if parsed.scheme not in {"http", "https"}:
            response.history = history
            return response, next_url
        if parsed.hostname and not is_host_allowed(parsed.hostname, context.config.scope, default_host=context.target.host):
            response.history = history
            return response, next_url
        if not is_path_allowed(parsed.path or "/", context.config.scope):
            response.history = history
            return response, next_url

        history.append(response)
        current_url = next_url
        if response.status_code == 303:
            current_method = "GET"

    raise ProbeError(f"Too many redirects after {context.config.http.max_redirects} hops")


def _redirect_chain(response: SimpleResponse) -> list[dict[str, object]]:
    chain = []
    for item in response.history:
        chain.append(
            {
                "status_code": item.status_code,
                "url": item.url,
                "location": item.get_header("location"),
            }
        )
    chain.append({"status_code": response.status_code, "url": response.url, "location": None})
    return chain


def _with_scheme(url: str, scheme: str) -> str:
    parsed = urlsplit(url)
    netloc = parsed.netloc
    if parsed.port in {80, 443}:
        host = parsed.hostname or parsed.netloc
        netloc = host if ":" not in host else f"[{host}]"
    return urlunsplit((scheme, netloc, parsed.path or "/", parsed.query, ""))
