from __future__ import annotations

from http.cookies import CookieError, SimpleCookie

from ai_web_auditor.context import ScanContext
from ai_web_auditor.errors import ProbeError
from ai_web_auditor.models import Evidence, Finding, ModuleResult


class CookiesModule:
    name = "cookies"

    def run(self, context: ScanContext) -> ModuleResult:
        response = context.final_response
        if response is None and context.response_error:
            return ModuleResult(
                name=self.name,
                status="skipped",
                summary="Cookie check skipped because no HTTP response is available.",
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
                    summary="Could not retrieve cookies.",
                    artifacts={"error": str(exc)},
                )

        raw_cookies = response.get_headers("set-cookie")
        if not raw_cookies:
            return ModuleResult(
                name=self.name,
                status="passed",
                summary="No Set-Cookie headers found in the audited response.",
                artifacts={"cookies": []},
            )

        findings: list[Finding] = []
        parsed: list[dict[str, object]] = []
        for raw_cookie in raw_cookies:
            try:
                cookie = SimpleCookie()
                cookie.load(raw_cookie)
            except CookieError:
                findings.append(
                    Finding(
                        id="COOKIE-PARSE-FAILED",
                        title="Cookie header could not be parsed",
                        severity="info",
                        category="cookies",
                        description="A Set-Cookie header could not be parsed with the standard cookie parser.",
                        recommendation="Review the cookie syntax manually.",
                        module=self.name,
                        target=response.url,
                        evidence=[Evidence("set-cookie", raw_cookie)],
                    )
                )
                continue

            for morsel in cookie.values():
                cookie_info = {
                    "name": morsel.key,
                    "secure": bool(morsel["secure"]),
                    "httponly": bool(morsel["httponly"]),
                    "samesite": morsel["samesite"] or None,
                    "path": morsel["path"] or None,
                    "domain": morsel["domain"] or None,
                }
                parsed.append(cookie_info)
                self._inspect_cookie(response.url, response.scheme == "https", morsel, findings)

        return ModuleResult(
            name=self.name,
            status="warning" if findings else "passed",
            summary=f"Checked {len(parsed)} cookie(s).",
            findings=findings,
            artifacts={"cookies": parsed},
        )

    def _inspect_cookie(self, target: str, is_https: bool, morsel, findings: list[Finding]) -> None:
        name = morsel.key
        if is_https and not morsel["secure"]:
            findings.append(
                Finding(
                    id="COOKIE-SECURE-MISSING",
                    title="Cookie missing Secure flag",
                    severity="medium",
                    category="cookies",
                    description="A cookie set over HTTPS is missing the Secure flag.",
                    recommendation="Set the Secure flag on cookies that should only travel over HTTPS.",
                    module=self.name,
                    target=target,
                    evidence=[Evidence("cookie", name)],
                )
            )

        if not morsel["httponly"]:
            findings.append(
                Finding(
                    id="COOKIE-HTTPONLY-MISSING",
                    title="Cookie missing HttpOnly flag",
                    severity="low",
                    category="cookies",
                    description="A cookie is accessible to client-side scripts when HttpOnly is absent.",
                    recommendation="Set HttpOnly for session or sensitive cookies.",
                    module=self.name,
                    target=target,
                    evidence=[Evidence("cookie", name)],
                )
            )

        samesite = morsel["samesite"]
        if not samesite:
            findings.append(
                Finding(
                    id="COOKIE-SAMESITE-MISSING",
                    title="Cookie missing SameSite attribute",
                    severity="low",
                    category="cookies",
                    description="A cookie does not declare a SameSite policy.",
                    recommendation="Set SameSite=Lax or SameSite=Strict unless cross-site usage is required.",
                    module=self.name,
                    target=target,
                    evidence=[Evidence("cookie", name)],
                )
            )
        elif samesite.lower() == "none" and not morsel["secure"]:
            findings.append(
                Finding(
                    id="COOKIE-SAMESITE-NONE-WITHOUT-SECURE",
                    title="Cookie uses SameSite=None without Secure",
                    severity="medium",
                    category="cookies",
                    description="SameSite=None cookies should also use Secure.",
                    recommendation="Set Secure or avoid SameSite=None if cross-site usage is not required.",
                    module=self.name,
                    target=target,
                    evidence=[Evidence("cookie", name)],
                )
            )
