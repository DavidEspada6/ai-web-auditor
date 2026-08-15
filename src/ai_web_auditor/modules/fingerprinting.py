from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urljoin

from ai_web_auditor.context import ScanContext
from ai_web_auditor.errors import ProbeError
from ai_web_auditor.http_probe import SimpleResponse
from ai_web_auditor.models import Evidence, Finding, ModuleResult
from ai_web_auditor.scope import is_url_allowed


@dataclass
class TechnologySignal:
    name: str
    category: str
    confidence: str
    signals: set[str] = field(default_factory=set)
    version: str | None = None

    def to_dict(self) -> dict[str, object]:
        data: dict[str, object] = {
            "name": self.name,
            "category": self.category,
            "confidence": self.confidence,
            "signals": sorted(self.signals),
        }
        if self.version:
            data["version"] = self.version
        return data


class FingerprintingModule:
    name = "fingerprinting"

    def run(self, context: ScanContext) -> ModuleResult:
        if context.final_response is None and context.response_error:
            return ModuleResult(
                name=self.name,
                status="skipped",
                summary="Fingerprinting skipped because no HTTP response is available.",
                artifacts={"error": context.response_error},
            )

        seed_url = context.final_response.url if context.final_response is not None else context.target.normalized_url
        technologies: dict[str, TechnologySignal] = {}
        findings: list[Finding] = []
        public_files: list[dict[str, object]] = []

        main_response = self._get_main_page(context, seed_url)
        if main_response is None:
            return ModuleResult(
                name=self.name,
                status="error",
                summary="Could not retrieve the target page for fingerprinting.",
                artifacts={"url": seed_url},
            )

        headers = main_response.headers_dict()
        cookie_headers = main_response.get_headers("set-cookie")
        html = _decode_body(main_response.body, main_response.get_header("content-type", "") or "")

        _detect_from_headers(headers, technologies)
        _detect_from_cookies(cookie_headers, technologies)
        _detect_from_html(html, technologies)
        _detect_from_public_files(context, seed_url, technologies, public_files)
        _add_disclosure_findings(self.name, main_response.url, headers, html, findings, context.config.fingerprinting.detect_versions)

        return ModuleResult(
            name=self.name,
            status="warning" if findings else "passed",
            summary=f"Identified {len(technologies)} technology signal(s) and checked {len(public_files)} public metadata path(s).",
            findings=findings,
            artifacts={
                "url": main_response.url,
                "technologies": [item.to_dict() for item in sorted(technologies.values(), key=lambda tech: tech.name.lower())],
                "public_files": public_files,
                "headers": {
                    key: value
                    for key, value in headers.items()
                    if key
                    in {
                        "server",
                        "x-powered-by",
                        "x-generator",
                        "x-aspnet-version",
                        "x-aspnetmvc-version",
                        "via",
                    }
                },
            },
        )

    def _get_main_page(self, context: ScanContext, url: str) -> SimpleResponse | None:
        try:
            return context.probe.request(
                "GET",
                url,
                follow_redirects=False,
                max_body_bytes=context.config.fingerprinting.max_body_bytes,
            )
        except ProbeError:
            return context.final_response


def _detect_from_headers(headers: dict[str, str], technologies: dict[str, TechnologySignal]) -> None:
    server = headers.get("server", "")
    if server:
        _add_known_server(server, technologies)

    powered_by = headers.get("x-powered-by", "")
    if powered_by:
        _add_known_powered_by(powered_by, technologies)

    generator = headers.get("x-generator", "")
    if generator:
        _add_from_generator(generator, technologies, "header:x-generator")

    if "x-aspnet-version" in headers or "x-aspnetmvc-version" in headers:
        _add_technology(technologies, "ASP.NET", "framework", "high", "header:aspnet")

    via = headers.get("via", "")
    if via:
        _add_technology(technologies, "HTTP proxy", "proxy", "medium", "header:via")

    cdn_signals = {
        "cf-ray": ("Cloudflare", "cdn"),
        "cf-cache-status": ("Cloudflare", "cdn"),
        "x-vercel-id": ("Vercel", "hosting"),
        "x-amz-cf-id": ("Amazon CloudFront", "cdn"),
        "x-amz-cf-pop": ("Amazon CloudFront", "cdn"),
        "x-served-by": ("Fastly", "cdn"),
        "x-cache-hits": ("Fastly", "cdn"),
        "x-azure-ref": ("Microsoft Azure", "hosting"),
        "x-github-request-id": ("GitHub Pages", "hosting"),
    }
    for header, (name, category) in cdn_signals.items():
        if header in headers:
            _add_technology(technologies, name, category, "high", f"header:{header}")


def _detect_from_cookies(cookie_headers: list[str], technologies: dict[str, TechnologySignal]) -> None:
    cookie_blob = "\n".join(cookie_headers).lower()
    cookie_signals = {
        "phpsessid": ("PHP", "language"),
        "laravel_session": ("Laravel", "framework"),
        "xsrf-token": ("Laravel", "framework"),
        "jsessionid": ("Java", "language"),
        "asp.net_sessionid": ("ASP.NET", "framework"),
        "csrftoken": ("Django", "framework"),
        "sessionid": ("Django", "framework"),
        "connect.sid": ("Express", "framework"),
        "_rails_session": ("Ruby on Rails", "framework"),
        "wordpress_logged_in": ("WordPress", "cms"),
        "wp-settings": ("WordPress", "cms"),
    }
    for marker, (name, category) in cookie_signals.items():
        if marker in cookie_blob:
            _add_technology(technologies, name, category, "medium", f"cookie:{marker}")


def _detect_from_html(html: str, technologies: dict[str, TechnologySignal]) -> None:
    lowered = html.lower()
    generator = _find_meta_generator(html)
    if generator:
        _add_from_generator(generator, technologies, "html:meta-generator")

    html_signals = {
        "wp-content/": ("WordPress", "cms", "high"),
        "wp-includes/": ("WordPress", "cms", "high"),
        "drupal-settings-json": ("Drupal", "cms", "high"),
        "/sites/default/": ("Drupal", "cms", "medium"),
        "content=\"joomla!": ("Joomla", "cms", "high"),
        "/media/system/js/": ("Joomla", "cms", "medium"),
        "id=\"__next_data__": ("Next.js", "framework", "high"),
        "data-reactroot": ("React", "javascript-framework", "medium"),
        "ng-version": ("Angular", "javascript-framework", "high"),
        "data-v-": ("Vue.js", "javascript-framework", "low"),
    }
    for marker, (name, category, confidence) in html_signals.items():
        if marker in lowered:
            _add_technology(technologies, name, category, confidence, f"html:{marker}")


def _detect_from_public_files(
    context: ScanContext,
    seed_url: str,
    technologies: dict[str, TechnologySignal],
    public_files: list[dict[str, object]],
) -> None:
    for path in context.config.fingerprinting.public_paths:
        file_url = urljoin(seed_url, path)
        if not is_url_allowed(file_url, context.config.scope, default_host=context.target.host):
            public_files.append({"path": path, "url": file_url, "status": "skipped_out_of_scope"})
            continue

        try:
            response = context.probe.request(
                "GET",
                file_url,
                follow_redirects=False,
                max_body_bytes=context.config.fingerprinting.max_body_bytes,
            )
        except ProbeError as exc:
            public_files.append({"path": path, "url": file_url, "status": "error", "error": str(exc)})
            continue

        body = _decode_body(response.body, response.get_header("content-type", "") or "")
        entry: dict[str, object] = {
            "path": path,
            "url": file_url,
            "status_code": response.status_code,
            "content_type": response.get_header("content-type"),
            "present": 200 <= response.status_code < 300,
            "body_truncated": response.body_truncated,
        }
        if path.endswith("robots.txt") and entry["present"]:
            entry["directives"] = _parse_robots(body)
        if path.endswith("security.txt") and entry["present"]:
            entry["fields"] = _parse_security_txt(body)
        if path.endswith("sitemap.xml") and entry["present"]:
            entry["url_count"] = len(re.findall(r"<loc\b", body, flags=re.IGNORECASE))
        public_files.append(entry)

        if path.endswith("robots.txt") and "wp-admin" in body.lower():
            _add_technology(technologies, "WordPress", "cms", "low", "robots:wp-admin")


def _add_disclosure_findings(
    module: str,
    target: str,
    headers: dict[str, str],
    html: str,
    findings: list[Finding],
    detect_versions: bool,
) -> None:
    server = headers.get("server", "")
    if server and detect_versions and _has_version(server):
        findings.append(
            Finding(
                id="FINGERPRINT-SERVER-VERSION-DISCLOSED",
                title="Server header discloses version information",
                severity="info",
                category="fingerprinting",
                description="The Server header appears to include product version information.",
                recommendation="Avoid exposing precise server versions unless there is an operational reason.",
                module=module,
                target=target,
                evidence=[Evidence("server", server)],
            )
        )

    powered_by = headers.get("x-powered-by", "")
    if powered_by:
        findings.append(
            Finding(
                id="FINGERPRINT-POWERED-BY-DISCLOSED",
                title="X-Powered-By header discloses technology information",
                severity="info",
                category="fingerprinting",
                description="The X-Powered-By header can reveal backend technology details to attackers.",
                recommendation="Remove or reduce technology-identifying response headers where practical.",
                module=module,
                target=target,
                evidence=[Evidence("x-powered-by", powered_by)],
            )
        )

    generator = _find_meta_generator(html)
    if generator and detect_versions:
        findings.append(
            Finding(
                id="FINGERPRINT-GENERATOR-DISCLOSED",
                title="HTML generator metadata is exposed",
                severity="info",
                category="fingerprinting",
                description="The HTML generator metadata can disclose CMS or framework details.",
                recommendation="Remove generator metadata if it is not required.",
                module=module,
                target=target,
                evidence=[Evidence("generator", generator)],
            )
        )


def _add_known_server(server: str, technologies: dict[str, TechnologySignal]) -> None:
    lowered = server.lower()
    known_servers = {
        "nginx": "nginx",
        "apache": "Apache HTTP Server",
        "microsoft-iis": "Microsoft IIS",
        "cloudflare": "Cloudflare",
        "openresty": "OpenResty",
        "caddy": "Caddy",
    }
    for marker, name in known_servers.items():
        if marker in lowered:
            _add_technology(technologies, name, "server", "high", "header:server", _extract_version(server, marker))
            return
    _add_technology(technologies, server.split()[0], "server", "low", "header:server")


def _add_known_powered_by(powered_by: str, technologies: dict[str, TechnologySignal]) -> None:
    lowered = powered_by.lower()
    known = {
        "php": ("PHP", "language"),
        "express": ("Express", "framework"),
        "asp.net": ("ASP.NET", "framework"),
        "next.js": ("Next.js", "framework"),
        "nuxt": ("Nuxt", "framework"),
    }
    for marker, (name, category) in known.items():
        if marker in lowered:
            _add_technology(technologies, name, category, "high", "header:x-powered-by", _extract_version(powered_by, marker))
            return
    _add_technology(technologies, powered_by, "framework", "low", "header:x-powered-by")


def _add_from_generator(value: str, technologies: dict[str, TechnologySignal], signal: str) -> None:
    lowered = value.lower()
    known = {
        "wordpress": ("WordPress", "cms"),
        "drupal": ("Drupal", "cms"),
        "joomla": ("Joomla", "cms"),
        "shopify": ("Shopify", "cms"),
        "wix": ("Wix", "site-builder"),
    }
    for marker, (name, category) in known.items():
        if marker in lowered:
            _add_technology(technologies, name, category, "high", signal, _extract_version(value, marker))
            return
    _add_technology(technologies, value, "generator", "low", signal)


def _add_technology(
    technologies: dict[str, TechnologySignal],
    name: str,
    category: str,
    confidence: str,
    signal: str,
    version: str | None = None,
) -> None:
    key = name.lower()
    existing = technologies.get(key)
    if existing is None:
        existing = TechnologySignal(name=name, category=category, confidence=confidence)
        technologies[key] = existing

    existing.signals.add(signal)
    if version and not existing.version:
        existing.version = version
    if _confidence_rank(confidence) > _confidence_rank(existing.confidence):
        existing.confidence = confidence


def _confidence_rank(confidence: str) -> int:
    return {"low": 1, "medium": 2, "high": 3}.get(confidence, 0)


def _find_meta_generator(html: str) -> str | None:
    match = re.search(
        r"<meta\b(?=[^>]*\bname=[\"']?generator[\"']?)(?=[^>]*\bcontent=[\"']([^\"']+)[\"'])[^>]*>",
        html,
        flags=re.IGNORECASE,
    )
    return match.group(1).strip() if match else None


def _has_version(value: str) -> bool:
    return bool(re.search(r"\b\d+(?:\.\d+){1,3}\b", value))


def _extract_version(value: str, marker: str) -> str | None:
    pattern = re.escape(marker).replace("\\-", "[- ]")
    match = re.search(pattern + r"[/ ]?([0-9]+(?:\.[0-9A-Za-z_-]+){0,3})", value, flags=re.IGNORECASE)
    return match.group(1) if match else None


def _parse_robots(body: str) -> dict[str, list[str]]:
    directives: dict[str, list[str]] = {}
    for raw_line in body.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line or ":" not in line:
            continue
        key, value = line.split(":", 1)
        normalized_key = key.strip().lower()
        directives.setdefault(normalized_key, []).append(value.strip())
    return directives


def _parse_security_txt(body: str) -> dict[str, list[str]]:
    allowed_fields = {"contact", "expires", "encryption", "acknowledgments", "preferred-languages", "canonical", "policy", "hiring"}
    fields: dict[str, list[str]] = {}
    for raw_line in body.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line or ":" not in line:
            continue
        key, value = line.split(":", 1)
        normalized_key = key.strip().lower()
        if normalized_key in allowed_fields:
            fields.setdefault(normalized_key, []).append(value.strip())
    return fields


def _decode_body(body: bytes, content_type: str) -> str:
    if not body:
        return ""
    charset = "utf-8"
    for item in content_type.split(";"):
        item = item.strip()
        if item.lower().startswith("charset="):
            charset = item.split("=", 1)[1].strip() or charset
            break
    try:
        return body.decode(charset, errors="replace")
    except LookupError:
        return body.decode("utf-8", errors="replace")
