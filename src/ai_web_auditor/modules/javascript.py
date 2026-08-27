from __future__ import annotations

import hashlib
import posixpath
import re
from html.parser import HTMLParser
from typing import Any
from urllib.parse import parse_qsl, urldefrag, urljoin, urlsplit, urlunsplit

from ai_web_auditor.context import ScanContext
from ai_web_auditor.errors import ProbeError
from ai_web_auditor.evidence import sanitize_url
from ai_web_auditor.models import Evidence, Finding, ModuleResult
from ai_web_auditor.routes import classify_url, route_types
from ai_web_auditor.scope import is_host_allowed, is_path_allowed


STRING_LITERAL_RE = re.compile(
    r"""(?P<quote>["'`])(?P<value>(?:\\.|(?! (?P=quote)).){1,700})(?P=quote)""".replace(" ", ""),
    flags=re.DOTALL,
)
ABSOLUTE_URL_RE = re.compile(r"https?://[^\s\"'`<>(){}\[\]]+", flags=re.IGNORECASE)
PROTOCOL_RELATIVE_RE = re.compile(r"//[A-Za-z0-9.-]+(?::\d+)?/[^\s\"'`<>(){}\[\]]*")
ROOT_PATH_RE = re.compile(r"(?<![:/])/[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{1,650}")
RELATIVE_ENDPOINT_RE = re.compile(
    r"\b(?:api|graphql|rest|v\d+|login|logout|signin|auth|oauth|sso|session|account|profile|users?|members?|admin|"
    r"reset|forgot|recover|upload|download|search|status|health|callback|webhook)"
    r"(?:/[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]*)?(?:\?[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+)?",
    flags=re.IGNORECASE,
)
METHOD_VALUE_RE = re.compile(r"\bmethod\s*:\s*['\"]?(GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)['\"]?", flags=re.IGNORECASE)
CALL_METHOD_RE = re.compile(r"\b(?:axios|client|api|\$)\.(get|post|put|patch|delete)\s*\(\s*$", flags=re.IGNORECASE)
FETCH_RE = re.compile(r"\bfetch\s*\(\s*$", flags=re.IGNORECASE)

STATIC_EXTENSIONS = {
    ".avif",
    ".css",
    ".gif",
    ".ico",
    ".jpeg",
    ".jpg",
    ".map",
    ".mp3",
    ".mp4",
    ".pdf",
    ".png",
    ".svg",
    ".webm",
    ".webp",
    ".woff",
    ".woff2",
}
SENSITIVE_PARAMETER_MARKERS = ("auth", "csrf", "key", "pass", "secret", "session", "sid", "token")


class JavaScriptAnalysisModule:
    name = "javascript"

    def run(self, context: ScanContext) -> ModuleResult:
        config = context.config.javascript
        page_urls = _candidate_page_urls(context)[: config.max_pages]
        findings: list[Finding] = []
        pages_checked: list[dict[str, Any]] = []
        script_urls: list[dict[str, Any]] = []
        scripts: list[dict[str, Any]] = []
        discovered: dict[str, dict[str, Any]] = {}
        out_of_scope: dict[str, dict[str, Any]] = {}
        excluded: dict[str, dict[str, Any]] = {}
        request_errors: list[dict[str, str]] = []
        ignored_candidates_count = 0
        seen_scripts: set[str] = set()
        script_budget_used = 0
        limit_reached = False

        if not page_urls:
            return ModuleResult(
                name=self.name,
                status="skipped",
                summary="JavaScript analysis skipped because no page URL is available.",
                artifacts={"max_pages": config.max_pages, "max_scripts": config.max_scripts},
            )

        for page_url in page_urls:
            try:
                response = context.probe.request("GET", page_url, follow_redirects=False, max_body_bytes=config.max_body_bytes)
            except ProbeError as exc:
                request_errors.append({"url": page_url, "kind": "page", "error": str(exc)})
                pages_checked.append({"url": sanitize_url(page_url), "status": "error", "error": str(exc)})
                continue

            content_type = response.get_header("content-type", "") or ""
            body = _decode_body(response.body, content_type)
            document = _ScriptExtractor.extract(body, page_url) if _is_html(content_type) else {"external": [], "inline": []}
            page_entry = {
                "url": sanitize_url(page_url),
                "status_code": response.status_code,
                "content_type": content_type,
                "body_truncated": response.body_truncated,
                "external_scripts": len(document["external"]),
                "inline_scripts": len(document["inline"]),
                "scripts_found": len(document["external"]) + len(document["inline"]),
            }
            pages_checked.append(page_entry)

            if config.fetch_external_scripts:
                for raw_src in document["external"]:
                    normalized_script_url, reason = _normalize_resource_url(page_url, raw_src, context)
                    script_display_url = sanitize_url(normalized_script_url or urljoin(page_url, raw_src))
                    if not normalized_script_url:
                        script_urls.append({"url": script_display_url, "page_url": sanitize_url(page_url), "status": reason or "skipped"})
                        continue
                    if normalized_script_url in seen_scripts:
                        script_urls.append({"url": script_display_url, "page_url": sanitize_url(page_url), "status": "duplicate"})
                        continue
                    if script_budget_used >= config.max_scripts:
                        script_urls.append({"url": script_display_url, "page_url": sanitize_url(page_url), "status": "limit"})
                        limit_reached = True
                        continue

                    seen_scripts.add(normalized_script_url)
                    script_budget_used += 1
                    script_urls.append({"url": script_display_url, "page_url": sanitize_url(page_url), "status": "in_scope"})
                    script, ignored = _fetch_and_analyze_script(
                        context,
                        normalized_script_url,
                        page_url,
                        discovered,
                        out_of_scope,
                        excluded,
                    )
                    ignored_candidates_count += ignored
                    scripts.append(script)
                    if script.get("error"):
                        request_errors.append({"url": script_display_url, "kind": "script", "error": str(script["error"])})

            if not config.include_inline:
                continue
            for inline_index, inline in enumerate(document["inline"], start=1):
                source = str(inline.get("body") or "")
                if not source.strip():
                    continue
                if script_budget_used >= config.max_scripts:
                    limit_reached = True
                    continue
                script_budget_used += 1
                script_id = f"inline-{len(scripts) + 1:04d}"
                endpoint_count_before = len(discovered)
                ignored_candidates_count += _analyze_javascript_source(
                    source,
                    page_url,
                    context,
                    discovered,
                    out_of_scope,
                    excluded,
                    script_url="",
                    source_kind="inline_script",
                )
                scripts.append(
                    {
                        "id": script_id,
                        "kind": "inline",
                        "page_url": sanitize_url(page_url),
                        "sha256": hashlib.sha256(source.encode("utf-8", errors="ignore")).hexdigest(),
                        "bytes": len(source.encode("utf-8", errors="ignore")),
                        "endpoints_found": max(0, len(discovered) - endpoint_count_before),
                    }
                )

        discovered_endpoints = _finalize_endpoints(discovered)
        out_of_scope_endpoints = _finalize_endpoints(out_of_scope)
        excluded_endpoints = _finalize_endpoints(excluded)
        sensitive_endpoints = [item for item in discovered_endpoints if item.get("sensitive_parameter_names")]

        if discovered_endpoints:
            findings.append(
                Finding(
                    id="JS-ENDPOINTS-DISCOVERED",
                    title="JavaScript endpoint references discovered",
                    severity="info",
                    category="javascript-enumeration",
                    description="Client-side JavaScript contains URL references that expand the passive review surface.",
                    recommendation="Review these endpoints against the authorized scope before deciding whether later validation is needed.",
                    module=self.name,
                    target=context.target.normalized_url,
                    evidence=[Evidence("endpoint", _endpoint_evidence(item)) for item in discovered_endpoints[:5]],
                )
            )

        if sensitive_endpoints:
            findings.append(
                Finding(
                    id="JS-SENSITIVE-PARAMETER-NAMES",
                    title="JavaScript references sensitive-looking parameter names",
                    severity="info",
                    category="javascript-enumeration",
                    description="Some JavaScript-discovered URLs contain parameter names commonly associated with authentication, sessions or secrets. Values are redacted.",
                    recommendation="Review how these parameters are generated, logged and exposed. Do not include raw secrets in reports.",
                    module=self.name,
                    target=context.target.normalized_url,
                    evidence=[Evidence("parameter_name", ", ".join(item["sensitive_parameter_names"]), item["url"]) for item in sensitive_endpoints[:5]],
                )
            )

        if out_of_scope_endpoints:
            findings.append(
                Finding(
                    id="JS-OUT-OF-SCOPE-ENDPOINTS",
                    title="JavaScript references endpoints outside scope",
                    severity="info",
                    category="javascript-enumeration",
                    description="Client-side JavaScript references hosts outside the configured scope. They were recorded but not requested.",
                    recommendation="Confirm whether those hosts belong to the engagement before scanning them.",
                    module=self.name,
                    target=context.target.normalized_url,
                    evidence=[Evidence("endpoint", item["url"]) for item in out_of_scope_endpoints[:5]],
                )
            )

        if limit_reached:
            findings.append(
                Finding(
                    id="JS-SCRIPT-LIMIT-REACHED",
                    title="JavaScript analysis script limit reached",
                    severity="info",
                    category="javascript-enumeration",
                    description="JavaScript analysis stopped before every discovered script could be analyzed because the configured script limit was reached.",
                    recommendation="Increase javascript.max_scripts only when the wider enumeration is authorized and useful.",
                    module=self.name,
                    target=context.target.normalized_url,
                    evidence=[Evidence("max_scripts", str(config.max_scripts))],
                )
            )

        if request_errors:
            findings.append(
                Finding(
                    id="JS-SCRIPT-REQUEST-ERRORS",
                    title="JavaScript analysis encountered request errors",
                    severity="info",
                    category="javascript-enumeration",
                    description="Some in-scope pages or scripts could not be retrieved for passive JavaScript analysis.",
                    recommendation="Review the errors and repeat with adjusted timeout or scope only if needed.",
                    module=self.name,
                    target=context.target.normalized_url,
                    evidence=[Evidence("error_url", item["url"], item.get("error", "")) for item in request_errors[:5]],
                )
            )

        status = "warning" if request_errors or limit_reached else "passed"
        return ModuleResult(
            name=self.name,
            status=status,
            summary=(
                f"Analyzed {len(pages_checked)} page(s) and {len(scripts)} script block(s), "
                f"discovered {len(discovered_endpoints)} in-scope endpoint reference(s)."
            ),
            findings=findings,
            artifacts={
                "max_pages": config.max_pages,
                "max_scripts": config.max_scripts,
                "include_inline": config.include_inline,
                "fetch_external_scripts": config.fetch_external_scripts,
                "pages_checked": pages_checked,
                "script_urls": script_urls,
                "scripts": scripts,
                "discovered_endpoints": discovered_endpoints,
                "out_of_scope_endpoints": out_of_scope_endpoints,
                "excluded_endpoints": excluded_endpoints,
                "ignored_candidates_count": ignored_candidates_count,
                "limit_reached": limit_reached,
            },
        )


def _fetch_and_analyze_script(
    context: ScanContext,
    script_url: str,
    page_url: str,
    discovered: dict[str, dict[str, Any]],
    out_of_scope: dict[str, dict[str, Any]],
    excluded: dict[str, dict[str, Any]],
) -> tuple[dict[str, Any], int]:
    try:
        response = context.probe.request("GET", script_url, follow_redirects=False, max_body_bytes=context.config.javascript.max_body_bytes)
    except ProbeError as exc:
        return (
            {
                "id": _script_id(script_url),
                "kind": "external",
                "url": sanitize_url(script_url),
                "page_url": sanitize_url(page_url),
                "status": "error",
                "error": str(exc),
                "endpoints_found": 0,
            },
            0,
        )

    content_type = response.get_header("content-type", "") or ""
    body = _decode_body(response.body, content_type)
    endpoint_count_before = len(discovered)
    ignored = _analyze_javascript_source(
        body,
        page_url,
        context,
        discovered,
        out_of_scope,
        excluded,
        script_url=script_url,
        source_kind="external_script",
        page_url=page_url,
    )
    return (
        {
            "id": _script_id(script_url),
            "kind": "external",
            "url": sanitize_url(script_url),
            "page_url": sanitize_url(page_url),
            "status_code": response.status_code,
            "content_type": content_type,
            "sha256": hashlib.sha256(response.body).hexdigest() if response.body else "",
            "bytes": len(response.body),
            "body_truncated": response.body_truncated,
            "endpoints_found": max(0, len(discovered) - endpoint_count_before),
        },
        ignored,
    )


def _analyze_javascript_source(
    source: str,
    base_url: str,
    context: ScanContext,
    discovered: dict[str, dict[str, Any]],
    out_of_scope: dict[str, dict[str, Any]],
    excluded: dict[str, dict[str, Any]],
    *,
    script_url: str,
    source_kind: str,
    page_url: str = "",
) -> int:
    ignored = 0
    seen_literals: set[tuple[str, int]] = set()
    for match in STRING_LITERAL_RE.finditer(source):
        literal = _decode_js_literal(match.group("value")).strip()
        if not literal or (literal, match.start()) in seen_literals:
            continue
        seen_literals.add((literal, match.start()))
        line = source.count("\n", 0, match.start()) + 1
        method = _infer_method(source, match.start(), match.end())
        for candidate in _candidate_values(literal):
            normalized, reason = _normalize_endpoint_candidate(base_url, candidate, context)
            if not normalized:
                if reason == "out_of_scope":
                    _add_endpoint(out_of_scope, urljoin(base_url, candidate), candidate, method, line, source_kind, script_url, page_url, reason)
                elif reason == "excluded_path":
                    _add_endpoint(excluded, urljoin(base_url, candidate), candidate, method, line, source_kind, script_url, page_url, reason)
                else:
                    ignored += 1
                continue
            _add_endpoint(discovered, normalized, candidate, method, line, source_kind, script_url, page_url, "in_scope")
    return ignored


def _add_endpoint(
    bucket: dict[str, dict[str, Any]],
    url: str,
    raw_value: str,
    method: str,
    line: int,
    source_kind: str,
    script_url: str,
    page_url: str,
    status: str,
) -> None:
    safe_url = sanitize_url(url)
    method = method.upper() if method else ""
    parameters = _query_parameter_names(url)
    classifications = classify_url(safe_url, methods=[method] if method else [])
    endpoint = bucket.setdefault(
        safe_url,
        {
            "url": safe_url,
            "status": status,
            "methods": set(),
            "raw_values": set(),
            "sources": set(),
            "script_urls": set(),
            "page_urls": set(),
            "line_numbers": set(),
            "parameter_names": set(),
            "sensitive_parameter_names": set(),
            "route_classifications": classifications,
            "route_types": set(route_types(classifications)),
        },
    )
    if method:
        endpoint["methods"].add(method)
        endpoint["route_types"].update(route_types(classify_url(safe_url, methods=list(endpoint["methods"]))))
    endpoint["raw_values"].add(_sanitize_raw_value(raw_value, url))
    endpoint["sources"].add(source_kind)
    if script_url:
        endpoint["script_urls"].add(sanitize_url(script_url))
    if page_url:
        endpoint["page_urls"].add(sanitize_url(page_url))
    if line:
        endpoint["line_numbers"].add(line)
    endpoint["parameter_names"].update(parameters)
    endpoint["sensitive_parameter_names"].update(name for name in parameters if _is_sensitive_parameter(name))


def _finalize_endpoints(items: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    for item in items.values():
        row = dict(item)
        methods = sorted(row.pop("methods"))
        row["methods"] = methods
        row["method"] = ", ".join(methods)
        row["raw_values"] = sorted(row.pop("raw_values"))[:10]
        row["sources"] = sorted(row.pop("sources"))
        row["script_urls"] = sorted(row.pop("script_urls"))
        row["page_urls"] = sorted(row.pop("page_urls"))
        row["line_numbers"] = sorted(row.pop("line_numbers"))[:25]
        row["parameter_names"] = sorted(row.pop("parameter_names"))
        row["sensitive_parameter_names"] = sorted(row.pop("sensitive_parameter_names"))
        row["route_types"] = sorted(row.pop("route_types"))
        output.append(row)
    output.sort(key=lambda item: (item.get("status") != "in_scope", item.get("url", ""), item.get("method", "")))
    return output


def _candidate_page_urls(context: ScanContext) -> list[str]:
    urls: list[str] = []
    for result in context.module_results:
        if result.name != "crawler" or not isinstance(result.artifacts, dict):
            continue
        for page in _dict_list(result.artifacts.get("pages")):
            url = _clean(page.get("url"))
            if not url or page.get("error"):
                continue
            content_type = _clean(page.get("content_type"))
            if _is_html(content_type):
                urls.append(url)
        for url in _string_list(result.artifacts.get("fetched_urls")):
            urls.append(url)

    if context.final_response is not None and _is_html(context.final_response.get_header("content-type", "") or ""):
        urls.insert(0, context.final_response.url)
    urls.append(context.target.normalized_url)

    output: list[str] = []
    seen: set[str] = set()
    for url in urls:
        normalized, reason = _normalize_resource_url(context.target.normalized_url, url, context)
        if not normalized or reason:
            continue
        if normalized in seen:
            continue
        seen.add(normalized)
        output.append(normalized)
    return output


def _candidate_values(literal: str) -> list[str]:
    candidates: list[str] = []
    stripped = literal.strip()
    if _looks_like_endpoint(stripped):
        candidates.append(stripped)
    elif "://" in stripped:
        candidates.extend(match.group(0) for match in ABSOLUTE_URL_RE.finditer(stripped))
        candidates.extend(match.group(0) for match in PROTOCOL_RELATIVE_RE.finditer(stripped))
    else:
        for pattern in [PROTOCOL_RELATIVE_RE, ROOT_PATH_RE, RELATIVE_ENDPOINT_RE]:
            candidates.extend(match.group(0) for match in pattern.finditer(stripped))
    output: list[str] = []
    seen: set[str] = set()
    for candidate in candidates:
        clean = _clean_candidate(candidate)
        if not clean or clean in seen:
            continue
        seen.add(clean)
        output.append(clean)
    return output


def _normalize_endpoint_candidate(base_url: str, value: str, context: ScanContext) -> tuple[str | None, str]:
    if not value or any(marker in value for marker in ("${", "<%", "{{", "}}")):
        return None, "template"
    if value.startswith(("mailto:", "tel:", "javascript:", "data:", "#")):
        return None, "unsupported_scheme"
    absolute_url = _absolute_url(base_url, value)
    parsed = urlsplit(urldefrag(absolute_url)[0])
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return None, "invalid_url"
    if _has_static_extension(parsed.path):
        return None, "static_asset"
    if not is_host_allowed(parsed.hostname, context.config.scope, default_host=context.target.host):
        return None, "out_of_scope"
    if not is_path_allowed(parsed.path or "/", context.config.scope):
        return None, "excluded_path"
    return _canonical_url(urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.query, ""))), "in_scope"


def _normalize_resource_url(base_url: str, value: str, context: ScanContext) -> tuple[str | None, str]:
    absolute_url = _absolute_url(base_url, value)
    parsed = urlsplit(urldefrag(absolute_url)[0])
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return None, "invalid_url"
    if not is_host_allowed(parsed.hostname, context.config.scope, default_host=context.target.host):
        return None, "out_of_scope"
    if not is_path_allowed(parsed.path or "/", context.config.scope):
        return None, "excluded_path"
    return _canonical_url(urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.query, ""))), ""


def _absolute_url(base_url: str, value: str) -> str:
    clean = value.strip()
    if clean.startswith("//"):
        scheme = urlsplit(base_url).scheme or "https"
        return f"{scheme}:{clean}"
    return urljoin(base_url, clean)


def _canonical_url(url: str) -> str:
    parsed = urlsplit(urldefrag(url)[0])
    host = (parsed.hostname or "").strip().rstrip(".").lower()
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        pass
    display_host = f"[{host}]" if ":" in host else host
    default_port = 443 if parsed.scheme == "https" else 80
    netloc = f"{display_host}:{parsed.port}" if parsed.port and parsed.port != default_port else display_host
    path = posixpath.normpath(parsed.path or "/")
    if not path.startswith("/"):
        path = f"/{path}"
    if parsed.path.endswith("/") and not path.endswith("/"):
        path = f"{path}/"
    return urlunsplit((parsed.scheme.lower(), netloc, path, parsed.query, ""))


def _infer_method(source: str, start: int, end: int) -> str:
    prefix = source[max(0, start - 100) : start]
    suffix = source[end : min(len(source), end + 180)]
    call_match = CALL_METHOD_RE.search(prefix)
    if call_match:
        method = call_match.group(1).upper()
        return "GET" if method == "GET" else method
    if FETCH_RE.search(prefix):
        same_call = suffix.split(")", 1)[0]
        method_match = METHOD_VALUE_RE.search(same_call)
        if method_match:
            return method_match.group(1).upper()
        return "GET"
    return ""


def _endpoint_evidence(item: dict[str, Any]) -> str:
    method = item.get("method")
    return f"{method} {item['url']}" if method else str(item["url"])


def _query_parameter_names(url: str) -> list[str]:
    return sorted({key for key, _value in parse_qsl(urlsplit(url).query, keep_blank_values=True) if key})


def _sanitize_raw_value(raw_value: str, url: str) -> str:
    raw_value = raw_value.strip()[:700]
    if "?" not in raw_value:
        return raw_value
    safe = sanitize_url(url)
    parsed = urlsplit(safe)
    if raw_value.startswith(("http://", "https://", "//")):
        return safe
    return urlunsplit(("", "", parsed.path, parsed.query, ""))


def _decode_js_literal(value: str) -> str:
    value = value.replace("\\/", "/")

    def unicode_replace(match: re.Match[str]) -> str:
        try:
            return chr(int(match.group(1), 16))
        except ValueError:
            return match.group(0)

    value = re.sub(r"\\u([0-9a-fA-F]{4})", unicode_replace, value)
    value = re.sub(r"\\x([0-9a-fA-F]{2})", unicode_replace, value)
    return value


def _clean_candidate(value: str) -> str:
    return value.strip().rstrip(".,;:)")


def _looks_like_endpoint(value: str) -> bool:
    stripped = value.strip()
    if len(stripped) < 2 or any(char.isspace() for char in stripped):
        return False
    lowered = stripped.lower()
    return (
        lowered.startswith(("http://", "https://", "//", "/"))
        or RELATIVE_ENDPOINT_RE.fullmatch(stripped) is not None
    )


def _has_static_extension(path: str) -> bool:
    lowered = path.lower()
    return any(lowered.endswith(extension) for extension in STATIC_EXTENSIONS)


def _is_sensitive_parameter(name: str) -> bool:
    lowered = name.lower()
    return any(marker in lowered for marker in SENSITIVE_PARAMETER_MARKERS)


def _is_html(content_type: str) -> bool:
    if not content_type:
        return True
    lowered = content_type.lower()
    return "text/html" in lowered or "application/xhtml+xml" in lowered


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


def _script_id(script_url: str) -> str:
    digest = hashlib.sha1(script_url.encode("utf-8", errors="ignore")).hexdigest()[:12]
    return f"js_{digest}"


def _dict_list(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [_clean(item) for item in value if _clean(item)]


def _clean(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


class _ScriptExtractor(HTMLParser):
    def __init__(self, base_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.external: list[str] = []
        self.inline: list[dict[str, str]] = []
        self._in_script = False
        self._script_parts: list[str] = []

    @classmethod
    def extract(cls, html: str, base_url: str) -> dict[str, list[Any]]:
        parser = cls(base_url)
        parser.feed(html)
        parser.close()
        if parser._in_script:
            parser._finish_inline_script()
        return {"external": parser.external, "inline": parser.inline}

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() != "script":
            return
        attr_map = {key.lower(): (value or "") for key, value in attrs}
        src = attr_map.get("src", "").strip()
        if src:
            self.external.append(src)
            return
        self._in_script = True
        self._script_parts = []

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "script" and self._in_script:
            self._finish_inline_script()

    def handle_data(self, data: str) -> None:
        if self._in_script:
            self._script_parts.append(data)

    def _finish_inline_script(self) -> None:
        body = "".join(self._script_parts)
        if body.strip():
            self.inline.append({"body": body})
        self._script_parts = []
        self._in_script = False
