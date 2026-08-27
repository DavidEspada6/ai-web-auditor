from __future__ import annotations

import posixpath
import json
import re
import time
from collections import deque
from html.parser import HTMLParser
from xml.etree import ElementTree
from urllib.parse import urldefrag, urljoin, urlsplit, urlunsplit

from ai_web_auditor.context import ScanContext
from ai_web_auditor.errors import ProbeError
from ai_web_auditor.models import Evidence, Finding, ModuleResult
from ai_web_auditor.routes import classify_url, route_types
from ai_web_auditor.scope import is_host_allowed, is_path_allowed, is_url_allowed


REDIRECT_STATUSES = {301, 302, 303, 307, 308}


class CrawlerModule:
    name = "crawler"

    def run(self, context: ScanContext) -> ModuleResult:
        if context.final_response is None and context.response_error:
            return ModuleResult(
                name=self.name,
                status="skipped",
                summary="Crawler skipped because no HTTP response is available.",
                artifacts={"error": context.response_error},
            )

        config = context.config.crawler
        seed_url = context.final_response.url if context.final_response is not None else context.target.normalized_url
        seed_url = _normalize_url(seed_url, context)
        if seed_url is None:
            return ModuleResult(
                name=self.name,
                status="skipped",
                summary="Crawler skipped because the seed URL is outside scope.",
                artifacts={"seed_url": context.target.normalized_url},
            )

        findings: list[Finding] = []
        pages: list[dict[str, object]] = []
        discovered_urls: set[str] = {seed_url}
        fetched_urls: set[str] = set()
        queued_urls: set[str] = {seed_url}
        out_of_scope_urls: set[str] = set()
        excluded_urls: set[str] = set()
        ignored_urls: set[str] = set()
        metadata_discovered_urls: set[str] = set()
        url_sources: dict[str, set[str]] = {seed_url: {"seed"}}
        queue: deque[tuple[str, int]] = deque([(seed_url, 0)])
        metadata = self._collect_metadata(
            context,
            seed_url,
            discovered_urls,
            metadata_discovered_urls,
            url_sources,
            out_of_scope_urls,
            excluded_urls,
            ignored_urls,
            queued_urls,
            queue,
        )

        while queue and len(fetched_urls) < config.max_pages:
            url, depth = queue.popleft()
            queued_urls.discard(url)
            if url in fetched_urls:
                continue
            if config.delay_seconds > 0 and fetched_urls:
                time.sleep(config.delay_seconds)

            page = self._fetch_page(context, url, depth)
            body = str(page.pop("_body", ""))
            page["route_classifications"] = classify_url(
                url,
                content_type=str(page.get("content_type") or ""),
                methods=["GET"] if not page.get("error") else [],
            )
            pages.append(page)
            fetched_urls.add(url)
            _record_url_source(url_sources, url, "crawler_fetched")

            if page.get("error"):
                continue

            status_code = int(page["status_code"])
            if status_code in REDIRECT_STATUSES:
                redirect_url, reason = _normalize_candidate(url, str(page.get("location") or ""), context)
                if redirect_url and redirect_url not in fetched_urls and redirect_url not in queued_urls:
                    discovered_urls.add(redirect_url)
                    _record_url_source(url_sources, redirect_url, "redirect")
                    queued_urls.add(redirect_url)
                    queue.append((redirect_url, depth))
                elif reason == "out_of_scope":
                    out_of_scope_urls.add(str(page.get("absolute_location") or page.get("location") or ""))
                elif reason == "excluded_path":
                    excluded_urls.add(str(page.get("absolute_location") or page.get("location") or ""))
                continue

            if not _is_html(str(page.get("content_type") or "")):
                continue

            document = _HTMLDocumentExtractor.extract(body, url)
            links = document["links"]
            page["links_found"] = len(links)
            page["forms_found"] = len(document["forms"])
            page["route_classifications"] = classify_url(
                url,
                forms_found=len(document["forms"]),
                content_type=str(page.get("content_type") or ""),
                methods=["GET"],
            )
            if document["forms"]:
                page["forms"] = document["forms"]
            if document["title"]:
                page["title"] = document["title"]

            for href in links:
                candidate, reason = _normalize_candidate(url, href, context)
                if candidate:
                    discovered_urls.add(candidate)
                    _record_url_source(url_sources, candidate, "html_link")
                    if depth < config.max_depth and candidate not in fetched_urls and candidate not in queued_urls:
                        queued_urls.add(candidate)
                        queue.append((candidate, depth + 1))
                elif reason == "out_of_scope":
                    out_of_scope_urls.add(urljoin(url, href))
                elif reason == "excluded_path":
                    excluded_urls.add(urljoin(url, href))
                elif reason == "ignored_extension":
                    ignored_urls.add(urljoin(url, href))

        limit_reached = bool(queue)
        if limit_reached:
            findings.append(
                Finding(
                    id="CRAWLER-PAGE-LIMIT-REACHED",
                    title="Crawler page limit reached",
                    severity="info",
                    category="crawler",
                    description="The crawler stopped before visiting every queued URL because the configured page limit was reached.",
                    recommendation="Increase crawler.max_pages only if the wider scope is authorized and useful.",
                    module=self.name,
                    target=seed_url,
                    evidence=[Evidence("max_pages", str(config.max_pages)), Evidence("queued_remaining", str(len(queue)))],
                )
            )

        if out_of_scope_urls:
            findings.append(
                Finding(
                    id="CRAWLER-OUT-OF-SCOPE-LINKS",
                    title="Crawler found links outside scope",
                    severity="info",
                    category="crawler",
                    description="The crawler discovered links outside the configured scope. They were recorded but not requested.",
                    recommendation="Review whether any external host should be added to the authorized scope before scanning it.",
                    module=self.name,
                    target=seed_url,
                    evidence=[Evidence("sample_url", url) for url in sorted(out_of_scope_urls)[:5]],
                )
            )

        errored_pages = [page for page in pages if page.get("error")]
        if errored_pages:
            findings.append(
                Finding(
                    id="CRAWLER-REQUEST-ERRORS",
                    title="Crawler encountered request errors",
                    severity="info",
                    category="crawler",
                    description="Some in-scope URLs could not be retrieved by the crawler.",
                    recommendation="Review request errors and confirm whether the URLs are reachable.",
                    module=self.name,
                    target=seed_url,
                    evidence=[Evidence("error_url", str(page["url"]), str(page["error"])) for page in errored_pages[:5]],
                )
            )

        status = "warning" if findings else "passed"
        return ModuleResult(
            name=self.name,
            status=status,
            summary=(
                f"Crawled {len(fetched_urls)} page(s), discovered {len(discovered_urls)} in-scope URL(s), "
                f"{len(metadata_discovered_urls)} from metadata."
            ),
            findings=findings,
            artifacts={
                "seed_url": seed_url,
                "max_depth": config.max_depth,
                "max_pages": config.max_pages,
                "fetched_urls": sorted(fetched_urls),
                "discovered_urls": sorted(discovered_urls),
                "metadata_discovered_urls": sorted(metadata_discovered_urls),
                "url_sources": _url_sources_artifact(url_sources),
                "route_classifications": _classified_routes(discovered_urls | fetched_urls, pages, url_sources),
                "out_of_scope_urls": sorted(out_of_scope_urls),
                "excluded_urls": sorted(excluded_urls),
                "ignored_urls_count": len(ignored_urls),
                "limit_reached": limit_reached,
                "metadata": metadata,
                "pages": pages,
            },
        )

    def _collect_metadata(
        self,
        context: ScanContext,
        seed_url: str,
        discovered_urls: set[str],
        metadata_discovered_urls: set[str],
        url_sources: dict[str, set[str]],
        out_of_scope_urls: set[str],
        excluded_urls: set[str],
        ignored_urls: set[str],
        queued_urls: set[str],
        queue: deque[tuple[str, int]],
    ) -> dict[str, object]:
        metadata: dict[str, object] = {
            "robots": None,
            "sitemaps": [],
            "well_known": [],
        }
        sitemap_urls: list[str] = []

        if context.config.crawler.use_robots_txt:
            robots, robot_sitemaps = self._fetch_robots(
                context,
                seed_url,
                discovered_urls,
                metadata_discovered_urls,
                url_sources,
                out_of_scope_urls,
                excluded_urls,
                ignored_urls,
                queued_urls,
                queue,
            )
            metadata["robots"] = robots
            sitemap_urls.extend(robot_sitemaps)

        if context.config.crawler.use_sitemap_xml:
            sitemap_urls.insert(0, urljoin(seed_url, "/sitemap.xml"))
            seen_sitemaps: set[str] = set()
            sitemap_entries: list[dict[str, object]] = []
            for sitemap_url in sitemap_urls:
                absolute_sitemap_url = urljoin(seed_url, sitemap_url)
                normalized = _normalize_url(absolute_sitemap_url, context)
                if normalized is None or normalized in seen_sitemaps:
                    continue
                self._fetch_sitemap(
                    context,
                    normalized,
                    "robots" if normalized != _normalize_url(urljoin(seed_url, "/sitemap.xml"), context) else "default",
                    seen_sitemaps,
                    sitemap_entries,
                    discovered_urls,
                    metadata_discovered_urls,
                    url_sources,
                    out_of_scope_urls,
                    excluded_urls,
                    ignored_urls,
                    queued_urls,
                    queue,
                )
            metadata["sitemaps"] = sitemap_entries

        if context.config.crawler.use_well_known:
            metadata["well_known"] = self._fetch_well_known(
                context,
                seed_url,
                discovered_urls,
                metadata_discovered_urls,
                url_sources,
                out_of_scope_urls,
                excluded_urls,
                ignored_urls,
            )

        return metadata

    def _fetch_robots(
        self,
        context: ScanContext,
        seed_url: str,
        discovered_urls: set[str],
        metadata_discovered_urls: set[str],
        url_sources: dict[str, set[str]],
        out_of_scope_urls: set[str],
        excluded_urls: set[str],
        ignored_urls: set[str],
        queued_urls: set[str],
        queue: deque[tuple[str, int]],
    ) -> tuple[dict[str, object], list[str]]:
        robots_url = urljoin(seed_url, "/robots.txt")
        try:
            response = context.probe.request("GET", robots_url, follow_redirects=False, max_body_bytes=context.config.crawler.max_body_bytes)
        except ProbeError as exc:
            return {"url": robots_url, "status": "error", "error": str(exc), "present": False}, []

        body = _decode_body(response.body, response.get_header("content-type", "") or "")
        directives = _parse_robots(body) if 200 <= response.status_code < 300 else {}
        paths: list[dict[str, object]] = []
        for directive in ["allow", "disallow"]:
            for value in directives.get(directive, []):
                if not value or value == "*":
                    continue
                candidate, reason = _add_metadata_candidate(
                    robots_url,
                    value,
                    context,
                    discovered_urls,
                    metadata_discovered_urls,
                    url_sources,
                    out_of_scope_urls,
                    excluded_urls,
                    ignored_urls,
                    queued_urls,
                    queue,
                    source=f"robots_{directive}",
                    enqueue=context.config.crawler.follow_robots_paths,
                )
                paths.append(
                    {
                        "directive": directive,
                        "value": value,
                        "url": candidate or urljoin(robots_url, value),
                        "status": "in_scope" if candidate else reason,
                        "route_classifications": classify_url(candidate or urljoin(robots_url, value)),
                    }
                )

        return (
            {
                "url": robots_url,
                "status_code": response.status_code,
                "content_type": response.get_header("content-type"),
                "present": 200 <= response.status_code < 300,
                "body_truncated": response.body_truncated,
                "directives": directives,
                "paths": paths,
            },
            directives.get("sitemap", []),
        )

    def _fetch_sitemap(
        self,
        context: ScanContext,
        sitemap_url: str,
        source: str,
        seen_sitemaps: set[str],
        sitemap_entries: list[dict[str, object]],
        discovered_urls: set[str],
        metadata_discovered_urls: set[str],
        url_sources: dict[str, set[str]],
        out_of_scope_urls: set[str],
        excluded_urls: set[str],
        ignored_urls: set[str],
        queued_urls: set[str],
        queue: deque[tuple[str, int]],
    ) -> None:
        if sitemap_url in seen_sitemaps or len(seen_sitemaps) >= 10:
            return
        seen_sitemaps.add(sitemap_url)

        try:
            response = context.probe.request("GET", sitemap_url, follow_redirects=False, max_body_bytes=context.config.crawler.max_body_bytes)
        except ProbeError as exc:
            sitemap_entries.append({"url": sitemap_url, "source": source, "status": "error", "error": str(exc), "present": False})
            return

        body = _decode_body(response.body, response.get_header("content-type", "") or "")
        nested_sitemaps, page_urls = _parse_sitemap(body) if 200 <= response.status_code < 300 else ([], [])
        entry = {
            "url": sitemap_url,
            "source": source,
            "status_code": response.status_code,
            "content_type": response.get_header("content-type"),
            "present": 200 <= response.status_code < 300,
            "body_truncated": response.body_truncated,
            "url_count": len(page_urls),
            "sitemap_count": len(nested_sitemaps),
            "sample_urls": page_urls[:10],
            "nested_sitemaps": nested_sitemaps[:10],
        }
        sitemap_entries.append(entry)

        remaining = max(0, context.config.crawler.metadata_max_urls - len(metadata_discovered_urls))
        for page_url in page_urls[:remaining]:
            _add_metadata_candidate(
                sitemap_url,
                page_url,
                context,
                discovered_urls,
                metadata_discovered_urls,
                url_sources,
                out_of_scope_urls,
                excluded_urls,
                ignored_urls,
                queued_urls,
                queue,
                source="sitemap",
                enqueue=context.config.crawler.follow_sitemap_urls,
            )

        for nested_url in nested_sitemaps[:10]:
            normalized = _normalize_url(urljoin(sitemap_url, nested_url), context)
            if normalized:
                self._fetch_sitemap(
                    context,
                    normalized,
                    "sitemap_index",
                    seen_sitemaps,
                    sitemap_entries,
                    discovered_urls,
                    metadata_discovered_urls,
                    url_sources,
                    out_of_scope_urls,
                    excluded_urls,
                    ignored_urls,
                    queued_urls,
                    queue,
                )

    def _fetch_well_known(
        self,
        context: ScanContext,
        seed_url: str,
        discovered_urls: set[str],
        metadata_discovered_urls: set[str],
        url_sources: dict[str, set[str]],
        out_of_scope_urls: set[str],
        excluded_urls: set[str],
        ignored_urls: set[str],
    ) -> list[dict[str, object]]:
        entries: list[dict[str, object]] = []
        for path in context.config.crawler.well_known_paths:
            file_url = urljoin(seed_url, path)
            normalized = _normalize_url(file_url, context)
            if normalized is None:
                entries.append({"path": path, "url": file_url, "status": "skipped_out_of_scope", "present": False})
                continue

            try:
                response = context.probe.request("GET", normalized, follow_redirects=False, max_body_bytes=context.config.crawler.max_body_bytes)
            except ProbeError as exc:
                entries.append({"path": path, "url": normalized, "status": "error", "error": str(exc), "present": False})
                continue

            body = _decode_body(response.body, response.get_header("content-type", "") or "")
            present = 200 <= response.status_code < 300
            _record_url_source(url_sources, normalized, "well_known")
            if present:
                discovered_urls.add(normalized)
                metadata_discovered_urls.add(normalized)

            entry: dict[str, object] = {
                "path": path,
                "url": normalized,
                "status_code": response.status_code,
                "content_type": response.get_header("content-type"),
                "present": present,
                "body_truncated": response.body_truncated,
                "route_classifications": classify_url(normalized),
            }
            if present and path.endswith("security.txt"):
                entry["fields"] = _parse_security_txt(body)
            if present and path.endswith("openid-configuration"):
                endpoints = _parse_json_endpoint_urls(body)
                entry["endpoints"] = endpoints
                for endpoint in endpoints:
                    _add_metadata_candidate(
                        normalized,
                        endpoint,
                        context,
                        discovered_urls,
                        metadata_discovered_urls,
                        url_sources,
                        out_of_scope_urls,
                        excluded_urls,
                        ignored_urls,
                        set(),
                        deque(),
                        source="well_known_endpoint",
                        enqueue=False,
                    )
            entries.append(entry)
        return entries

    def _fetch_page(self, context: ScanContext, url: str, depth: int) -> dict[str, object]:
        try:
            response = context.probe.request(
                "GET",
                url,
                follow_redirects=False,
                max_body_bytes=context.config.crawler.max_body_bytes,
            )
        except ProbeError as exc:
            return {"url": url, "depth": depth, "error": str(exc)}

        location = response.get_header("location")
        absolute_location = urljoin(url, location) if location else None
        return {
            "url": url,
            "depth": depth,
            "status_code": response.status_code,
            "content_type": response.get_header("content-type"),
            "body_truncated": response.body_truncated,
            "location": location,
            "absolute_location": absolute_location,
            "links_found": 0,
            "forms_found": 0,
            "_body": _decode_body(response.body, response.get_header("content-type", "") or ""),
        }


def _add_metadata_candidate(
    current_url: str,
    href: str,
    context: ScanContext,
    discovered_urls: set[str],
    metadata_discovered_urls: set[str],
    url_sources: dict[str, set[str]],
    out_of_scope_urls: set[str],
    excluded_urls: set[str],
    ignored_urls: set[str],
    queued_urls: set[str],
    queue: deque[tuple[str, int]],
    *,
    source: str,
    enqueue: bool,
) -> tuple[str | None, str | None]:
    candidate, reason = _normalize_candidate(current_url, href, context)
    if candidate:
        discovered_urls.add(candidate)
        metadata_discovered_urls.add(candidate)
        _record_url_source(url_sources, candidate, source)
        if enqueue and candidate not in queued_urls:
            queued_urls.add(candidate)
            queue.append((candidate, 0))
        return candidate, None
    absolute = urljoin(current_url, href)
    if reason == "out_of_scope":
        out_of_scope_urls.add(absolute)
    elif reason == "excluded_path":
        excluded_urls.add(absolute)
    elif reason == "ignored_extension":
        ignored_urls.add(absolute)
    return None, reason


def _record_url_source(url_sources: dict[str, set[str]], url: str, source: str) -> None:
    if url:
        url_sources.setdefault(url, set()).add(source)


def _url_sources_artifact(url_sources: dict[str, set[str]]) -> list[dict[str, object]]:
    return [{"url": url, "sources": sorted(sources)} for url, sources in sorted(url_sources.items())]


def _classified_routes(
    urls: set[str],
    pages: list[dict[str, object]],
    url_sources: dict[str, set[str]],
) -> list[dict[str, object]]:
    page_index = {str(page.get("url")): page for page in pages}
    output: list[dict[str, object]] = []
    for url in sorted(urls):
        page = page_index.get(url, {})
        classifications = classify_url(
            url,
            forms_found=int(page.get("forms_found") or 0),
            content_type=str(page.get("content_type") or ""),
            methods=["GET"] if page else [],
        )
        interesting = [item for item in classifications if item.get("interesting")]
        if not interesting:
            continue
        output.append(
            {
                "url": url,
                "types": route_types(classifications),
                "sources": sorted(url_sources.get(url, set())),
                "classifications": classifications,
            }
        )
    return output


def _parse_robots(body: str) -> dict[str, list[str]]:
    directives: dict[str, list[str]] = {}
    for raw_line in body.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line or ":" not in line:
            continue
        key, value = line.split(":", 1)
        normalized_key = key.strip().lower()
        if normalized_key in {"user-agent", "allow", "disallow", "sitemap"}:
            directives.setdefault(normalized_key, []).append(value.strip())
    return directives


def _parse_sitemap(body: str) -> tuple[list[str], list[str]]:
    if not body.strip():
        return [], []
    try:
        root = ElementTree.fromstring(body)
    except ElementTree.ParseError:
        locs = re.findall(r"<loc\b[^>]*>\s*([^<]+)\s*</loc>", body, flags=re.IGNORECASE)
        return [], [_clean_text(item) for item in locs if _clean_text(item)]

    root_name = _local_name(root.tag)
    sitemap_urls: list[str] = []
    page_urls: list[str] = []
    for element in root.iter():
        if _local_name(element.tag) != "loc" or not element.text:
            continue
        value = _clean_text(element.text)
        if not value:
            continue
        if root_name == "sitemapindex":
            sitemap_urls.append(value)
        else:
            page_urls.append(value)
    return sitemap_urls, page_urls


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


def _parse_json_endpoint_urls(body: str) -> list[str]:
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        return []
    if not isinstance(data, dict):
        return []
    urls: list[str] = []
    for key, value in data.items():
        if not str(key).endswith(("_endpoint", "_uri")):
            continue
        if isinstance(value, str) and value.startswith(("http://", "https://")):
            urls.append(value)
    return sorted(set(urls))


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1].lower()


def _clean_text(value: object) -> str:
    if value is None:
        return ""
    return str(value).strip()


class _HTMLDocumentExtractor(HTMLParser):
    def __init__(self, base_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.links: list[str] = []
        self.forms: list[dict[str, object]] = []
        self.title_parts: list[str] = []
        self._current_form: dict[str, object] | None = None
        self._in_title = False

    @classmethod
    def extract(cls, html: str, base_url: str) -> dict[str, object]:
        parser = cls(base_url)
        parser.feed(html)
        if parser._current_form is not None:
            parser.forms.append(parser._current_form)
            parser._current_form = None
        return {
            "links": parser.links,
            "forms": parser.forms,
            "title": " ".join(" ".join(parser.title_parts).split())[:200],
        }

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        lowered_tag = tag.lower()
        attr_map = {key.lower(): (value or "") for key, value in attrs}

        if lowered_tag == "title":
            self._in_title = True
            return

        if lowered_tag == "a":
            href = attr_map.get("href", "").strip()
            if href:
                self.links.append(href)
            return

        if lowered_tag == "form":
            action = attr_map.get("action", "").strip()
            self._current_form = {
                "action": urljoin(self.base_url, action) if action else self.base_url,
                "method": (attr_map.get("method") or "get").upper(),
                "input_count": 0,
                "password_fields": 0,
                "hidden_fields": 0,
                "csrf_candidates": [],
                "fields": [],
            }
            return

        if self._current_form is not None and lowered_tag in {"input", "textarea", "select"}:
            field_type = (attr_map.get("type") if lowered_tag == "input" else lowered_tag) or "text"
            field_name = attr_map.get("name") or attr_map.get("id") or ""
            fields = self._current_form["fields"]
            if isinstance(fields, list):
                fields.append({"name": field_name, "type": field_type.lower()})
            self._current_form["input_count"] = int(self._current_form["input_count"]) + 1
            if field_type.lower() == "password":
                self._current_form["password_fields"] = int(self._current_form["password_fields"]) + 1
            if field_type.lower() == "hidden":
                self._current_form["hidden_fields"] = int(self._current_form["hidden_fields"]) + 1
            if _is_csrf_candidate(field_name):
                candidates = self._current_form["csrf_candidates"]
                if isinstance(candidates, list):
                    candidates.append(field_name)

    def handle_endtag(self, tag: str) -> None:
        lowered_tag = tag.lower()
        if lowered_tag == "title":
            self._in_title = False
            return
        if lowered_tag == "form" and self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None

    def handle_data(self, data: str) -> None:
        if self._in_title and data.strip():
            self.title_parts.append(data.strip())


def _normalize_candidate(current_url: str, href: str, context: ScanContext) -> tuple[str | None, str | None]:
    if not href or href.startswith(("#", "mailto:", "tel:", "javascript:", "data:")):
        return None, "unsupported_scheme"

    absolute_url = urldefrag(urljoin(current_url, href))[0]
    parsed = urlsplit(absolute_url)
    if parsed.scheme not in {"http", "https"}:
        return None, "unsupported_scheme"
    if not parsed.hostname:
        return None, "invalid_url"
    if not is_host_allowed(parsed.hostname, context.config.scope, default_host=context.target.host):
        return None, "out_of_scope"
    if not is_path_allowed(parsed.path or "/", context.config.scope):
        return None, "excluded_path"
    if _has_ignored_extension(parsed.path, context.config.crawler.ignored_extensions):
        return None, "ignored_extension"

    normalized_url = _normalize_url(absolute_url, context)
    if normalized_url is None:
        return None, "invalid_url"
    return normalized_url, None


def _normalize_url(url: str, context: ScanContext) -> str | None:
    parsed = urlsplit(urldefrag(url)[0])
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return None
    if not is_url_allowed(url, context.config.scope, default_host=context.target.host):
        return None

    host = parsed.hostname.strip().rstrip(".").lower().encode("idna").decode("ascii")
    display_host = f"[{host}]" if ":" in host else host
    default_port = 443 if parsed.scheme == "https" else 80
    netloc = f"{display_host}:{parsed.port}" if parsed.port and parsed.port != default_port else display_host
    path = posixpath.normpath(parsed.path or "/")
    if not path.startswith("/"):
        path = f"/{path}"
    if parsed.path.endswith("/") and not path.endswith("/"):
        path = f"{path}/"
    query = parsed.query if context.config.crawler.include_query_strings else ""
    return urlunsplit((parsed.scheme.lower(), netloc, path, query, ""))


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


def _has_ignored_extension(path: str, ignored_extensions: list[str]) -> bool:
    lowered = path.lower()
    return any(lowered.endswith(extension.lower()) for extension in ignored_extensions)


def _is_csrf_candidate(name: str) -> bool:
    lowered = name.strip().lower()
    return "csrf" in lowered or lowered in {"token", "_token", "authenticity_token"}
