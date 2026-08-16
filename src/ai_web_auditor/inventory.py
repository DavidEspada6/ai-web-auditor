from __future__ import annotations

import csv
from collections import Counter
from io import StringIO
from typing import Any
from urllib.parse import urlsplit, urlunsplit


INTERESTING_PATH_RULES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("admin_path", ("/admin", "/administrator", "/wp-admin", "/cpanel")),
    ("login_path", ("/login", "/signin", "/sign-in", "/auth", "/account/login")),
    ("members_area", ("/members", "/member", "/clientes", "/customer")),
    ("api_path", ("/api", "/graphql", "/swagger", "/openapi")),
    ("private_path", ("/private", "/internal", "/dashboard", "/panel")),
    ("sensitive_file", ("/.env", "/config", "/backup", "/dump", "/db", "/database")),
)

CSV_FIELDS = [
    "url",
    "status_code",
    "content_type",
    "fetched",
    "depth",
    "methods",
    "links_found",
    "forms_found",
    "interesting",
    "reasons",
    "sources",
    "title",
    "error",
]


def build_inventory_from_scan(scan_data: dict[str, Any]) -> dict[str, Any]:
    existing = scan_data.get("inventory")
    if isinstance(existing, dict) and isinstance(existing.get("urls"), list):
        return existing

    entries: dict[str, dict[str, Any]] = {}
    source_index: dict[str, set[str]] = {}
    method_index: dict[str, set[str]] = {}
    forms: list[dict[str, Any]] = []

    target = scan_data.get("target") if isinstance(scan_data.get("target"), dict) else {}
    target_url = _clean_text(target.get("normalized_url") or target.get("original_url"))
    if target_url:
        _add_url(entries, source_index, method_index, target_url, source="target")

    for module in _modules(scan_data):
        if module.get("name") != "crawler":
            continue

        artifacts = module.get("artifacts") if isinstance(module.get("artifacts"), dict) else {}
        for page in _dict_list(artifacts.get("pages")):
            page_url = _clean_text(page.get("url"))
            if not page_url:
                continue
            entry = _add_url(
                entries,
                source_index,
                method_index,
                page_url,
                source="crawler_page",
                status_code=_optional_int(page.get("status_code")),
                content_type=_clean_text(page.get("content_type")),
                depth=_optional_int(page.get("depth")),
                fetched=True,
                links_found=_optional_int(page.get("links_found")) or 0,
                forms_found=_optional_int(page.get("forms_found")) or 0,
                title=_clean_text(page.get("title")),
                error=_clean_text(page.get("error")),
                method="GET",
            )
            for form in _dict_list(page.get("forms")):
                normalized = _normalize_form(form, page_url)
                forms.append(normalized)
                action_url = _clean_text(normalized.get("action"))
                if action_url:
                    _add_url(entries, source_index, method_index, action_url, source="form_action")
                if entry is not None:
                    entry["forms_found"] = max(int(entry.get("forms_found") or 0), len(forms_for_page(forms, page_url)))

        for url in _string_list(artifacts.get("fetched_urls")):
            _add_url(entries, source_index, method_index, url, source="crawler_fetched", fetched=True, method="GET")
        for url in _string_list(artifacts.get("discovered_urls")):
            _add_url(entries, source_index, method_index, url, source="crawler_discovered")
        for url in _string_list(artifacts.get("out_of_scope_urls")):
            _add_url(entries, source_index, method_index, url, source="out_of_scope")
        for url in _string_list(artifacts.get("excluded_urls")):
            _add_url(entries, source_index, method_index, url, source="excluded")

    for record in _dict_list(scan_data.get("requests")):
        method = _clean_text(record.get("method")).upper() or None
        _add_url(
            entries,
            source_index,
            method_index,
            _clean_text(record.get("url")),
            source="request",
            status_code=_optional_int(record.get("status_code")),
            fetched=True,
            error=_clean_text(record.get("error")),
            method=method,
        )
        final_url = _clean_text(record.get("final_url"))
        if final_url and final_url != _clean_text(record.get("url")):
            _add_url(entries, source_index, method_index, final_url, source="request_final", fetched=True)

    urls = [_finalize_entry(entry, source_index, method_index) for entry in entries.values()]
    urls.sort(key=_inventory_sort_key)
    forms.sort(key=lambda item: (_clean_text(item.get("page_url")), _clean_text(item.get("action"))))

    status_counts = Counter(str(item.get("status_code")) for item in urls if item.get("status_code") is not None)
    content_type_counts = Counter(_main_content_type(item.get("content_type")) for item in urls if item.get("content_type"))
    summary = {
        "total_urls": len(urls),
        "fetched_urls": sum(1 for item in urls if item.get("fetched")),
        "interesting_urls": sum(1 for item in urls if item.get("interesting")),
        "forms": len(forms),
        "pages_with_forms": sum(1 for item in urls if int(item.get("forms_found") or 0) > 0),
        "external_urls": sum(1 for item in urls if "out_of_scope" in item.get("sources", [])),
        "excluded_urls": sum(1 for item in urls if "excluded" in item.get("sources", [])),
        "status_codes": dict(sorted(status_counts.items())),
        "content_types": dict(sorted(content_type_counts.items())),
    }

    return {
        "summary": summary,
        "urls": urls,
        "forms": forms,
        "interesting_paths": [item for item in urls if item.get("interesting")],
    }


def inventory_to_csv(inventory: dict[str, Any]) -> str:
    output = StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=CSV_FIELDS, extrasaction="ignore", lineterminator="\n")
    writer.writeheader()
    for row in _dict_list(inventory.get("urls")):
        writer.writerow({field: _csv_value(row.get(field)) for field in CSV_FIELDS})
    return output.getvalue()


def forms_for_page(forms: list[dict[str, Any]], page_url: str) -> list[dict[str, Any]]:
    return [form for form in forms if form.get("page_url") == page_url]


def _add_url(
    entries: dict[str, dict[str, Any]],
    source_index: dict[str, set[str]],
    method_index: dict[str, set[str]],
    url: str,
    *,
    source: str,
    status_code: int | None = None,
    content_type: str = "",
    depth: int | None = None,
    fetched: bool = False,
    links_found: int = 0,
    forms_found: int = 0,
    title: str = "",
    error: str = "",
    method: str | None = None,
) -> dict[str, Any] | None:
    normalized_url = _canonical_url(url)
    if not normalized_url:
        return None

    entry = entries.setdefault(
        normalized_url,
        {
            "url": normalized_url,
            "status_code": None,
            "content_type": "",
            "fetched": False,
            "depth": None,
            "methods": [],
            "links_found": 0,
            "forms_found": 0,
            "interesting": False,
            "reasons": [],
            "sources": [],
            "source": "",
            "title": "",
            "error": "",
        },
    )

    source_index.setdefault(normalized_url, set()).add(source)
    if method:
        method_index.setdefault(normalized_url, set()).add(method.upper())
    if status_code is not None and entry.get("status_code") is None:
        entry["status_code"] = status_code
    if content_type and not entry.get("content_type"):
        entry["content_type"] = content_type
    if fetched:
        entry["fetched"] = True
    if depth is not None:
        current_depth = entry.get("depth")
        entry["depth"] = depth if current_depth is None else min(int(current_depth), depth)
    entry["links_found"] = max(int(entry.get("links_found") or 0), links_found)
    entry["forms_found"] = max(int(entry.get("forms_found") or 0), forms_found)
    if title and not entry.get("title"):
        entry["title"] = title[:200]
    if error and not entry.get("error"):
        entry["error"] = error
    return entry


def _finalize_entry(
    entry: dict[str, Any],
    source_index: dict[str, set[str]],
    method_index: dict[str, set[str]],
) -> dict[str, Any]:
    url = _clean_text(entry.get("url"))
    sources = sorted(source_index.get(url, set()))
    methods = sorted(method_index.get(url, set()))
    reasons = _interesting_reasons(url, int(entry.get("forms_found") or 0))
    output = dict(entry)
    output["sources"] = sources
    output["source"] = ", ".join(sources)
    output["methods"] = methods
    output["reasons"] = reasons
    output["interesting"] = bool(reasons)
    return output


def _normalize_form(form: dict[str, Any], page_url: str) -> dict[str, Any]:
    fields = _dict_list(form.get("fields"))
    action = _canonical_url(_clean_text(form.get("action")) or page_url)
    method = (_clean_text(form.get("method")) or "GET").upper()
    csrf_candidates = _string_list(form.get("csrf_candidates"))
    if not csrf_candidates:
        csrf_candidates = [
            _clean_text(field.get("name"))
            for field in fields
            if _is_csrf_candidate(_clean_text(field.get("name")))
        ]

    return {
        "page_url": _canonical_url(page_url),
        "action": action,
        "method": method,
        "input_count": _optional_int(form.get("input_count")) or len(fields),
        "password_fields": _optional_int(form.get("password_fields")) or _count_field_type(fields, "password"),
        "hidden_fields": _optional_int(form.get("hidden_fields")) or _count_field_type(fields, "hidden"),
        "csrf_candidates": sorted(set(item for item in csrf_candidates if item)),
        "fields": fields[:25],
    }


def _interesting_reasons(url: str, forms_found: int) -> list[str]:
    parsed = urlsplit(url)
    target = f"{parsed.path or '/'}?{parsed.query}".lower()
    reasons: list[str] = []
    for reason, markers in INTERESTING_PATH_RULES:
        if any(marker in target for marker in markers):
            reasons.append(reason)
    if forms_found > 0:
        reasons.append("form_detected")
    return reasons


def _inventory_sort_key(item: dict[str, Any]) -> tuple[int, str]:
    source = set(_string_list(item.get("sources")))
    if item.get("interesting"):
        group = 0
    elif "crawler_page" in source or "crawler_fetched" in source:
        group = 1
    elif "crawler_discovered" in source or "form_action" in source:
        group = 2
    elif "excluded" in source:
        group = 3
    elif "out_of_scope" in source:
        group = 4
    else:
        group = 5
    return group, _clean_text(item.get("url"))


def _canonical_url(url: str) -> str:
    value = _clean_text(url)
    if not value:
        return ""
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return value
    host = (parsed.hostname or "").strip().rstrip(".").lower()
    if not host:
        return value
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        pass
    display_host = f"[{host}]" if ":" in host else host
    default_port = 443 if parsed.scheme == "https" else 80
    netloc = f"{display_host}:{parsed.port}" if parsed.port and parsed.port != default_port else display_host
    path = parsed.path or "/"
    return urlunsplit((parsed.scheme.lower(), netloc, path, parsed.query, ""))


def _modules(scan_data: dict[str, Any]) -> list[dict[str, Any]]:
    return _dict_list(scan_data.get("modules"))


def _dict_list(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [_clean_text(item) for item in value if _clean_text(item)]


def _optional_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _count_field_type(fields: list[dict[str, Any]], field_type: str) -> int:
    return sum(1 for field in fields if _clean_text(field.get("type")).lower() == field_type)


def _is_csrf_candidate(name: str) -> bool:
    lowered = name.lower()
    return "csrf" in lowered or lowered in {"token", "_token", "authenticity_token"}


def _main_content_type(value: Any) -> str:
    return _clean_text(value).split(";", 1)[0].strip().lower()


def _csv_value(value: Any) -> str:
    if isinstance(value, list):
        return "; ".join(_clean_text(item) for item in value)
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return ""
    return str(value)


def _clean_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()
