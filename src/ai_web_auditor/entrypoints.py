from __future__ import annotations

import csv
import hashlib
from collections import Counter
from io import StringIO
from typing import Any
from urllib.parse import parse_qsl, urlsplit, urlunsplit

from .inventory import build_inventory_from_scan
from .routes import classify_url, route_types


STATE_CHANGING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

CSV_FIELDS = [
    "id",
    "url",
    "state",
    "review_candidate",
    "methods",
    "route_types",
    "parameters",
    "forms",
    "sources",
    "status_code",
    "content_type",
    "notes",
]


def build_entry_points_from_scan(scan_data: dict[str, Any]) -> dict[str, Any]:
    existing = scan_data.get("entry_points")
    if isinstance(existing, dict) and isinstance(existing.get("endpoints"), list):
        return existing

    inventory = build_inventory_from_scan(scan_data)
    endpoints: dict[str, dict[str, Any]] = {}
    parameters: dict[str, dict[str, Any]] = {}
    forms: list[dict[str, Any]] = []

    for item in _dict_list(inventory.get("urls")):
        endpoint = _ensure_endpoint(endpoints, _clean(item.get("url")))
        if endpoint is None:
            continue
        _merge_inventory_url(endpoint, item)
        for name in _query_parameter_names(endpoint["url"]):
            _add_parameter(endpoint, parameters, name, location="query")

    target_url = _target_url(scan_data)
    if target_url:
        methods = _http_methods(scan_data)
        if methods:
            endpoint = _ensure_endpoint(endpoints, target_url)
            if endpoint is not None:
                endpoint["_methods"].update(methods)
                endpoint["_sources"].add("http_methods_options")

    for item in _dict_list(inventory.get("forms")):
        form = _form_entry(item)
        forms.append(form)
        endpoint = _ensure_endpoint(endpoints, form["action"] or form["page_url"])
        if endpoint is None:
            continue
        endpoint["_sources"].add("form_action")
        endpoint["_methods"].add(form["method"])
        endpoint["_form_ids"].add(form["id"])
        endpoint["_route_types"].update(_string_list(form.get("route_types")))
        for name in _query_parameter_names(endpoint["url"]):
            _add_parameter(endpoint, parameters, name, location="query")
        for field in _dict_list(form.get("fields")):
            name = _clean(field.get("name"))
            if not name:
                continue
            _add_parameter(
                endpoint,
                parameters,
                name,
                location="form",
                form_id=form["id"],
                method=form["method"],
                field_type=_clean(field.get("type"), "text"),
            )

    endpoint_list = [_finalize_endpoint(item) for item in endpoints.values()]
    endpoint_list.sort(key=_endpoint_sort_key)
    form_list = sorted(forms, key=lambda item: (_clean(item.get("page_url")), _clean(item.get("action")), _clean(item.get("id"))))
    parameter_list = [_finalize_parameter(item) for item in parameters.values()]
    parameter_list.sort(key=lambda item: (item["name"].lower(), item["locations"]))
    methods = _method_summary(endpoint_list)

    summary = {
        "total_endpoints": len(endpoint_list),
        "review_candidates": sum(1 for item in endpoint_list if item.get("review_candidate")),
        "fetched_endpoints": sum(1 for item in endpoint_list if item.get("state") == "fetched"),
        "metadata_endpoints": sum(1 for item in endpoint_list if item.get("state") == "metadata"),
        "excluded_endpoints": sum(1 for item in endpoint_list if item.get("state") == "excluded"),
        "state_changing_endpoints": sum(1 for item in endpoint_list if item.get("state_changing")),
        "forms": len(form_list),
        "forms_with_password_fields": sum(1 for item in form_list if int(item.get("password_fields") or 0) > 0),
        "parameters": len(parameter_list),
        "query_parameters": sum(1 for item in parameter_list if "query" in item.get("locations", [])),
        "form_parameters": sum(1 for item in parameter_list if "form" in item.get("locations", [])),
        "methods": {item["method"]: item["endpoint_count"] for item in methods},
    }

    return {
        "summary": summary,
        "endpoints": endpoint_list,
        "forms": form_list,
        "parameters": parameter_list,
        "methods": methods,
    }


def entry_points_to_csv(entry_points: dict[str, Any]) -> str:
    output = StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=CSV_FIELDS, extrasaction="ignore", lineterminator="\n")
    writer.writeheader()
    for row in _dict_list(entry_points.get("endpoints")):
        writer.writerow({field: _csv_value(row.get(field)) for field in CSV_FIELDS})
    return output.getvalue()


def _merge_inventory_url(endpoint: dict[str, Any], item: dict[str, Any]) -> None:
    endpoint["_sources"].update(_string_list(item.get("sources")))
    endpoint["_methods"].update(_string_list(item.get("methods")))
    endpoint["_route_types"].update(_string_list(item.get("route_types")))
    endpoint["status_code"] = endpoint.get("status_code") if endpoint.get("status_code") is not None else _optional_int(item.get("status_code"))
    endpoint["content_type"] = endpoint.get("content_type") or _clean(item.get("content_type"))
    endpoint["fetched"] = bool(endpoint.get("fetched") or item.get("fetched"))
    endpoint["forms_found"] = max(int(endpoint.get("forms_found") or 0), _optional_int(item.get("forms_found")) or 0)
    endpoint["title"] = endpoint.get("title") or _clean(item.get("title"))


def _ensure_endpoint(endpoints: dict[str, dict[str, Any]], url: str) -> dict[str, Any] | None:
    normalized_url = _canonical_url(url)
    if not normalized_url:
        return None
    endpoint = endpoints.setdefault(
        normalized_url,
        {
            "id": _stable_id("ep", normalized_url),
            "url": normalized_url,
            "path": urlsplit(normalized_url).path or "/",
            "status_code": None,
            "content_type": "",
            "fetched": False,
            "forms_found": 0,
            "title": "",
            "_methods": set(),
            "_sources": set(),
            "_route_types": set(),
            "_form_ids": set(),
            "_parameters": {},
        },
    )
    return endpoint


def _form_entry(item: dict[str, Any]) -> dict[str, Any]:
    page_url = _canonical_url(_clean(item.get("page_url")))
    action = _canonical_url(_clean(item.get("action")) or page_url)
    method = (_clean(item.get("method"), "GET") or "GET").upper()
    fields = _dict_list(item.get("fields"))
    route_types = _route_types_for_url(action)
    return {
        "id": _stable_id("form", "|".join([page_url, action, method, ",".join(_field_names(fields))])),
        "page_url": page_url,
        "action": action,
        "method": method,
        "input_count": _optional_int(item.get("input_count")) or len(fields),
        "password_fields": _optional_int(item.get("password_fields")) or _count_field_type(fields, "password"),
        "hidden_fields": _optional_int(item.get("hidden_fields")) or _count_field_type(fields, "hidden"),
        "csrf_candidates": _string_list(item.get("csrf_candidates")),
        "fields": fields[:25],
        "field_names": _field_names(fields),
        "route_types": route_types,
        "state_changing": method in STATE_CHANGING_METHODS,
    }


def _add_parameter(
    endpoint: dict[str, Any],
    parameters: dict[str, dict[str, Any]],
    name: str,
    *,
    location: str,
    form_id: str = "",
    method: str = "",
    field_type: str = "",
) -> None:
    clean_name = _clean(name)
    if not clean_name:
        return
    endpoint_parameter = endpoint["_parameters"].setdefault(
        clean_name,
        {
            "name": clean_name,
            "locations": set(),
            "field_types": set(),
            "forms": set(),
        },
    )
    endpoint_parameter["locations"].add(location)
    if field_type:
        endpoint_parameter["field_types"].add(field_type)
    if form_id:
        endpoint_parameter["forms"].add(form_id)

    aggregate = parameters.setdefault(
        clean_name,
        {
            "name": clean_name,
            "locations": set(),
            "endpoints": set(),
            "forms": set(),
            "methods": set(),
            "field_types": set(),
            "occurrences": 0,
            "sensitive_hint": _is_sensitive_name(clean_name),
        },
    )
    aggregate["locations"].add(location)
    aggregate["endpoints"].add(endpoint["id"])
    if form_id:
        aggregate["forms"].add(form_id)
    if method:
        aggregate["methods"].add(method)
    if field_type:
        aggregate["field_types"].add(field_type)
    aggregate["occurrences"] = int(aggregate["occurrences"]) + 1


def _finalize_endpoint(endpoint: dict[str, Any]) -> dict[str, Any]:
    sources = sorted(endpoint.pop("_sources"))
    methods = sorted(method.upper() for method in endpoint.pop("_methods") if method)
    route_types = sorted(endpoint.pop("_route_types"))
    forms = sorted(endpoint.pop("_form_ids"))
    parameters = [_finalize_endpoint_parameter(item) for item in endpoint.pop("_parameters").values()]
    parameters.sort(key=lambda item: item["name"].lower())
    state = _endpoint_state(endpoint, sources)
    state_changing = bool(STATE_CHANGING_METHODS.intersection(methods) or "state_changing_candidate" in route_types)
    static_only = route_types == ["static_asset"]
    notes = _endpoint_notes(endpoint, methods, route_types, parameters, forms)
    output = dict(endpoint)
    output.update(
        {
            "state": state,
            "review_candidate": state not in {"excluded", "out_of_scope"} and not static_only,
            "state_changing": state_changing,
            "methods": methods,
            "route_types": route_types,
            "parameters": parameters,
            "parameter_names": [item["name"] for item in parameters],
            "forms": forms,
            "sources": sources,
            "notes": notes,
        }
    )
    return output


def _finalize_endpoint_parameter(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": item["name"],
        "locations": sorted(item["locations"]),
        "field_types": sorted(item["field_types"]),
        "forms": sorted(item["forms"]),
        "sensitive_hint": _is_sensitive_name(item["name"]),
    }


def _finalize_parameter(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": item["name"],
        "locations": sorted(item["locations"]),
        "endpoints": sorted(item["endpoints"]),
        "forms": sorted(item["forms"]),
        "methods": sorted(item["methods"]),
        "field_types": sorted(item["field_types"]),
        "occurrences": int(item.get("occurrences") or 0),
        "sensitive_hint": bool(item.get("sensitive_hint")),
    }


def _method_summary(endpoints: list[dict[str, Any]]) -> list[dict[str, Any]]:
    counter: Counter[str] = Counter()
    state_changing_counter: Counter[str] = Counter()
    samples: dict[str, list[str]] = {}
    for endpoint in endpoints:
        for method in _string_list(endpoint.get("methods")):
            counter[method] += 1
            samples.setdefault(method, [])
            if len(samples[method]) < 10:
                samples[method].append(endpoint["id"])
            if method in STATE_CHANGING_METHODS:
                state_changing_counter[method] += 1
    return [
        {
            "method": method,
            "endpoint_count": counter[method],
            "state_changing": method in STATE_CHANGING_METHODS,
            "state_changing_endpoint_count": state_changing_counter.get(method, 0),
            "sample_endpoint_ids": samples.get(method, []),
        }
        for method in sorted(counter)
    ]


def _endpoint_state(endpoint: dict[str, Any], sources: list[str]) -> str:
    source_set = set(sources)
    if "out_of_scope" in source_set:
        return "out_of_scope"
    if "excluded" in source_set:
        return "excluded"
    if endpoint.get("fetched"):
        return "fetched"
    if "form_action" in source_set:
        return "form_action"
    if "metadata_discovered" in source_set or any(source.startswith(("robots_", "sitemap", "well_known")) for source in source_set):
        return "metadata"
    return "discovered"


def _endpoint_notes(
    endpoint: dict[str, Any],
    methods: list[str],
    route_types: list[str],
    parameters: list[dict[str, Any]],
    forms: list[str],
) -> list[str]:
    notes: list[str] = []
    if forms:
        notes.append("form_action" if not int(endpoint.get("forms_found") or 0) else "page_has_form")
    if STATE_CHANGING_METHODS.intersection(methods):
        notes.append("state_changing_method")
    if parameters:
        notes.append("parameters_observed")
    if any(item.get("sensitive_hint") for item in parameters):
        notes.append("sensitive_parameter_name")
    for route_type in route_types:
        if route_type in {"admin", "login", "api", "password_reset", "callback", "upload", "debug"}:
            notes.append(f"{route_type}_route")
    return sorted(set(notes))


def _endpoint_sort_key(item: dict[str, Any]) -> tuple[int, int, str]:
    if item.get("review_candidate") and item.get("state_changing"):
        group = 0
    elif item.get("review_candidate"):
        group = 1
    elif item.get("state") == "excluded":
        group = 2
    else:
        group = 3
    return group, -len(_dict_list(item.get("parameters"))), _clean(item.get("url"))


def _http_methods(scan_data: dict[str, Any]) -> list[str]:
    module = _module_by_name(_modules(scan_data), "http_methods")
    artifacts = module.get("artifacts") if module and isinstance(module.get("artifacts"), dict) else {}
    return [method.upper() for method in _string_list(artifacts.get("methods"))]


def _target_url(scan_data: dict[str, Any]) -> str:
    target = scan_data.get("target") if isinstance(scan_data.get("target"), dict) else {}
    return _clean(target.get("normalized_url") or target.get("original_url"))


def _route_types_for_url(url: str) -> list[str]:
    return route_types(classify_url(url))


def _query_parameter_names(url: str) -> list[str]:
    parsed = urlsplit(url)
    if not parsed.query:
        return []
    return sorted({key for key, _value in parse_qsl(parsed.query, keep_blank_values=True) if key})


def _field_names(fields: list[dict[str, Any]]) -> list[str]:
    return sorted(_clean(field.get("name")) for field in fields if _clean(field.get("name")))


def _count_field_type(fields: list[dict[str, Any]], field_type: str) -> int:
    return sum(1 for field in fields if _clean(field.get("type")).lower() == field_type)


def _canonical_url(url: str) -> str:
    value = _clean(url)
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


def _stable_id(prefix: str, value: str) -> str:
    digest = hashlib.sha1(value.encode("utf-8", errors="ignore")).hexdigest()[:12]
    return f"{prefix}_{digest}"


def _module_by_name(modules: list[dict[str, Any]], name: str) -> dict[str, Any] | None:
    for module in modules:
        if module.get("name") == name:
            return module
    return None


def _modules(scan_data: dict[str, Any]) -> list[dict[str, Any]]:
    return _dict_list(scan_data.get("modules"))


def _dict_list(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [_clean(item) for item in value if _clean(item)]


def _optional_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _is_sensitive_name(name: str) -> bool:
    lowered = name.strip().lower()
    return any(marker in lowered for marker in ["auth", "csrf", "key", "pass", "secret", "session", "sid", "token"])


def _csv_value(value: Any) -> str:
    if isinstance(value, list):
        if value and all(isinstance(item, dict) for item in value):
            return "; ".join(_clean(item.get("name", item.get("id", ""))) for item in value if isinstance(item, dict))
        return "; ".join(map(str, value))
    if isinstance(value, bool):
        return "true" if value else "false"
    return "" if value is None else str(value)


def _clean(value: Any, default: str = "") -> str:
    if value is None:
        return default
    text = str(value).strip()
    return text or default
