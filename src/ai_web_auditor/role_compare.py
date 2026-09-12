from __future__ import annotations

from typing import Any

from . import __version__
from .models import utc_now


def compare_role_scans(baseline: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
    baseline_urls = _urls_by_key(baseline)
    current_urls = _urls_by_key(current)
    baseline_entries = _entry_points_by_key(baseline)
    current_entries = _entry_points_by_key(current)

    common_url_keys = sorted(set(baseline_urls) & set(current_urls))
    status_changes = [
        {
            "url": key,
            "baseline_status": baseline_urls[key].get("status_code"),
            "current_status": current_urls[key].get("status_code"),
            "baseline_sources": baseline_urls[key].get("sources", []),
            "current_sources": current_urls[key].get("sources", []),
        }
        for key in common_url_keys
        if baseline_urls[key].get("status_code") != current_urls[key].get("status_code")
    ]

    common_entry_keys = sorted(set(baseline_entries) & set(current_entries))
    method_changes = [
        {
            "url": key,
            "baseline_methods": baseline_entries[key].get("methods", []),
            "current_methods": current_entries[key].get("methods", []),
        }
        for key in common_entry_keys
        if sorted(baseline_entries[key].get("methods", [])) != sorted(current_entries[key].get("methods", []))
    ]

    baseline_score = _risk_score(baseline)
    current_score = _risk_score(current)
    new_url_keys = sorted(set(current_urls) - set(baseline_urls))
    resolved_url_keys = sorted(set(baseline_urls) - set(current_urls))
    new_entry_keys = sorted(set(current_entries) - set(baseline_entries))
    resolved_entry_keys = sorted(set(baseline_entries) - set(current_entries))

    return {
        "tool": "ai-web-auditor",
        "version": __version__,
        "generated_at": utc_now(),
        "baseline": _scan_summary(baseline),
        "current": _scan_summary(current),
        "summary": {
            "new_urls": len(new_url_keys),
            "baseline_only_urls": len(resolved_url_keys),
            "new_entry_points": len(new_entry_keys),
            "baseline_only_entry_points": len(resolved_entry_keys),
            "status_code_changes": len(status_changes),
            "method_changes": len(method_changes),
            "risk_delta": current_score - baseline_score,
        },
        "new_urls": [current_urls[key] for key in new_url_keys[:100]],
        "baseline_only_urls": [baseline_urls[key] for key in resolved_url_keys[:100]],
        "new_entry_points": [current_entries[key] for key in new_entry_keys[:100]],
        "baseline_only_entry_points": [baseline_entries[key] for key in resolved_entry_keys[:100]],
        "status_code_changes": status_changes[:100],
        "method_changes": method_changes[:100],
        "review_notes": _review_notes(new_url_keys, new_entry_keys, status_changes, method_changes),
    }


def render_role_compare_console(comparison: dict[str, Any]) -> None:
    baseline = comparison.get("baseline", {})
    current = comparison.get("current", {})
    summary = comparison.get("summary", {})
    print("AI Web Auditor role comparison")
    print(f"Baseline: {baseline.get('auth_profile', {}).get('name', 'Public')} | {baseline.get('target', 'unknown')}")
    print(f"Current:  {current.get('auth_profile', {}).get('name', 'Current')} | {current.get('target', 'unknown')}")
    print()
    print("Summary")
    print("-------")
    print(f"New URLs in current role: {summary.get('new_urls', 0)}")
    print(f"New entry points in current role: {summary.get('new_entry_points', 0)}")
    print(f"Status code changes: {summary.get('status_code_changes', 0)}")
    print(f"Method changes: {summary.get('method_changes', 0)}")
    print(f"Risk delta: {summary.get('risk_delta', 0)}")
    _print_url_group("New URLs", comparison.get("new_urls"))
    _print_entry_group("New entry points", comparison.get("new_entry_points"))


def _print_url_group(label: str, items: Any) -> None:
    rows = items if isinstance(items, list) else []
    if not rows:
        return
    print()
    print(label)
    print("-" * len(label))
    for item in rows[:15]:
        if isinstance(item, dict):
            status = item.get("status_code")
            status_label = f" [{status}]" if status is not None else ""
            print(f"- {item.get('url', 'unknown')}{status_label}")


def _print_entry_group(label: str, items: Any) -> None:
    rows = items if isinstance(items, list) else []
    if not rows:
        return
    print()
    print(label)
    print("-" * len(label))
    for item in rows[:15]:
        if isinstance(item, dict):
            methods = ", ".join(item.get("methods", [])) if isinstance(item.get("methods"), list) else ""
            suffix = f" ({methods})" if methods else ""
            print(f"- {item.get('url', 'unknown')}{suffix}")


def _scan_summary(scan_data: dict[str, Any]) -> dict[str, Any]:
    target = scan_data.get("target") if isinstance(scan_data.get("target"), dict) else {}
    return {
        "generated_at": scan_data.get("generated_at", "unknown"),
        "status": scan_data.get("status", "unknown"),
        "version": scan_data.get("version", "unknown"),
        "target": target.get("normalized_url", target.get("original_url", "unknown")),
        "host": target.get("host", "unknown"),
        "auth_profile": _auth_profile(scan_data),
        "risk_score": _risk_score(scan_data),
    }


def _auth_profile(scan_data: dict[str, Any]) -> dict[str, Any]:
    profile = scan_data.get("auth_profile") if isinstance(scan_data.get("auth_profile"), dict) else {}
    return {
        "id": _clean(profile.get("id"), "public"),
        "name": _clean(profile.get("name"), "Public"),
        "authenticated": bool(profile.get("authenticated")),
    }


def _urls_by_key(scan_data: dict[str, Any]) -> dict[str, dict[str, Any]]:
    inventory = scan_data.get("inventory") if isinstance(scan_data.get("inventory"), dict) else {}
    urls = inventory.get("urls") if isinstance(inventory.get("urls"), list) else []
    output: dict[str, dict[str, Any]] = {}
    for item in urls:
        if isinstance(item, dict):
            key = _clean(item.get("url"))
            if key:
                output[key] = {
                    "url": key,
                    "status_code": item.get("status_code"),
                    "content_type": _clean(item.get("content_type")),
                    "forms_found": _int(item.get("forms_found")),
                    "interesting": bool(item.get("interesting")),
                    "route_types": _string_list(item.get("route_types")),
                    "sources": _string_list(item.get("sources")),
                }
    return output


def _entry_points_by_key(scan_data: dict[str, Any]) -> dict[str, dict[str, Any]]:
    entry_points = scan_data.get("entry_points") if isinstance(scan_data.get("entry_points"), dict) else {}
    endpoints = entry_points.get("endpoints") if isinstance(entry_points.get("endpoints"), list) else []
    output: dict[str, dict[str, Any]] = {}
    for item in endpoints:
        if isinstance(item, dict):
            key = _clean(item.get("url"))
            if key:
                output[key] = {
                    "id": _clean(item.get("id")),
                    "url": key,
                    "state": _clean(item.get("state")),
                    "status_code": item.get("status_code"),
                    "methods": _string_list(item.get("methods")),
                    "parameters": [_clean(param.get("name")) for param in _dict_list(item.get("parameters")) if _clean(param.get("name"))],
                    "forms": _string_list(item.get("forms")),
                    "route_types": _string_list(item.get("route_types")),
                    "review_candidate": bool(item.get("review_candidate")),
                }
    return output


def _risk_score(scan_data: dict[str, Any]) -> int:
    assessment = scan_data.get("assessment") if isinstance(scan_data.get("assessment"), dict) else {}
    summary = assessment.get("summary") if isinstance(assessment.get("summary"), dict) else {}
    return _int(summary.get("risk_score"))


def _review_notes(
    new_url_keys: list[str],
    new_entry_keys: list[str],
    status_changes: list[dict[str, Any]],
    method_changes: list[dict[str, Any]],
) -> list[str]:
    notes: list[str] = []
    if new_url_keys:
        notes.append("The current role exposes URLs that were not visible in the baseline scan.")
    if new_entry_keys:
        notes.append("The current role exposes additional entry points that should be mapped to intended permissions.")
    if status_changes:
        notes.append("Some shared URLs return different status codes across roles; review intended access boundaries.")
    if method_changes:
        notes.append("Some shared entry points advertise different methods across roles; confirm route-level authorization.")
    if not notes:
        notes.append("No role-based surface differences were detected from the available passive evidence.")
    return notes


def _dict_list(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return sorted({_clean(item) for item in value if _clean(item)})


def _clean(value: Any, default: str = "") -> str:
    text = str(value or "").strip()
    return text or default


def _int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0
