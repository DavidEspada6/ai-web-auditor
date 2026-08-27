from __future__ import annotations

import hashlib
import json
import re
from io import BytesIO
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from zipfile import ZIP_DEFLATED, ZipFile

from .config import EvidenceCaptureConfig
from .models import utc_now


REDACTED = "[redacted]"
SENSITIVE_HEADERS = {
    "authorization",
    "cookie",
    "proxy-authorization",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "x-csrf-token",
    "x-xsrf-token",
}
SENSITIVE_QUERY_MARKERS = {
    "access_token",
    "api_key",
    "apikey",
    "auth",
    "bearer",
    "code",
    "csrf",
    "jwt",
    "key",
    "pass",
    "password",
    "refresh_token",
    "secret",
    "session",
    "sid",
    "token",
}
SECRET_PATTERN = re.compile(
    r"(?i)\b([a-z0-9_.-]*(?:access[_-]?token|api[_-]?key|authorization|bearer|client[_-]?secret|csrf|jwt|pass(?:word)?|refresh[_-]?token|secret|session|token)[a-z0-9_.-]*)\b"
    r"(\s*[:=]\s*)"
    r"([\"']?)[^\"'&\s<>{}]{4,}",
)
JWT_PATTERN = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")


def sanitize_url(url: str) -> str:
    parsed = urlsplit(url)
    if not parsed.query:
        return url
    query = []
    for key, value in parse_qsl(parsed.query, keep_blank_values=True):
        query.append((key, REDACTED if _is_sensitive_name(key) else value))
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(query, doseq=True), parsed.fragment))


def sanitize_headers(headers: dict[str, str] | list[tuple[str, str]]) -> dict[str, str]:
    items = headers.items() if isinstance(headers, dict) else headers
    output: dict[str, str] = {}
    for key, value in items:
        output[key] = sanitize_header_value(key, value)
    return output


def sanitize_header_value(name: str, value: str) -> str:
    lowered = name.strip().lower()
    if lowered == "set-cookie":
        return _sanitize_set_cookie(value)
    if lowered == "cookie":
        return _sanitize_cookie(value)
    if lowered in SENSITIVE_HEADERS or _is_sensitive_name(lowered):
        return REDACTED
    return _redact_text(value)


def build_body_capture(body: bytes, content_type: str, *, body_truncated: bool, config: EvidenceCaptureConfig) -> dict[str, Any]:
    capture: dict[str, Any] = {
        "captured": False,
        "content_type": content_type or "",
        "sha256": hashlib.sha256(body).hexdigest() if body else "",
        "bytes": len(body),
        "truncated_by_probe": body_truncated,
    }
    if not config.enabled or not config.capture_response_body_sample:
        capture["reason"] = "disabled"
        return capture
    if not body:
        capture["reason"] = "empty"
        return capture
    if not _is_text_content(content_type, config.text_content_types):
        capture["reason"] = "non_text_content"
        return capture

    text = _decode_body(body, content_type)
    redacted = _redact_text(text)
    sample = redacted[: config.max_body_chars]
    capture.update(
        {
            "captured": True,
            "sample": sample,
            "sample_chars": len(sample),
            "sample_truncated": len(redacted) > len(sample),
        }
    )
    return capture


def write_evidence_package(scan_data: dict[str, Any], output: Path) -> Path:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(build_evidence_package(scan_data))
    return output


def build_evidence_package(scan_data: dict[str, Any]) -> bytes:
    safe_scan_data = sanitize_scan_data(scan_data)
    manifest = build_evidence_manifest(safe_scan_data)
    buffer = BytesIO()
    with ZipFile(buffer, "w", compression=ZIP_DEFLATED) as archive:
        _write_json(archive, "manifest.json", manifest)
        archive.writestr("README.md", _package_readme(manifest))
        _write_json(archive, "scan-result.json", safe_scan_data)
        _write_json(archive, "findings/findings.json", _list_value(safe_scan_data.get("findings")))
        _write_json(archive, "modules/modules.json", _list_value(safe_scan_data.get("modules")))
        _write_json(archive, "http/requests.json", _list_value(safe_scan_data.get("requests")))

        for request in _list_value(safe_scan_data.get("requests")):
            if not isinstance(request, dict):
                continue
            request_id = str(request.get("id") or "request")
            safe_id = _safe_filename(request_id)
            _write_json(archive, f"http/{safe_id}.json", request)

        inventory = safe_scan_data.get("inventory")
        if isinstance(inventory, dict):
            _write_json(archive, "inventory/inventory.json", inventory)

        entry_points = safe_scan_data.get("entry_points")
        if isinstance(entry_points, dict):
            _write_json(archive, "entry-points/entry-points.json", entry_points)

        assessment = safe_scan_data.get("assessment")
        if isinstance(assessment, dict):
            _write_json(archive, "assessment/assessment.json", assessment)
    return buffer.getvalue()


def build_evidence_manifest(scan_data: dict[str, Any]) -> dict[str, Any]:
    scan_data = sanitize_scan_data(scan_data)
    target = scan_data.get("target") if isinstance(scan_data.get("target"), dict) else {}
    requests = _list_value(scan_data.get("requests"))
    findings = _list_value(scan_data.get("findings"))
    modules = _list_value(scan_data.get("modules"))
    entry_points = scan_data.get("entry_points") if isinstance(scan_data.get("entry_points"), dict) else {}
    endpoint_list = _list_value(entry_points.get("endpoints")) if entry_points else []
    captured_bodies = [
        item
        for item in requests
        if isinstance(item, dict)
        and isinstance(item.get("response_body"), dict)
        and item["response_body"].get("captured") is True
    ]
    return {
        "tool": "ai-web-auditor",
        "scan_version": scan_data.get("version", "unknown"),
        "package_version": "1.0",
        "generated_at": utc_now(),
        "scan_generated_at": scan_data.get("generated_at", "unknown"),
        "target": {
            "url": target.get("normalized_url") or target.get("original_url") or "unknown",
            "host": target.get("host", "unknown"),
        },
        "counts": {
            "modules": len([item for item in modules if isinstance(item, dict)]),
            "findings": len([item for item in findings if isinstance(item, dict)]),
            "requests": len([item for item in requests if isinstance(item, dict)]),
            "entry_points": len([item for item in endpoint_list if isinstance(item, dict)]),
            "captured_body_samples": len(captured_bodies),
        },
        "safety": {
            "sanitized": True,
            "raw_request_bodies_included": False,
            "response_bodies_are_samples": True,
            "sensitive_headers_redacted": sorted(SENSITIVE_HEADERS),
            "sensitive_query_values_redacted": True,
        },
        "files": [
            "manifest.json",
            "README.md",
            "scan-result.json",
            "findings/findings.json",
            "modules/modules.json",
            "http/requests.json",
            "http/<request-id>.json",
            "inventory/inventory.json",
            "entry-points/entry-points.json",
            "assessment/assessment.json",
        ],
    }


def evidence_package_filename(scan_data: dict[str, Any]) -> str:
    scan_data = sanitize_scan_data(scan_data)
    target = scan_data.get("target") if isinstance(scan_data.get("target"), dict) else {}
    host = str(target.get("host") or "target")
    generated = str(scan_data.get("generated_at") or utc_now()).replace(":", "").replace("T", "-").replace("Z", "")
    return f"evidence-{_safe_filename(host)}-{_safe_filename(generated)}.zip"


def sanitize_scan_data(value: Any, parent_key: str = "") -> Any:
    if isinstance(value, dict):
        output: dict[str, Any] = {}
        evidence_label = str(value.get("label", "")).strip().lower()
        for key, item in value.items():
            if str(key).strip().lower() in SENSITIVE_HEADERS:
                output[key] = sanitize_header_value(str(key), str(item))
            elif str(key).strip().lower() == "value" and evidence_label == "set-cookie":
                output[key] = sanitize_header_value("set-cookie", str(item))
            elif str(key).strip().lower() == "value" and evidence_label and _is_sensitive_key(evidence_label) and evidence_label != "cookie":
                output[key] = REDACTED
            elif _is_sensitive_key(str(key)):
                output[key] = REDACTED
            else:
                output[key] = sanitize_scan_data(item, str(key))
        return output
    if isinstance(value, list):
        return [sanitize_scan_data(item, parent_key) for item in value]
    if isinstance(value, str):
        if parent_key in {"url", "final_url", "original_url", "normalized_url", "base_url", "target"} and value.startswith(("http://", "https://")):
            return sanitize_url(value)
        return _redact_text(value)
    return value


def _package_readme(manifest: dict[str, Any]) -> str:
    target = manifest.get("target") if isinstance(manifest.get("target"), dict) else {}
    counts = manifest.get("counts") if isinstance(manifest.get("counts"), dict) else {}
    return (
        "# AI Web Auditor Evidence Package\n\n"
        f"- Target: {target.get('url', 'unknown')}\n"
        f"- Scan generated at: {manifest.get('scan_generated_at', 'unknown')}\n"
        f"- Package generated at: {manifest.get('generated_at', 'unknown')}\n"
        f"- Requests: {counts.get('requests', 0)}\n"
        f"- Findings: {counts.get('findings', 0)}\n"
        f"- Captured body samples: {counts.get('captured_body_samples', 0)}\n\n"
        "This package contains sanitized audit evidence. Sensitive headers, cookie values and sensitive query parameters are redacted. "
        "Response bodies are truncated text samples when available; full raw request bodies are not included.\n"
    )


def _write_json(archive: ZipFile, path: str, data: Any) -> None:
    archive.writestr(path, json.dumps(data, indent=2, ensure_ascii=True) + "\n")


def _list_value(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _safe_filename(value: str) -> str:
    value = re.sub(r"[^A-Za-z0-9._-]+", "-", value).strip("-._")
    return value[:120] or "item"


def _sanitize_cookie(value: str) -> str:
    names = []
    for item in value.split(";"):
        name = item.split("=", 1)[0].strip()
        if name:
            names.append(f"{name}={REDACTED}")
    return "; ".join(names) if names else REDACTED


def _sanitize_set_cookie(value: str) -> str:
    parts = [part.strip() for part in value.split(";") if part.strip()]
    if not parts:
        return REDACTED
    name = parts[0].split("=", 1)[0].strip() or "cookie"
    safe_parts = [f"{name}={REDACTED}"]
    for attribute in parts[1:]:
        attr_name = attribute.split("=", 1)[0].strip()
        if _is_sensitive_name(attr_name):
            safe_parts.append(f"{attr_name}={REDACTED}")
        else:
            safe_parts.append(attribute)
    return "; ".join(safe_parts)


def _redact_text(value: str) -> str:
    value = JWT_PATTERN.sub(REDACTED, value)
    return SECRET_PATTERN.sub(lambda match: f"{match.group(1)}{match.group(2)}{match.group(3)}{REDACTED}{match.group(3)}", value)


def _is_sensitive_name(value: str) -> bool:
    lowered = value.strip().lower()
    return lowered in SENSITIVE_HEADERS or any(marker in lowered for marker in SENSITIVE_QUERY_MARKERS)


def _is_sensitive_key(value: str) -> bool:
    lowered = value.strip().lower().replace("-", "_")
    exact = {item.replace("-", "_") for item in SENSITIVE_HEADERS | SENSITIVE_QUERY_MARKERS}
    suffixes = ("_token", "_secret", "_password", "_api_key", "_session", "_jwt")
    return lowered in exact or lowered.endswith(suffixes)


def _is_text_content(content_type: str, allowed_types: list[str]) -> bool:
    lowered = content_type.lower()
    if not lowered:
        return True
    return any(marker.lower() in lowered for marker in allowed_types)


def _decode_body(body: bytes, content_type: str) -> str:
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
