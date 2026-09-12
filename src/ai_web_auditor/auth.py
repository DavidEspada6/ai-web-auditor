from __future__ import annotations

import re
from dataclasses import asdict, is_dataclass
from typing import Any, Mapping

from .config import AuditConfig, AuthProfileConfig


FORBIDDEN_HEADER_NAMES = {
    "connection",
    "content-length",
    "host",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}

HEADER_NAME_RE = re.compile(r"^[A-Za-z0-9!#$%&'*+.^_`|~-]+$")


def active_auth_profile(config: AuditConfig) -> dict[str, Any] | None:
    active_id = _clean_text(config.auth.active_profile) or "public"
    profiles = [_profile_to_dict(profile) for profile in config.auth.profiles]
    for profile in profiles:
        if _clean_text(profile.get("id")) == active_id:
            return profile
    return None


def auth_request_headers(config: AuditConfig) -> dict[str, str]:
    profile = active_auth_profile(config)
    if not profile:
        return {}

    headers = _clean_headers(profile.get("headers") if isinstance(profile.get("headers"), Mapping) else {})
    cookies = _clean_mapping(profile.get("cookies") if isinstance(profile.get("cookies"), Mapping) else {})
    if cookies and "cookie" not in {key.lower() for key in headers}:
        headers["Cookie"] = "; ".join(f"{name}={value}" for name, value in cookies.items())
    return headers


def auth_profile_metadata(config: AuditConfig) -> dict[str, Any]:
    profile = active_auth_profile(config) or {}
    profile_id = _clean_text(profile.get("id")) or "public"
    profile_name = _clean_text(profile.get("name")) or _default_profile_name(profile_id)
    headers = _clean_headers(profile.get("headers") if isinstance(profile.get("headers"), Mapping) else {})
    cookies = _clean_mapping(profile.get("cookies") if isinstance(profile.get("cookies"), Mapping) else {})
    return {
        "id": profile_id,
        "name": profile_name,
        "authenticated": bool(headers or cookies),
        "request_header_names": sorted(headers),
        "cookie_names": sorted(cookies),
        "notes": _clean_text(profile.get("notes")),
        "sensitive_values_redacted": True,
    }


def upsert_auth_profile(
    config: AuditConfig,
    *,
    profile_id: str,
    name: str = "",
    headers: Mapping[str, Any] | None = None,
    cookies: Mapping[str, Any] | None = None,
    notes: str = "",
) -> None:
    profile_id = _clean_text(profile_id) or "custom"
    profile = AuthProfileConfig(
        id=profile_id,
        name=_clean_text(name) or _default_profile_name(profile_id),
        headers=_clean_headers(headers or {}),
        cookies=_clean_mapping(cookies or {}),
        notes=_clean_text(notes),
    )

    profiles = [_profile_to_config(item) for item in config.auth.profiles]
    for index, existing in enumerate(profiles):
        if existing.id == profile.id:
            profiles[index] = profile
            break
    else:
        profiles.append(profile)

    config.auth.profiles = profiles
    config.auth.active_profile = profile.id


def parse_header_lines(values: list[str] | tuple[str, ...] | None) -> dict[str, str]:
    headers: dict[str, str] = {}
    for value in values or []:
        for line in str(value).splitlines():
            line = line.strip()
            if not line:
                continue
            if ":" not in line:
                raise ValueError("Auth headers must use 'Header-Name: value'")
            name, header_value = line.split(":", 1)
            headers[_clean_header_name(name)] = header_value.strip()
    return headers


def parse_cookie_lines(values: list[str] | tuple[str, ...] | None) -> dict[str, str]:
    cookies: dict[str, str] = {}
    for value in values or []:
        for part in str(value).split(";"):
            part = part.strip()
            if not part:
                continue
            if "=" not in part:
                raise ValueError("Auth cookies must use 'name=value'")
            name, cookie_value = part.split("=", 1)
            name = _clean_cookie_name(name)
            if not name:
                raise ValueError("Auth cookie name cannot be empty")
            cookies[name] = cookie_value.strip()
    return cookies


def _profile_to_config(value: Any) -> AuthProfileConfig:
    data = _profile_to_dict(value)
    return AuthProfileConfig(
        id=_clean_text(data.get("id")) or "custom",
        name=_clean_text(data.get("name")) or _default_profile_name(_clean_text(data.get("id"))),
        headers=_clean_headers(data.get("headers") if isinstance(data.get("headers"), Mapping) else {}),
        cookies=_clean_mapping(data.get("cookies") if isinstance(data.get("cookies"), Mapping) else {}),
        notes=_clean_text(data.get("notes")),
    )


def _profile_to_dict(value: Any) -> dict[str, Any]:
    if is_dataclass(value):
        return asdict(value)
    if isinstance(value, Mapping):
        return dict(value)
    return {}


def _clean_headers(values: Mapping[str, Any]) -> dict[str, str]:
    output: dict[str, str] = {}
    for raw_name, raw_value in values.items():
        name = _clean_header_name(raw_name)
        if raw_value is None:
            continue
        value = str(raw_value).strip()
        if value:
            output[name] = value
    return output


def _clean_mapping(values: Mapping[str, Any]) -> dict[str, str]:
    output: dict[str, str] = {}
    for raw_name, raw_value in values.items():
        name = _clean_cookie_name(raw_name)
        if not name or raw_value is None:
            continue
        value = str(raw_value).strip()
        if value:
            output[name] = value
    return output


def _clean_header_name(value: Any) -> str:
    name = _clean_text(value)
    if not name or not HEADER_NAME_RE.match(name):
        raise ValueError(f"Invalid auth header name: {value}")
    if name.lower() in FORBIDDEN_HEADER_NAMES:
        raise ValueError(f"Auth header is managed by the HTTP client and cannot be overridden: {name}")
    return name


def _clean_cookie_name(value: Any) -> str:
    name = _clean_text(value)
    if not name or any(char in name for char in "=;,\r\n\t "):
        raise ValueError(f"Invalid auth cookie name: {value}")
    return name


def _clean_text(value: Any) -> str:
    return str(value or "").strip()


def _default_profile_name(profile_id: str) -> str:
    if profile_id == "public":
        return "Public"
    return profile_id.replace("-", " ").replace("_", " ").title()
