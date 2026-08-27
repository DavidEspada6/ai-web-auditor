from __future__ import annotations

from pathlib import PurePosixPath
from typing import Any
from urllib.parse import urlsplit


ROUTE_RULES: tuple[dict[str, Any], ...] = (
    {
        "type": "admin",
        "label": "Administration",
        "confidence": "high",
        "markers": ("/admin", "/administrator", "/wp-admin", "/cpanel", "/manager", "/manage", "/panel"),
        "reason": "admin_path",
        "interesting": True,
    },
    {
        "type": "login",
        "label": "Login or authentication",
        "confidence": "high",
        "markers": ("/login", "/signin", "/sign-in", "/auth", "/sso", "/session", "/account/login", "/members"),
        "reason": "login_path",
        "interesting": True,
    },
    {
        "type": "logout",
        "label": "Logout or session termination",
        "confidence": "medium",
        "markers": ("/logout", "/signout", "/sign-out", "/session/end"),
        "reason": "logout_path",
        "interesting": True,
    },
    {
        "type": "password_reset",
        "label": "Password reset or account recovery",
        "confidence": "high",
        "markers": ("/reset", "/forgot", "/recover", "/recovery", "/change-password", "/password"),
        "reason": "password_reset_path",
        "interesting": True,
    },
    {
        "type": "account",
        "label": "Account, member or customer area",
        "confidence": "medium",
        "markers": ("/account", "/profile", "/dashboard", "/members", "/member", "/clientes", "/customer", "/private", "/internal"),
        "reason": "account_area",
        "interesting": True,
    },
    {
        "type": "api",
        "label": "API surface",
        "confidence": "high",
        "markers": ("/api", "/graphql", "/rest", "/openapi", "/swagger", "/api-docs"),
        "reason": "api_path",
        "interesting": True,
    },
    {
        "type": "upload",
        "label": "File upload or import",
        "confidence": "high",
        "markers": ("/upload", "/uploads", "/import", "/avatar", "/attachment", "/file", "/media"),
        "reason": "upload_path",
        "interesting": True,
    },
    {
        "type": "search",
        "label": "Search or filtering",
        "confidence": "medium",
        "markers": ("/search", "/buscar", "/query", "/filter", "/find"),
        "reason": "search_path",
        "interesting": True,
    },
    {
        "type": "callback",
        "label": "Callback, webhook or federation flow",
        "confidence": "high",
        "markers": ("/callback", "/webhook", "/oauth", "/oidc", "/saml", "/redirect", "/return"),
        "reason": "callback_path",
        "interesting": True,
    },
    {
        "type": "payment",
        "label": "Payment or billing",
        "confidence": "medium",
        "markers": ("/checkout", "/payment", "/billing", "/invoice", "/stripe", "/paypal"),
        "reason": "payment_path",
        "interesting": True,
    },
    {
        "type": "documentation",
        "label": "Documentation or API documentation",
        "confidence": "medium",
        "markers": ("/docs", "/documentation", "/swagger", "/openapi", "/api-docs", "/redoc"),
        "reason": "documentation_path",
        "interesting": True,
    },
    {
        "type": "health",
        "label": "Health, status or metrics",
        "confidence": "medium",
        "markers": ("/status", "/health", "/ready", "/live", "/metrics", "/actuator"),
        "reason": "health_status_path",
        "interesting": True,
    },
    {
        "type": "debug",
        "label": "Debug or diagnostic surface",
        "confidence": "high",
        "markers": ("/debug", "/trace", "/phpinfo", "/server-status", "/actuator/env", "/actuator/heapdump"),
        "reason": "debug_path",
        "interesting": True,
    },
    {
        "type": "sensitive_file",
        "label": "Sensitive file or backup pattern",
        "confidence": "high",
        "markers": ("/.env", "/.git", "/config", "/backup", "/dump", "/db", "/database", "/id_rsa", ".bak", ".old", ".sql"),
        "reason": "sensitive_file",
        "interesting": True,
    },
)

STATIC_EXTENSIONS = {
    ".avif",
    ".css",
    ".gif",
    ".ico",
    ".jpeg",
    ".jpg",
    ".js",
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


def classify_url(
    url: str,
    *,
    forms_found: int = 0,
    content_type: str = "",
    methods: list[str] | None = None,
) -> list[dict[str, Any]]:
    parsed = urlsplit(url)
    target = f"{parsed.path or '/'}?{parsed.query}".lower()
    path = parsed.path or "/"
    output: list[dict[str, Any]] = []

    for rule in ROUTE_RULES:
        markers = rule["markers"]
        if any(str(marker).lower() in target for marker in markers):
            output.append(_classification(rule))

    suffix = PurePosixPath(path.lower()).suffix
    if suffix in STATIC_EXTENSIONS or _main_content_type(content_type).startswith(("image/", "font/", "video/", "audio/")):
        output.append(
            {
                "type": "static_asset",
                "label": "Static asset",
                "confidence": "medium",
                "reason": "static_asset",
                "interesting": False,
            }
        )

    if forms_found > 0:
        output.append(
            {
                "type": "form",
                "label": "HTML form",
                "confidence": "high",
                "reason": "form_detected",
                "interesting": True,
            }
        )

    normalized_methods = {str(method).upper() for method in methods or [] if str(method).strip()}
    if "POST" in normalized_methods:
        output.append(
            {
                "type": "state_changing_candidate",
                "label": "State-changing candidate",
                "confidence": "medium",
                "reason": "post_method",
                "interesting": True,
            }
        )

    return _dedupe(output)


def interesting_reasons(url: str, *, forms_found: int = 0, content_type: str = "", methods: list[str] | None = None) -> list[str]:
    return [
        item["reason"]
        for item in classify_url(url, forms_found=forms_found, content_type=content_type, methods=methods)
        if item.get("interesting")
    ]


def route_types(classifications: list[dict[str, Any]]) -> list[str]:
    return sorted({str(item.get("type")) for item in classifications if item.get("type")})


def _classification(rule: dict[str, Any]) -> dict[str, Any]:
    return {
        "type": rule["type"],
        "label": rule["label"],
        "confidence": rule["confidence"],
        "reason": rule["reason"],
        "interesting": bool(rule["interesting"]),
    }


def _dedupe(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    output: list[dict[str, Any]] = []
    for item in items:
        key = str(item.get("type"))
        if key in seen:
            continue
        seen.add(key)
        output.append(item)
    return output


def _main_content_type(value: str) -> str:
    return str(value or "").split(";", 1)[0].strip().lower()
