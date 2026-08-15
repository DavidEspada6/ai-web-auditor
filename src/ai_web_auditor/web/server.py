from __future__ import annotations

import json
import webbrowser
from dataclasses import fields
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from ..config import AuditConfig
from ..engine import run_scan
from ..errors import AuditError
from ..reporting import generate_markdown_report


WEB_ROOT = Path(__file__).resolve().parent
MAX_REQUEST_BYTES = 2_000_000


class LocalAuditHandler(BaseHTTPRequestHandler):
    server_version = "AIWebAuditorGUI/0.6"

    def do_GET(self) -> None:  # noqa: N802 - http.server uses this naming.
        path = urlparse(self.path).path
        if path == "/":
            self._send_file(WEB_ROOT / "templates" / "index.html", "text/html; charset=utf-8")
            return
        if path == "/api/health":
            self._send_json({"ok": True})
            return
        if path.startswith("/static/"):
            relative = path.removeprefix("/static/")
            self._send_static(relative)
            return
        self._send_json({"ok": False, "error": "Not found"}, status=404)

    def do_POST(self) -> None:  # noqa: N802 - http.server uses this naming.
        path = urlparse(self.path).path
        try:
            payload = self._read_json_payload()
            if path == "/api/scan":
                self._handle_scan(payload)
                return
            if path == "/api/report":
                self._handle_report(payload)
                return
            self._send_json({"ok": False, "error": "Not found"}, status=404)
        except (AuditError, OSError, ValueError) as exc:
            self._send_json({"ok": False, "error": str(exc)}, status=400)
        except Exception as exc:  # Defensive boundary for the local UI.
            self._send_json({"ok": False, "error": f"{exc.__class__.__name__}: {exc}"}, status=500)

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _handle_scan(self, payload: dict[str, Any]) -> None:
        target = str(payload.get("target", "")).strip()
        if not target:
            raise ValueError("Target URL is required")

        config = build_config_from_gui_payload(payload)
        result = run_scan(target, config)
        self._send_json({"ok": True, "result": result.to_dict()})

    def _handle_report(self, payload: dict[str, Any]) -> None:
        scan_data = payload.get("scan")
        if not isinstance(scan_data, dict):
            raise ValueError("scan must be a JSON object")

        ai_analysis = payload.get("ai_analysis")
        if ai_analysis is not None and not isinstance(ai_analysis, dict):
            raise ValueError("ai_analysis must be a JSON object")

        title = payload.get("title")
        markdown = generate_markdown_report(
            scan_data,
            ai_analysis=ai_analysis,
            title=str(title).strip() if title else None,
        )
        self._send_json({"ok": True, "markdown": markdown})

    def _send_static(self, relative: str) -> None:
        if not relative or ".." in relative.replace("\\", "/").split("/"):
            self._send_json({"ok": False, "error": "Invalid static path"}, status=400)
            return

        file_path = WEB_ROOT / "static" / relative
        content_types = {
            ".css": "text/css; charset=utf-8",
            ".js": "application/javascript; charset=utf-8",
        }
        content_type = content_types.get(file_path.suffix.lower(), "application/octet-stream")
        self._send_file(file_path, content_type)

    def _send_file(self, path: Path, content_type: str) -> None:
        if not path.exists() or not path.is_file():
            self._send_json({"ok": False, "error": "Not found"}, status=404)
            return
        body = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _read_json_payload(self) -> dict[str, Any]:
        raw_length = self.headers.get("Content-Length", "0")
        length = int(raw_length)
        if length > MAX_REQUEST_BYTES:
            raise ValueError("Request body is too large")
        body = self.rfile.read(length)
        if not body:
            return {}
        payload = json.loads(body.decode("utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("JSON body must be an object")
        return payload

    def _send_json(self, payload: dict[str, Any], status: int = 200) -> None:
        body = json.dumps(payload, ensure_ascii=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)


def build_config_from_gui_payload(payload: dict[str, Any]) -> AuditConfig:
    config = AuditConfig()
    target = str(payload.get("target", "")).strip()
    config.target.url = target

    config.scope.allowed_hosts = _split_items(payload.get("allowed_hosts"))
    config.scope.allow_subdomains = _bool_value(payload.get("allow_subdomains"), True)
    config.scope.allow_private_networks = _bool_value(payload.get("allow_private_networks"), False)
    config.scope.resolve_dns = _bool_value(payload.get("resolve_dns"), True)
    config.scope.include_paths = _paths(payload.get("include_paths"), default=["/"])
    config.scope.exclude_paths = _paths(payload.get("exclude_paths"), default=[])

    config.http.timeout_seconds = _float_value(payload.get("timeout_seconds"), 10.0, minimum=1.0, maximum=60.0)
    config.http.max_redirects = _int_value(payload.get("max_redirects"), 10, minimum=0, maximum=20)
    config.http.check_http_counterpart = _bool_value(payload.get("check_http_counterpart"), True)

    crawler = payload.get("crawler") if isinstance(payload.get("crawler"), dict) else {}
    config.crawler.max_depth = _int_value(crawler.get("max_depth"), 1, minimum=0, maximum=3)
    config.crawler.max_pages = _int_value(crawler.get("max_pages"), 25, minimum=1, maximum=100)
    config.crawler.delay_seconds = _float_value(crawler.get("delay_seconds"), 0.0, minimum=0.0, maximum=10.0)

    modules = payload.get("modules") if isinstance(payload.get("modules"), dict) else {}
    for module_field in fields(config.modules):
        if module_field.name in modules:
            setattr(config.modules, module_field.name, _bool_value(modules[module_field.name], True))

    return config


def serve_gui(host: str = "127.0.0.1", port: int = 8765, open_browser: bool = True) -> None:
    server = _bind_server(host, port)
    actual_host, actual_port = server.server_address[:2]
    display_host = host if host != "0.0.0.0" else actual_host
    url = f"http://{display_host}:{actual_port}/"
    print(f"AI Web Auditor GUI running at {url}")
    print("Press Ctrl+C to stop.")
    if open_browser:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping GUI server.")
    finally:
        server.server_close()


def _bind_server(host: str, port: int) -> ThreadingHTTPServer:
    last_error: OSError | None = None
    for candidate in range(port, port + 21):
        try:
            return ThreadingHTTPServer((host, candidate), LocalAuditHandler)
        except OSError as exc:
            last_error = exc
            if not _is_address_in_use(exc):
                break
    raise OSError(f"Could not bind local GUI server: {last_error}")


def _is_address_in_use(exc: OSError) -> bool:
    return getattr(exc, "winerror", None) == 10048 or getattr(exc, "errno", None) in {48, 98, 10048}


def _split_items(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    if value is None:
        return []
    return [item.strip() for item in str(value).split(",") if item.strip()]


def _paths(value: Any, *, default: list[str]) -> list[str]:
    items = _split_items(value)
    if not items:
        return list(default)
    output: list[str] = []
    for item in items:
        output.append(item if item.startswith("/") else f"/{item}")
    return output


def _bool_value(value: Any, default: bool) -> bool:
    if value is None or value == "":
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "y", "si", "s", "on"}


def _int_value(value: Any, default: int, *, minimum: int, maximum: int) -> int:
    if value is None or value == "":
        return default
    number = int(value)
    if number < minimum or number > maximum:
        raise ValueError(f"Value must be between {minimum} and {maximum}")
    return number


def _float_value(value: Any, default: float, *, minimum: float, maximum: float) -> float:
    if value is None or value == "":
        return default
    number = float(value)
    if number < minimum or number > maximum:
        raise ValueError(f"Value must be between {minimum:g} and {maximum:g}")
    return number
