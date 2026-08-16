from __future__ import annotations

import json
import webbrowser
from base64 import b64encode
from dataclasses import fields
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from ..ai.analyzer import analyze_scan_data
from ..compare import compare_scans
from ..config import AuditConfig
from ..engine import run_scan
from ..errors import AuditError
from ..history import DEFAULT_HISTORY_DIR, list_history, load_scan_reference, save_analysis_for_history, save_scan_history
from ..inventory import build_inventory_from_scan
from ..lab import DEFAULT_LAB_HOST, DEFAULT_LAB_PORT, LabManager
from ..projects import create_project, list_projects, load_project, load_project_config, project_report_metadata
from ..reporting import generate_html_report, generate_markdown_report, generate_pdf_report


WEB_ROOT = Path(__file__).resolve().parent
MAX_REQUEST_BYTES = 2_000_000
LAB_MANAGER = LabManager()


class LocalAuditHandler(BaseHTTPRequestHandler):
    server_version = "AIWebAuditorGUI/0.13"

    def do_GET(self) -> None:  # noqa: N802 - http.server uses this naming.
        parsed = urlparse(self.path)
        path = parsed.path
        if path == "/":
            self._send_file(WEB_ROOT / "templates" / "index.html", "text/html; charset=utf-8")
            return
        if path == "/api/health":
            self._send_json({"ok": True})
            return
        if path == "/api/projects":
            self._send_json({"ok": True, "items": [_project_to_gui_dict(project) for project in list_projects()]})
            return
        if path == "/api/lab/status":
            self._send_json({"ok": True, "lab": LAB_MANAGER.status().to_dict()})
            return
        if path == "/api/history":
            history_dir = _history_dir_from_project_id(_query_value(parsed.query, "project"))
            self._send_json({"ok": True, "items": [entry.to_dict() for entry in list_history(history_dir)]})
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
            if path == "/api/analyze":
                self._handle_analyze(payload)
                return
            if path == "/api/projects/create":
                self._handle_project_create(payload)
                return
            if path == "/api/lab/start":
                self._handle_lab_start(payload)
                return
            if path == "/api/lab/stop":
                self._handle_lab_stop()
                return
            if path == "/api/history/load":
                self._handle_history_load(payload)
                return
            if path == "/api/compare":
                self._handle_compare(payload)
                return
            self._send_json({"ok": False, "error": "Not found"}, status=404)
        except (AuditError, OSError, ValueError) as exc:
            self._send_json({"ok": False, "error": str(exc)}, status=400)
        except Exception as exc:  # Defensive boundary for the local UI.
            self._send_json({"ok": False, "error": f"{exc.__class__.__name__}: {exc}"}, status=500)

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _handle_scan(self, payload: dict[str, Any]) -> None:
        project = _project_from_payload(payload)
        target = str(payload.get("target", "")).strip()
        config = None
        if not target and project:
            config = load_project_config(project)
            target = config.target.url
        if not target:
            raise ValueError("Target URL is required")

        config = config or build_config_from_gui_payload(payload)
        result = run_scan(target, config)
        result_data = result.to_dict()
        response: dict[str, Any] = {"ok": True, "result": result_data}
        if _bool_value(payload.get("save_history"), False):
            history_dir = project.audit_history_dir if project else DEFAULT_HISTORY_DIR
            entry = save_scan_history(result_data, history_dir=history_dir, label=_clean_text(payload.get("history_label")))
            result_data = load_scan_reference(entry.id, history_dir=history_dir)
            response["history_entry"] = entry.to_dict()
            response["result"] = result_data
        if project:
            response["project"] = project.to_dict()
        self._send_json(response)

    def _handle_analyze(self, payload: dict[str, Any]) -> None:
        project = _project_from_payload(payload)
        scan_data = payload.get("scan")
        if not isinstance(scan_data, dict):
            raise ValueError("scan must be a JSON object")

        config = AuditConfig()
        ai_payload = payload.get("ai") if isinstance(payload.get("ai"), dict) else {}
        if ai_payload.get("provider"):
            config.ai.provider = _clean_text(ai_payload.get("provider"))
        if ai_payload.get("model"):
            config.ai.model = _clean_text(ai_payload.get("model"))
        if ai_payload.get("language"):
            config.ai.language = _clean_text(ai_payload.get("language"))
        config.ai.max_input_chars = _int_value(ai_payload.get("max_input_chars"), config.ai.max_input_chars, minimum=1000, maximum=250000)

        history = scan_data.get("_history") if isinstance(scan_data.get("_history"), dict) else {}
        source = f"history:{history.get('id')}" if history.get("id") else "gui"
        result = analyze_scan_data(
            scan_data,
            config,
            source=source,
            dry_run=_bool_value(payload.get("dry_run"), False),
        )
        analysis_data = result.to_dict()
        response: dict[str, Any] = {"ok": True, "analysis": analysis_data}

        if not _bool_value(payload.get("dry_run"), False) and _bool_value(payload.get("save_to_history"), True):
            history_id = _clean_text(history.get("id"))
            if history_id:
                history_dir = project.audit_history_dir if project else DEFAULT_HISTORY_DIR
                response["scan"] = save_analysis_for_history(history_id, analysis_data, history_dir=history_dir)

        self._send_json(response)

    def _handle_report(self, payload: dict[str, Any]) -> None:
        project = _project_from_payload(payload)
        scan_data = payload.get("scan")
        if not isinstance(scan_data, dict):
            raise ValueError("scan must be a JSON object")

        ai_analysis = payload.get("ai_analysis")
        if ai_analysis is not None and not isinstance(ai_analysis, dict):
            raise ValueError("ai_analysis must be a JSON object")

        title = payload.get("title")
        metadata = _report_metadata_from_payload(payload, project=project)
        report_format = str(payload.get("format", "all")).strip().lower() or "all"

        markdown = generate_markdown_report(
            scan_data,
            ai_analysis=ai_analysis,
            title=str(title).strip() if title else None,
            metadata=metadata,
        )
        response: dict[str, Any] = {"ok": True}

        if report_format in {"all", "markdown"}:
            response["markdown"] = markdown
        if report_format in {"all", "html"}:
            response["html"] = generate_html_report(
                scan_data,
                ai_analysis=ai_analysis,
                title=str(title).strip() if title else None,
                metadata=metadata,
            )
        if report_format in {"all", "pdf"}:
            response["pdf_base64"] = b64encode(
                generate_pdf_report(
                    scan_data,
                    ai_analysis=ai_analysis,
                    title=str(title).strip() if title else None,
                    metadata=metadata,
                )
            ).decode("ascii")
        if report_format not in {"all", "markdown", "html", "pdf"}:
            raise ValueError(f"Unsupported report format: {report_format}")

        self._send_json(response)

    def _handle_project_create(self, payload: dict[str, Any]) -> None:
        name = _clean_text(payload.get("name"))
        if not name:
            raise ValueError("Project name is required")
        project = create_project(
            name,
            target=_clean_text(payload.get("target")),
            client=_clean_text(payload.get("client")),
            auditor=_clean_text(payload.get("auditor")),
            engagement=_clean_text(payload.get("engagement")),
            scope_summary=_clean_text(payload.get("scope_summary")),
            force=_bool_value(payload.get("force"), False),
        )
        self._send_json({"ok": True, "project": _project_to_gui_dict(project)})

    def _handle_lab_start(self, payload: dict[str, Any]) -> None:
        host = _clean_text(payload.get("host")) or DEFAULT_LAB_HOST
        port = _int_value(payload.get("port"), DEFAULT_LAB_PORT, minimum=1, maximum=65535)
        self._send_json({"ok": True, "lab": LAB_MANAGER.start(host=host, port=port).to_dict()})

    def _handle_lab_stop(self) -> None:
        self._send_json({"ok": True, "lab": LAB_MANAGER.stop().to_dict()})

    def _handle_history_load(self, payload: dict[str, Any]) -> None:
        identifier = _clean_text(payload.get("id"))
        if not identifier:
            raise ValueError("History id is required")
        history_dir = _history_dir_from_payload(payload)
        scan = load_scan_reference(identifier, history_dir=history_dir)
        scan["inventory"] = build_inventory_from_scan(scan)
        self._send_json({"ok": True, "scan": scan})

    def _handle_compare(self, payload: dict[str, Any]) -> None:
        baseline_id = _clean_text(payload.get("baseline_id"))
        current_id = _clean_text(payload.get("current_id"))
        if not baseline_id or not current_id:
            raise ValueError("Both baseline_id and current_id are required")
        history_dir = _history_dir_from_payload(payload)
        baseline = load_scan_reference(baseline_id, history_dir=history_dir)
        current = load_scan_reference(current_id, history_dir=history_dir)
        self._send_json({"ok": True, "comparison": compare_scans(baseline, current)})

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

    subdomains = payload.get("subdomains") if isinstance(payload.get("subdomains"), dict) else {}
    config.subdomains.max_candidates = _int_value(subdomains.get("max_candidates"), 25, minimum=1, maximum=100)
    config.subdomains.timeout_seconds = _float_value(subdomains.get("timeout_seconds"), 2.0, minimum=0.5, maximum=10.0)

    modules = payload.get("modules") if isinstance(payload.get("modules"), dict) else {}
    for module_field in fields(config.modules):
        if module_field.name in modules:
            setattr(config.modules, module_field.name, _bool_value(modules[module_field.name], True))

    return config


def _report_metadata_from_payload(payload: dict[str, Any], *, project: object | None = None) -> dict[str, str]:
    metadata = payload.get("metadata")
    if not isinstance(metadata, dict):
        metadata = {}
    defaults = project_report_metadata(project) if project else {}
    return {
        "client": _clean_text(metadata.get("client")) or defaults.get("client", ""),
        "auditor": _clean_text(metadata.get("auditor")) or defaults.get("auditor", ""),
        "engagement": _clean_text(metadata.get("engagement")) or defaults.get("engagement", ""),
        "scope_summary": _clean_text(metadata.get("scope_summary")) or defaults.get("scope_summary", ""),
        "notes": _clean_text(metadata.get("notes")),
    }


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


def _clean_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _paths(value: Any, *, default: list[str]) -> list[str]:
    items = _split_items(value)
    if not items:
        return list(default)
    output: list[str] = []
    for item in items:
        output.append(item if item.startswith("/") else f"/{item}")
    return output


def _project_from_payload(payload: dict[str, Any]) -> object | None:
    project_id = _clean_text(payload.get("project_id"))
    if not project_id:
        return None
    return load_project(project_id)


def _history_dir_from_payload(payload: dict[str, Any]) -> Path:
    return _history_dir_from_project_id(_clean_text(payload.get("project_id")))


def _history_dir_from_project_id(project_id: str) -> Path:
    if not project_id:
        return DEFAULT_HISTORY_DIR
    return load_project(project_id).audit_history_dir


def _query_value(query: str, name: str) -> str:
    values = parse_qs(query).get(name, [])
    return values[0] if values else ""


def _project_to_gui_dict(project: object) -> dict[str, Any]:
    data = project.to_dict()
    try:
        data["config"] = load_project_config(project).to_dict()
    except (OSError, ValueError):
        data["config"] = {}
    return data


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
