from __future__ import annotations

import json
import threading
import webbrowser
from dataclasses import asdict, dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlparse


DEFAULT_LAB_HOST = "127.0.0.1"
DEFAULT_LAB_PORT = 8080
LAB_AUDIT_PATH = "/members/"
LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1"}


@dataclass
class LabStatus:
    connected: bool
    host: str = DEFAULT_LAB_HOST
    port: int = DEFAULT_LAB_PORT
    url: str = ""
    target_url: str = ""
    message: str = "Desconectado"

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["scan_defaults"] = lab_scan_defaults(self)
        return data


class RunningLab:
    def __init__(self, server: ThreadingHTTPServer, host: str, port: int, thread: threading.Thread) -> None:
        self.server = server
        self.host = host
        self.port = port
        self.thread = thread

    @property
    def url(self) -> str:
        return _lab_url(self.host, self.port, "/")

    @property
    def target_url(self) -> str:
        return _lab_url(self.host, self.port, LAB_AUDIT_PATH)

    def status(self) -> LabStatus:
        connected = self.thread.is_alive()
        return LabStatus(
            connected=connected,
            host=self.host,
            port=self.port,
            url=self.url,
            target_url=self.target_url,
            message="Conectado" if connected else "Desconectado",
        )

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)


class LabManager:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._lab: RunningLab | None = None

    def start(self, *, host: str = DEFAULT_LAB_HOST, port: int = DEFAULT_LAB_PORT) -> LabStatus:
        with self._lock:
            if self._lab and self._lab.thread.is_alive():
                return self._lab.status()

            lab = start_lab_server(host=host, port=port)
            self._lab = lab
            return lab.status()

    def stop(self) -> LabStatus:
        with self._lock:
            if self._lab:
                self._lab.stop()
                host = self._lab.host
                port = self._lab.port
                self._lab = None
                return disconnected_status(host=host, port=port)
            return disconnected_status()

    def status(self) -> LabStatus:
        with self._lock:
            if self._lab and self._lab.thread.is_alive():
                return self._lab.status()
            return disconnected_status()


class VulnerableLabHandler(BaseHTTPRequestHandler):
    server_version = "AIWebAuditorLab/0.14"
    sys_version = ""

    def do_GET(self) -> None:  # noqa: N802 - http.server uses this naming.
        parsed = urlparse(self.path)
        path = parsed.path
        if path == "/health":
            self._send_json({"status": "ok", "lab": "ai-web-auditor"})
            return
        if path == "/robots.txt":
            self._send_text("User-agent: *\nDisallow: /admin/\nDisallow: /private/\n", "text/plain; charset=utf-8")
            return
        if path == "/sitemap.xml":
            base_url = _lab_url(self.server.server_address[0], int(self.server.server_address[1]), "/")
            body = (
                '<?xml version="1.0" encoding="UTF-8"?>\n'
                '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
                f"  <url><loc>{base_url}</loc></url>\n"
                f"  <url><loc>{base_url}members/</loc></url>\n"
                "</urlset>\n"
            )
            self._send_text(body, "application/xml; charset=utf-8")
            return
        if path == "/members/":
            self._send_members_challenge()
            return
        if path in {"/admin/", "/private/report"}:
            self._send_html("Panel interno de laboratorio", _page("Panel interno", "Ruta sensible de ejemplo para probar el scope."))
            return
        if path == "/":
            self._send_html("Portal de laboratorio", _home_page())
            return
        self._send_html("No encontrado", _page("No encontrado", "Recurso inexistente."), status=404)

    def do_HEAD(self) -> None:  # noqa: N802 - http.server uses this naming.
        self._send_headers(200, "text/html; charset=utf-8", 0)

    def do_OPTIONS(self) -> None:  # noqa: N802 - http.server uses this naming.
        allow = "GET, POST, OPTIONS, PUT, DELETE, TRACE"
        self.send_response(204)
        self.send_header("Allow", allow)
        self.send_header("Access-Control-Allow-Methods", allow)
        self.send_header("X-Powered-By", "PHP/5.6.40")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _send_members_challenge(self) -> None:
        body = _members_page()
        raw = body.encode("utf-8")
        self.send_response(401)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("WWW-Authenticate", 'Basic realm="AI Web Auditor Lab"')
        self.send_header("Set-Cookie", "sessionid=lab-session; Path=/")
        self.send_header("Set-Cookie", "tracking_id=demo; Path=/; SameSite=None")
        self.send_header("X-Powered-By", "PHP/5.6.40")
        self.end_headers()
        self.wfile.write(raw)

    def _send_html(self, title: str, body: str, *, status: int = 200) -> None:
        self._send_text(body, "text/html; charset=utf-8", status=status, title=title)

    def _send_json(self, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, ensure_ascii=True).encode("utf-8")
        self._send_headers(200, "application/json; charset=utf-8", len(body))
        self.wfile.write(body)

    def _send_text(self, text: str, content_type: str, *, status: int = 200, title: str = "") -> None:
        body = text.encode("utf-8")
        self._send_headers(status, content_type, len(body), title=title)
        self.wfile.write(body)

    def _send_headers(self, status: int, content_type: str, content_length: int, *, title: str = "") -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(content_length))
        self.send_header("Set-Cookie", "sessionid=lab-session; Path=/")
        self.send_header("X-Powered-By", "PHP/5.6.40")
        if title:
            self.send_header("X-Lab-Page", title)
        self.end_headers()


def start_lab_server(host: str = DEFAULT_LAB_HOST, port: int = DEFAULT_LAB_PORT) -> RunningLab:
    _validate_local_host(host)
    server = _bind_lab_server(host, port)
    actual_host, actual_port = server.server_address[:2]
    display_host = host if host != "::1" else "[::1]"
    thread = threading.Thread(target=server.serve_forever, name="ai-web-auditor-lab", daemon=True)
    lab = RunningLab(server=server, host=display_host or str(actual_host), port=int(actual_port), thread=thread)
    thread.start()
    return lab


def serve_lab(host: str = DEFAULT_LAB_HOST, port: int = DEFAULT_LAB_PORT, open_browser: bool = True) -> None:
    lab = start_lab_server(host=host, port=port)
    print(f"AI Web Auditor lab running at {lab.url}")
    print(f"Audit target: {lab.target_url}")
    print("Press Ctrl+C to stop.")
    if open_browser:
        webbrowser.open(lab.url)
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        print("\nStopping lab server.")
    finally:
        lab.stop()


def disconnected_status(*, host: str = DEFAULT_LAB_HOST, port: int = DEFAULT_LAB_PORT) -> LabStatus:
    return LabStatus(
        connected=False,
        host=host,
        port=port,
        url=_lab_url(host, port, "/"),
        target_url=_lab_url(host, port, LAB_AUDIT_PATH),
        message="Desconectado",
    )


def lab_scan_defaults(status: LabStatus) -> dict[str, Any]:
    return {
        "target": status.target_url,
        "allowed_hosts": status.host.strip("[]"),
        "include_paths": "/",
        "exclude_paths": "/admin, /private, /logout, /delete, /reset",
        "allow_subdomains": False,
        "resolve_dns": False,
        "check_http_counterpart": False,
        "allow_private_networks": True,
        "save_history": True,
        "history_label": "lab-demo-inicial",
        "modules": {
            "scope": True,
            "http": True,
            "security_headers": True,
            "cookies": True,
            "basic_auth": True,
            "http_methods": True,
            "tls": False,
            "subdomains": False,
            "ports": True,
            "fingerprinting": True,
            "crawler": True,
        },
        "crawler": {
            "max_depth": 1,
            "max_pages": 20,
            "delay_seconds": 0.0,
        },
        "subdomains": {
            "max_candidates": 25,
            "timeout_seconds": 2.0,
        },
        "ports": {
            "ports": f"{status.port}, 80, 443",
            "max_ports": 5,
            "timeout_seconds": 0.5,
        },
    }


def _bind_lab_server(host: str, port: int) -> ThreadingHTTPServer:
    if port == 0:
        return ThreadingHTTPServer((host, 0), VulnerableLabHandler)

    last_error: OSError | None = None
    for candidate in range(port, port + 21):
        try:
            return ThreadingHTTPServer((host, candidate), VulnerableLabHandler)
        except OSError as exc:
            last_error = exc
            if not _is_address_in_use(exc):
                break
    raise OSError(f"Could not bind local lab server: {last_error}")


def _validate_local_host(host: str) -> None:
    if host not in LOCAL_HOSTS:
        raise ValueError("The lab server can only bind to localhost or loopback addresses")


def _is_address_in_use(exc: OSError) -> bool:
    return getattr(exc, "winerror", None) == 10048 or getattr(exc, "errno", None) in {48, 98, 10048}


def _lab_url(host: str, port: int, path: str) -> str:
    display_host = f"[{host}]" if ":" in host and not host.startswith("[") else host
    return f"http://{display_host}:{port}{path}"


def _home_page() -> str:
    return """<!doctype html>
<html>
  <head>
    <meta charset="utf-8">
    <meta name="generator" content="WordPress 4.7.0">
    <title>AI Web Auditor Lab</title>
  </head>
  <body>
    <h1>AI Web Auditor Lab</h1>
    <p>Laboratorio local para generar hallazgos controlados.</p>
    <nav>
      <a href="/members/">Miembros</a>
      <a href="/admin/">Admin</a>
      <a href="/private/report">Informe privado</a>
      <a href="https://example.org/external">Externo</a>
    </nav>
  </body>
</html>
"""


def _page(title: str, text: str) -> str:
    return f"""<!doctype html>
<html>
  <head>
    <meta charset="utf-8">
    <meta name="generator" content="WordPress 4.7.0">
    <title>{title}</title>
  </head>
  <body>
    <h1>{title}</h1>
    <p>{text}</p>
    <a href="/">Inicio</a>
  </body>
</html>
"""


def _members_page() -> str:
    return """<!doctype html>
<html>
  <head>
    <meta charset="utf-8">
    <meta name="generator" content="WordPress 4.7.0">
    <title>Miembros</title>
  </head>
  <body>
    <h1>Miembros</h1>
    <p>Esta ruta de laboratorio fuerza HTTP Basic Auth sobre HTTP para generar evidencia controlada.</p>
    <form action="/login/" method="post">
      <input type="hidden" name="csrf_token">
      <input type="text" name="username">
      <input type="password" name="password">
      <button type="submit">Entrar</button>
    </form>
    <a href="/">Inicio</a>
  </body>
</html>
"""
