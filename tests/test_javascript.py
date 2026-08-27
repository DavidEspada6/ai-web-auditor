import json
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from ai_web_auditor.config import AuditConfig
from ai_web_auditor.engine import run_scan


REQUESTED_PATHS: list[str] = []


class JavaScriptDemoHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        REQUESTED_PATHS.append(self.path)
        if self.path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(
                b"""<!doctype html>
<html>
  <head><script src="/static/app.js"></script></head>
  <body>
    <script>
      fetch('/inline/api?csrf_token=inline-secret', { method: 'POST' });
    </script>
  </body>
</html>"""
            )
            return
        if self.path == "/static/app.js":
            self.send_response(200)
            self.send_header("Content-Type", "application/javascript; charset=utf-8")
            self.end_headers()
            self.wfile.write(
                b"""
const endpoints = [
  "/api/users?role=admin",
  "/api/profile?session_id=demo-session",
  "/admin/export?token=demo-token",
  "https://outside.example/collect"
];
fetch("/api/users?role=admin");
fetch("/api/profile?session_id=demo-session", { method: "POST" });
"""
            )
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.end_headers()
        self.wfile.write(b"unexpected")

    def do_OPTIONS(self):
        REQUESTED_PATHS.append(self.path)
        self.send_response(204)
        self.send_header("Allow", "GET, OPTIONS")
        self.end_headers()

    def log_message(self, *args):
        return


class JavaScriptModuleTests(unittest.TestCase):
    def test_javascript_analysis_discovers_endpoints_without_requesting_them(self):
        REQUESTED_PATHS.clear()
        server = HTTPServer(("127.0.0.1", 0), JavaScriptDemoHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)

        config = AuditConfig()
        config.scope.allow_private_networks = True
        config.scope.resolve_dns = False
        config.scope.exclude_paths = ["/admin"]
        config.http.check_http_counterpart = False
        config.modules.tls = False
        config.modules.subdomains = False
        config.modules.ports = False
        config.crawler.max_depth = 0
        config.crawler.max_pages = 1
        config.crawler.use_robots_txt = False
        config.crawler.use_sitemap_xml = False
        config.crawler.use_well_known = False

        result = run_scan(f"http://127.0.0.1:{server.server_port}/", config)
        data = result.to_dict()
        javascript = next(module for module in data["modules"] if module["name"] == "javascript")
        artifacts = javascript["artifacts"]
        discovered_urls = {item["url"] for item in artifacts["discovered_endpoints"]}
        excluded_urls = {item["url"] for item in artifacts["excluded_endpoints"]}
        out_of_scope_urls = {item["url"] for item in artifacts["out_of_scope_endpoints"]}
        entry_urls = {item["url"] for item in data["entry_points"]["endpoints"]}
        serialized = json.dumps(data)

        self.assertIn(f"http://127.0.0.1:{server.server_port}/api/users?role=admin", discovered_urls)
        self.assertIn(f"http://127.0.0.1:{server.server_port}/api/profile?session_id=%5Bredacted%5D", discovered_urls)
        self.assertIn(f"http://127.0.0.1:{server.server_port}/inline/api?csrf_token=%5Bredacted%5D", discovered_urls)
        self.assertIn(f"http://127.0.0.1:{server.server_port}/admin/export?token=%5Bredacted%5D", excluded_urls)
        self.assertIn("https://outside.example/collect", out_of_scope_urls)
        self.assertIn(f"http://127.0.0.1:{server.server_port}/api/users?role=admin", entry_urls)
        self.assertIn("JS-ENDPOINTS-DISCOVERED", {finding["id"] for finding in data["findings"]})
        self.assertIn("JS-SENSITIVE-PARAMETER-NAMES", {finding["id"] for finding in data["findings"]})
        self.assertNotIn("demo-session", serialized)
        self.assertNotIn("inline-secret", serialized)
        self.assertNotIn("demo-token", serialized)
        self.assertNotIn("/api/users?role=admin", REQUESTED_PATHS)
        self.assertNotIn("/api/profile?session_id=demo-session", REQUESTED_PATHS)


if __name__ == "__main__":
    unittest.main()
