import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from ai_web_auditor.auth import parse_cookie_lines, parse_header_lines, upsert_auth_profile
from ai_web_auditor.config import AuditConfig
from ai_web_auditor.engine import run_scan


class AuthProfileHandler(BaseHTTPRequestHandler):
    seen_headers: list[dict[str, str]] = []

    def do_GET(self):  # noqa: N802 - http.server naming.
        AuthProfileHandler.seen_headers.append({key: value for key, value in self.headers.items()})
        role = self.headers.get("X-Test-Role", "public")
        if self.path == "/":
            links = '<a href="/member">Member area</a>' if role == "member" else ""
            self._send(200, f"<html><body><h1>{role}</h1>{links}</body></html>")
            return
        if self.path == "/member" and role == "member":
            self._send(200, "<html><body><h1>Member</h1></body></html>")
            return
        self._send(403, "<html><body>Forbidden</body></html>")

    def log_message(self, format, *args):
        return

    def _send(self, status: int, body: str) -> None:
        raw = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


class AuthProfileTests(unittest.TestCase):
    def setUp(self):
        AuthProfileHandler.seen_headers = []
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), AuthProfileHandler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}/"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)

    def test_authenticated_profile_headers_are_applied_and_metadata_is_safe(self):
        config = _local_config()
        upsert_auth_profile(
            config,
            profile_id="member",
            name="Usuario demo",
            headers={"X-Test-Role": "member"},
            notes="Demo profile",
        )

        result = run_scan(self.url, config)
        data = result.to_dict()
        urls = {item["url"] for item in data["inventory"]["urls"]}

        self.assertTrue(any(headers.get("X-Test-Role") == "member" for headers in AuthProfileHandler.seen_headers))
        self.assertIn(f"{self.url}member", urls)
        self.assertEqual(data["auth_profile"]["id"], "member")
        self.assertEqual(data["auth_profile"]["name"], "Usuario demo")
        self.assertTrue(data["auth_profile"]["authenticated"])
        self.assertEqual(data["auth_profile"]["request_header_names"], ["X-Test-Role"])
        self.assertEqual(data["auth_profile"]["cookie_names"], [])
        self.assertNotIn("member-token", str(data["auth_profile"]))

    def test_authorization_and_cookie_values_are_redacted_from_request_evidence(self):
        config = _local_config()
        upsert_auth_profile(
            config,
            profile_id="cli",
            name="CLI",
            headers={"Authorization": "Bearer member-token"},
            cookies={"sessionid": "secret-session"},
        )

        data = run_scan(self.url, config).to_dict()
        request_headers = data["requests"][0]["request_headers"]

        self.assertEqual(request_headers["Authorization"], "[redacted]")
        self.assertIn("sessionid=[redacted]", request_headers["Cookie"])
        self.assertNotIn("member-token", str(data))
        self.assertNotIn("secret-session", str(data))
        self.assertEqual(data["auth_profile"]["request_header_names"], ["Authorization"])
        self.assertEqual(data["auth_profile"]["cookie_names"], ["sessionid"])

    def test_auth_line_parsers_reject_invalid_values(self):
        self.assertEqual(parse_header_lines(["X-Test-Role: member"]), {"X-Test-Role": "member"})
        self.assertEqual(parse_cookie_lines(["sessionid=abc; csrftoken=def"]), {"sessionid": "abc", "csrftoken": "def"})
        with self.assertRaises(ValueError):
            parse_header_lines(["Broken header"])
        with self.assertRaises(ValueError):
            parse_cookie_lines(["broken-cookie"])


def _local_config() -> AuditConfig:
    config = AuditConfig()
    config.scope.allowed_hosts = ["127.0.0.1"]
    config.scope.allow_private_networks = True
    config.scope.resolve_dns = False
    config.scope.include_paths = ["/"]
    config.http.check_http_counterpart = False
    config.modules.tls = False
    config.modules.subdomains = False
    config.modules.ports = False
    config.modules.javascript = False
    config.crawler.use_robots_txt = False
    config.crawler.use_sitemap_xml = False
    config.crawler.use_well_known = False
    config.crawler.max_depth = 1
    config.crawler.max_pages = 5
    return config


if __name__ == "__main__":
    unittest.main()
