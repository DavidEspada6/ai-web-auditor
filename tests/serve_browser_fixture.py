"""Isolated loopback UI and lab for browser regression; exits when stdin closes."""
import json
import os
import sys
import tempfile
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from ai_web_auditor.web.server import LAB_MANAGER, LocalAuditHandler


def main():
    previous = Path.cwd()
    with tempfile.TemporaryDirectory() as tmp:
        os.chdir(tmp)
        server = ThreadingHTTPServer(("127.0.0.1", 0), LocalAuditHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        try:
            lab = LAB_MANAGER.start(port=0)
            thread.start()
            print(json.dumps({"url": f"http://127.0.0.1:{server.server_port}", "lab_port": lab.port}), flush=True)
            sys.stdin.readline()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
            LAB_MANAGER.stop()
            os.chdir(previous)


if __name__ == "__main__":
    main()
