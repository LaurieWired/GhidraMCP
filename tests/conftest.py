import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import pytest


class FakeBackend:
    """A stand-in for the Java backend. `routes` maps path -> (status, body or callable)."""

    def __init__(self):
        self.routes: dict[str, tuple[int, object]] = {}
        self.requests: list[tuple[str, str, dict]] = []
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def _handle(self, method):
                parsed = urlparse(self.path)
                params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
                length = int(self.headers.get("Content-Length") or 0)
                if length:
                    body = self.rfile.read(length).decode()
                    params.update({k: v[0] for k, v in parse_qs(body).items()})
                fake.requests.append((method, parsed.path, params))
                status, payload = fake.routes.get(
                    parsed.path,
                    (404, {"success": False, "error": {"code": "UNKNOWN_ENDPOINT", "message": parsed.path}}),
                )
                if callable(payload):
                    payload = payload(params)
                raw = payload.encode() if isinstance(payload, str) else json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def do_GET(self):
                self._handle("GET")

            def do_POST(self):
                self._handle("POST")

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}/"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def ok(self, path, data):
        self.routes[path] = (200, {"success": True, "data": data})

    def fail(self, path, status, code, message):
        self.routes[path] = (status, {"success": False, "error": {"code": code, "message": message}})

    def close(self):
        self.server.shutdown()


@pytest.fixture
def fake_backend():
    fake = FakeBackend()
    yield fake
    fake.close()
