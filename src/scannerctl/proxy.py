from __future__ import annotations

import json
import os
import threading
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

from scannerctl.contract import Verdict


@dataclass(frozen=True)
class Route:
    host: str
    upstream: str
    auth_env: str = ""
    auth_header: str = "Authorization"
    auth_prefix: str = "Bearer "


class RouteTable:
    def __init__(self, routes: list[Route]) -> None:
        for route in routes:
            parsed = urlparse(route.upstream)
            if parsed.scheme != "https" or not parsed.hostname:
                raise ValueError("route upstream must be an absolute HTTPS URL")
            if not route.host or "/" in route.host:
                raise ValueError("route host must be a hostname")
        self._routes = {route.host.lower(): route for route in routes}
        if len(self._routes) != len(routes):
            raise ValueError("duplicate route host")

    def resolve(self, host: str) -> Route | None:
        return self._routes.get(host.partition(":")[0].lower())

    @classmethod
    def from_json(cls, path: str | Path) -> RouteTable:
        payload = json.loads(Path(path).read_text())
        if payload.get("schema_version") != "1":
            raise ValueError("unsupported route schema_version")
        return cls([Route(**item) for item in payload.get("routes", [])])


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def forward_http(route, method, path, headers, body):
    target = route.upstream.rstrip("/") + "/" + path.lstrip("/")
    outbound_headers = {
        key: value
        for key, value in headers.items()
        if key.lower() not in {"host", "content-length", "authorization"}
    }
    if route.auth_env:
        credential = os.environ.get(route.auth_env)
        if not credential:
            raise RuntimeError("route credential unavailable")
        outbound_headers[route.auth_header] = route.auth_prefix + credential
    request = urllib.request.Request(
        target,
        data=body,
        method=method,
        headers=outbound_headers,
    )
    opener = urllib.request.build_opener(_NoRedirect)
    with opener.open(request, timeout=120) as response:
        return response.status, dict(response.headers), response.read()


class ProxyServer(ThreadingHTTPServer):
    allow_reuse_address = True

    def __init__(
        self,
        address,
        *,
        scanner,
        routes: RouteTable,
        metrics=None,
        forwarder: Callable = forward_http,
        max_body_bytes: int = 16 * 1024 * 1024,
    ):
        self.scanner = scanner
        self.routes = routes
        self.metrics = metrics
        self.forwarder = forwarder
        self.max_body_bytes = max_body_bytes
        super().__init__(address, _Handler)

    @classmethod
    def for_test(cls, *, scanner, routes, forwarder):
        server = cls(
            ("127.0.0.1", 0),
            scanner=scanner,
            routes=routes,
            forwarder=forwarder,
        )
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        class Context:
            def __enter__(self):
                return server

            def __exit__(self, *args):
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)

        return Context()


class _Handler(BaseHTTPRequestHandler):
    server: ProxyServer

    def log_message(self, format, *args):
        return

    def do_GET(self):
        if self.path == "/healthz":
            self._respond(200, b'{"status":"ok"}', "application/json")
            return
        if self.path == "/metrics" and self.server.metrics is not None:
            self._respond(
                200,
                self.server.metrics.render().encode(),
                "text/plain; version=0.0.4",
            )
            return
        self._respond(404, b"not found")

    def do_POST(self):
        length = self.headers.get("Content-Length")
        if length is None or not length.isdigit():
            self._respond(411, b"content-length required")
            return
        size = int(length)
        if size > self.server.max_body_bytes:
            self._respond(413, b"request too large")
            return
        body = self.rfile.read(size)
        result = self.server.scanner.scan(body)
        if self.server.metrics is not None:
            self.server.metrics.observe(
                result.verdict,
                duration_ms=getattr(result, "duration_ms", 0),
                bytes_scanned=len(body),
            )
        if result.verdict is Verdict.BLOCK:
            self._respond(403, b'{"verdict":"block"}', "application/json")
            return
        if result.verdict is not Verdict.CLEAN:
            self._respond(503, b'{"verdict":"error"}', "application/json")
            return
        route = self.server.routes.resolve(self.headers.get("Host", ""))
        if route is None:
            self._respond(421, b"unknown route")
            return
        try:
            status, headers, response_body = self.server.forwarder(
                route, "POST", self.path, self.headers, body
            )
        except (OSError, RuntimeError):
            self._respond(502, b"upstream unavailable")
            return
        self.send_response(status)
        for key, value in headers.items():
            if key.lower() not in {"content-length", "connection"}:
                self.send_header(key, value)
        self.send_header("Content-Length", str(len(response_body)))
        self.end_headers()
        self.wfile.write(response_body)

    def _respond(self, status: int, body: bytes, content_type="text/plain"):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
