"""The proxy forwards only the representation it inspected (scannerctl-I68).

A gzip-encoded body hides a must-detect pattern from a byte scanner, and the
proxy used to forward it with Content-Encoding intact. Every non-identity
encoding, and any Transfer-Encoding framing, is now refused before scanning.
"""

import gzip
import http.client
import zlib
from threading import Thread

import pytest

from scannerctl.contract import Verdict
from scannerctl.metrics import Metrics
from scannerctl.proxy import ProxyServer, Route, RouteTable
from scannerctl.runtime import _MUST_DETECT, Scanner


class CanaryBackend:
    """Blocks on the baseline must-detect pattern, as config/baseline.toml does."""

    name = "canary"
    version = "1"

    def __init__(self):
        self.payloads = []

    def scan(self, payload):
        self.payloads.append(payload)
        if b"SCANNERCTL_MUST_DETECT_" in payload:
            return "block", ("scannerctl-canary",)
        return "clean", ()


class RecordingForwarder:
    def __init__(self):
        self.calls = []

    def __call__(self, route, method, path, headers, body):
        self.calls.append({k.lower(): v for k, v in headers.items()} | {"_body": body})
        return 200, {"content-type": "application/json"}, b'{"ok":true}'


MUST_DETECT_FIXTURES = [
    _MUST_DETECT,
    b'{"messages":[{"role":"user","content":"' + _MUST_DETECT + b'"}]}',
]


@pytest.fixture()
def proxy(tmp_path):
    config = tmp_path / "rules.toml"
    config.write_text("rules")
    backend = CanaryBackend()
    forward = RecordingForwarder()
    metrics = Metrics(runtime_version="0.1.0", config_sha256="a" * 64)
    server = ProxyServer(
        ("127.0.0.1", 0),
        scanner=Scanner(backend, config, target_id="test"),
        routes=RouteTable([Route("tenant.test", "https://upstream.test")]),
        metrics=metrics,
        forwarder=forward,
    )
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    server.backend = backend
    server.forward = forward
    yield server
    server.shutdown()
    server.server_close()
    thread.join(timeout=2)


def _post(server, body, headers=()):
    connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=2)
    connection.putrequest("POST", "/v1/test", skip_host=True, skip_accept_encoding=True)
    connection.putheader("Host", "tenant.test")
    connection.putheader("Content-Type", "application/json")
    connection.putheader("Content-Length", str(len(body)))
    for name, value in headers:
        connection.putheader(name, value)
    connection.endheaders()
    connection.send(body)
    response = connection.getresponse()
    status = response.status
    response.read()
    connection.close()
    return status


@pytest.mark.parametrize("fixture", MUST_DETECT_FIXTURES)
def test_plain_must_detect_fixture_blocks(proxy, fixture):
    assert _post(proxy, fixture) == 403
    assert proxy.forward.calls == []


@pytest.mark.parametrize("fixture", MUST_DETECT_FIXTURES)
@pytest.mark.parametrize(
    ("coding", "encode"),
    [
        ("gzip", gzip.compress),
        ("x-gzip", gzip.compress),
        ("GZip", gzip.compress),
        ("deflate", zlib.compress),
        ("br", lambda raw: raw),
        ("identity, gzip", gzip.compress),
    ],
)
def test_encoded_must_detect_fixture_never_forwards(proxy, fixture, coding, encode):
    status = _post(proxy, encode(fixture), [("Content-Encoding", coding)])

    assert status == 415
    assert proxy.forward.calls == []
    assert proxy.backend.payloads == [], "refused before scanning, never scored clean"


def test_a_second_content_encoding_header_is_not_ignored(proxy):
    headers = [("Content-Encoding", "identity"), ("Content-Encoding", "gzip")]

    assert _post(proxy, gzip.compress(_MUST_DETECT), headers) == 415
    assert proxy.forward.calls == []


def test_a_decompression_bomb_is_refused_without_being_inflated(proxy):
    bomb = gzip.compress(b"\0" * (8 * 1024 * 1024))

    assert _post(proxy, bomb, [("Content-Encoding", "gzip")]) == 415
    assert proxy.backend.payloads == []
    assert proxy.forward.calls == []


def test_transfer_encoding_beside_content_length_is_ambiguous_framing(proxy):
    status = _post(proxy, b'{"hello":"world"}', [("Transfer-Encoding", "chunked")])

    assert status == 415
    assert proxy.forward.calls == []


@pytest.mark.parametrize("headers", [[], [("Content-Encoding", "identity")]])
def test_clean_identity_request_forwards_exactly_what_was_inspected(proxy, headers):
    body = b'{"hello":"world"}'

    assert _post(proxy, body, headers) == 200
    (call,) = proxy.forward.calls
    assert proxy.backend.payloads == [body]
    assert call["_body"] == body
    assert call.get("content-encoding", "identity") == "identity"
    assert "transfer-encoding" not in call


def test_denials_are_counted_by_reason(proxy):
    _post(proxy, gzip.compress(_MUST_DETECT), [("Content-Encoding", "gzip")])
    _post(proxy, b"{}", [("Transfer-Encoding", "chunked")])
    _post(proxy, _MUST_DETECT)

    rendered = proxy.metrics.render()
    assert 'scannerctl_request_denied_total{reason="unsupported_content_encoding"} 1' in rendered
    assert 'scannerctl_request_denied_total{reason="ambiguous_framing"} 1' in rendered
    assert f'scannerctl_scan_total{{verdict="{Verdict.BLOCK.value}"}} 1' in rendered
    assert 'scannerctl_scan_total{verdict="clean"} 0' in rendered
