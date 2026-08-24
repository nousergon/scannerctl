import json
import subprocess
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

import pytest

from scannerctl.backend import GitleaksBackend
from scannerctl.contract import ScanResult, Verdict
from scannerctl.metrics import Metrics
from scannerctl.proxy import ProxyServer, Route, RouteTable, forward_http
from scannerctl.runtime import Scanner


class FakeScanner:
    def __init__(self, verdict, duration_ms=7):
        self.verdict = verdict
        self.duration_ms = duration_ms

    def scan(self, payload):
        return ScanResult(
            verdict=Verdict(self.verdict),
            backend="stub",
            backend_version="8.30.1",
            config_sha256="a" * 64,
            duration_ms=self.duration_ms,
            bytes_scanned=len(payload),
            target_id="test",
            rule_ids=("rule-a",) if self.verdict == "block" else (),
        )


def _routes():
    return RouteTable([Route("tenant.test", "https://upstream.test")])


def _forwarder(*args, **kwargs):
    return 200, {"content-type": "application/json"}, b'{"ok":true}'


def _get(server, path):
    return urllib.request.urlopen(
        f"http://127.0.0.1:{server.server_port}{path}", timeout=2
    )


def _post(server, body, headers=None, raw_content_length=None):
    request = urllib.request.Request(
        f"http://127.0.0.1:{server.server_port}/v1/test",
        data=body,
        method="POST",
        headers=headers or {"Host": "tenant.test"},
    )
    if raw_content_length is not None:
        request.add_header("Content-Length", raw_content_length)
    return urllib.request.urlopen(request, timeout=2)


def test_healthz_is_served_without_scanning():
    with ProxyServer.for_test(
        scanner=FakeScanner("error"), routes=_routes(), forwarder=_forwarder
    ) as server:
        response = _get(server, "/healthz")
    assert response.status == 200
    assert json.loads(response.read())["status"] == "ok"


def test_unknown_get_path_is_not_found():
    with ProxyServer.for_test(
        scanner=FakeScanner("clean"), routes=_routes(), forwarder=_forwarder
    ) as server:
        with pytest.raises(urllib.error.HTTPError) as exc:
            _get(server, "/nope")
    assert exc.value.code == 404


def test_metrics_endpoint_is_absent_until_metrics_are_wired():
    with ProxyServer.for_test(
        scanner=FakeScanner("clean"), routes=_routes(), forwarder=_forwarder
    ) as server:
        with pytest.raises(urllib.error.HTTPError) as exc:
            _get(server, "/metrics")
    assert exc.value.code == 404


def test_metrics_record_every_scan_and_expose_identity():
    metrics = Metrics(runtime_version="0.1.0", config_sha256="a" * 64)
    server = ProxyServer(
        ("127.0.0.1", 0),
        scanner=FakeScanner("block"),
        routes=_routes(),
        metrics=metrics,
        forwarder=_forwarder,
    )
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with pytest.raises(urllib.error.HTTPError) as exc:
            _post(server, b'{"secret":"x"}')
        assert exc.value.code == 403
        rendered = _get(server, "/metrics").read().decode()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    assert 'scannerctl_scan_total{verdict="block"} 1' in rendered
    assert "scannerctl_scan_duration_milliseconds_total 7" in rendered
    assert 'runtime_version="0.1.0"' in rendered


def test_request_without_content_length_is_refused():
    with ProxyServer.for_test(
        scanner=FakeScanner("clean"), routes=_routes(), forwarder=_forwarder
    ) as server:
        connection = __import__("http.client", fromlist=["HTTPConnection"]).HTTPConnection(
            "127.0.0.1", server.server_port, timeout=2
        )
        connection.putrequest("POST", "/v1/test")
        connection.putheader("Host", "tenant.test")
        connection.endheaders()
        status = connection.getresponse().status
        connection.close()
    assert status == 411


def test_oversized_body_is_refused_before_scanning():
    server = ProxyServer(
        ("127.0.0.1", 0),
        scanner=FakeScanner("clean"),
        routes=_routes(),
        forwarder=_forwarder,
        max_body_bytes=4,
    )
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with pytest.raises(urllib.error.HTTPError) as exc:
            _post(server, b"0123456789")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
    assert exc.value.code == 413


def test_upstream_failure_is_reported_as_bad_gateway():
    def failing(*args, **kwargs):
        raise OSError("upstream down")

    with ProxyServer.for_test(
        scanner=FakeScanner("clean"), routes=_routes(), forwarder=failing
    ) as server:
        with pytest.raises(urllib.error.HTTPError) as exc:
            _post(server, b'{"hello":"world"}')
    assert exc.value.code == 502


def test_route_table_rejects_a_host_containing_a_path():
    with pytest.raises(ValueError, match="hostname"):
        RouteTable([Route("tenant.test/v1", "https://upstream.test")])


def test_route_table_rejects_duplicate_hosts():
    with pytest.raises(ValueError, match="duplicate"):
        RouteTable(
            [
                Route("tenant.test", "https://a.test"),
                Route("TENANT.test", "https://b.test"),
            ]
        )


def test_route_table_rejects_an_unsupported_schema_version(tmp_path):
    path = tmp_path / "routes.json"
    path.write_text('{"schema_version":"2","routes":[]}')
    with pytest.raises(ValueError, match="schema_version"):
        RouteTable.from_json(path)


def test_route_lookup_ignores_port_and_case():
    table = _routes()
    assert table.resolve("TENANT.test:8990") is not None
    assert table.resolve("other.test") is None


class _Echo(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        return

    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        payload = json.dumps(
            {"headers": {k.lower(): v for k, v in self.headers.items()}, "body": body.decode()}
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


@pytest.fixture()
def upstream():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Echo)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()
    server.server_close()
    thread.join(timeout=2)


def test_forwarder_injects_the_route_credential_and_drops_the_client_one(
    upstream, monkeypatch
):
    monkeypatch.setenv("UPSTREAM_KEY", "s3cret")
    route = Route("tenant.test", upstream, auth_env="UPSTREAM_KEY")

    status, headers, body = forward_http(
        route,
        "POST",
        "/v1/test",
        {"Host": "tenant.test", "Authorization": "Bearer client-token", "X-Trace": "1"},
        b'{"hello":"world"}',
    )

    echoed = json.loads(body)
    assert status == 200
    assert headers["Content-Type"] == "application/json"
    assert echoed["headers"]["authorization"] == "Bearer s3cret"
    assert echoed["headers"]["x-trace"] == "1"
    assert echoed["body"] == '{"hello":"world"}'


def test_forwarder_fails_closed_when_the_credential_is_absent(upstream, monkeypatch):
    monkeypatch.delenv("UPSTREAM_KEY", raising=False)
    route = Route("tenant.test", upstream, auth_env="UPSTREAM_KEY")

    with pytest.raises(RuntimeError, match="credential"):
        forward_http(route, "POST", "/v1/test", {}, b"{}")


def test_scanner_without_a_readable_config_is_error(tmp_path):
    scanner = Scanner(object(), tmp_path / "absent.toml", target_id="test")

    assert scanner.config_sha256 == ""
    assert scanner.scan(b"anything").verdict is Verdict.ERROR


def test_backend_reports_no_version_when_the_binary_is_missing(tmp_path):
    def runner(*args, **kwargs):
        raise OSError("no such binary")

    backend = GitleaksBackend("/absent/gitleaks", tmp_path / "c.toml", runner=runner)

    assert backend.version == ""
    assert backend.scan(b"payload") == ("error", ())


def test_backend_reports_no_version_on_a_non_zero_version_exit(tmp_path):
    def runner(*args, **kwargs):
        return subprocess.CompletedProcess(args, 1, stdout="ignored", stderr="")

    assert GitleaksBackend("gitleaks", tmp_path / "c.toml", runner=runner).version == ""


def test_backend_falls_back_to_stderr_when_the_report_is_unreadable(tmp_path):
    calls = []

    def runner(command, **kwargs):
        calls.append(command)
        if command[1] == "version":
            return subprocess.CompletedProcess(command, 0, stdout="8.30.1\n", stderr="")
        return subprocess.CompletedProcess(
            command, 1, stdout="", stderr='[{"RuleID":"aws-access-key"}]'
        )

    backend = GitleaksBackend("gitleaks", tmp_path / "c.toml", runner=runner)

    assert backend.scan(b"payload") == ("block", ("aws-access-key",))


def test_backend_rejects_a_report_that_is_not_a_list(tmp_path):
    def runner(command, **kwargs):
        if command[1] == "version":
            return subprocess.CompletedProcess(command, 0, stdout="8.30.1\n", stderr="")
        return subprocess.CompletedProcess(command, 1, stdout="", stderr='{"RuleID":"x"}')

    backend = GitleaksBackend("gitleaks", tmp_path / "c.toml", runner=runner)

    assert backend.scan(b"payload") == ("error", ())


def test_backend_maps_an_unexpected_exit_code_to_error(tmp_path):
    def runner(command, **kwargs):
        if command[1] == "version":
            return subprocess.CompletedProcess(command, 0, stdout="8.30.1\n", stderr="")
        return subprocess.CompletedProcess(command, 3, stdout="", stderr="boom")

    backend = GitleaksBackend("gitleaks", tmp_path / "c.toml", runner=runner)

    assert backend.scan(b"payload") == ("error", ())


@pytest.mark.parametrize(
    "payload",
    [
        '["not", "an", "object"]',
        '{"schema_version":"1","verdict":"clean","backend":1}',
        '{"schema_version":"1","verdict":"block","backend":"b","backend_version":"1",'
        '"config_sha256":"' + "a" * 64 + '","target_id":"t","rule_ids":[]}',
    ],
)
def test_contract_rejects_structurally_invalid_results(payload):
    with pytest.raises(ValueError):
        ScanResult.from_json(payload)


def test_backend_maps_a_scan_timeout_to_error(tmp_path):
    def runner(command, **kwargs):
        if command[1] == "version":
            return subprocess.CompletedProcess(command, 0, stdout="8.30.1\n", stderr="")
        raise subprocess.TimeoutExpired(command, 10)

    backend = GitleaksBackend("gitleaks", tmp_path / "c.toml", runner=runner)

    assert backend.scan(b"payload") == ("error", ())
