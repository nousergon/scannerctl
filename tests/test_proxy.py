import urllib.error
import urllib.request

import pytest

from scannerctl.contract import Verdict
from scannerctl.proxy import ProxyServer, Route, RouteTable, _NoRedirect


class Result:
    def __init__(self, verdict):
        self.verdict = Verdict(verdict)


class FakeScanner:
    def __init__(self, verdict):
        self.verdict = verdict

    def scan(self, payload):
        return Result(self.verdict)


class FakeForwarder:
    def __init__(self):
        self.calls = []

    def __call__(self, route, method, path, headers, body):
        self.calls.append((route, method, path, headers, body))
        return 200, {"content-type": "application/json"}, b'{"ok":true}'


def _request(server, body=b'{"hello":"world"}'):
    req = urllib.request.Request(
        f"http://127.0.0.1:{server.server_port}/v1/test",
        data=body,
        method="POST",
        headers={"Host": "tenant.test", "Content-Type": "application/json"},
    )
    return urllib.request.urlopen(req, timeout=2)


def test_clean_request_is_forwarded():
    forward = FakeForwarder()
    with ProxyServer.for_test(
        scanner=FakeScanner("clean"),
        routes=RouteTable([Route("tenant.test", "https://upstream.test")]),
        forwarder=forward,
    ) as server:
        response = _request(server)
    assert response.status == 200
    assert len(forward.calls) == 1


@pytest.mark.parametrize("verdict", ["block", "error", "disabled"])
def test_every_non_clean_state_denies_without_forwarding(verdict):
    forward = FakeForwarder()
    with ProxyServer.for_test(
        scanner=FakeScanner(verdict),
        routes=RouteTable([Route("tenant.test", "https://upstream.test")]),
        forwarder=forward,
    ) as server:
        with pytest.raises(urllib.error.HTTPError) as exc:
            _request(server)
    assert exc.value.code in (403, 503)
    assert forward.calls == []


def test_unknown_host_is_denied():
    forward = FakeForwarder()
    with ProxyServer.for_test(
        scanner=FakeScanner("clean"),
        routes=RouteTable([]),
        forwarder=forward,
    ) as server:
        with pytest.raises(urllib.error.HTTPError) as exc:
            _request(server)
    assert exc.value.code == 421
    assert forward.calls == []


def test_route_table_rejects_non_tls_upstream(tmp_path):
    route_file = tmp_path / "routes.json"
    route_file.write_text(
        '{"schema_version":"1","routes":[{"host":"x.test","upstream":"http://x.test"}]}'
    )
    with pytest.raises(ValueError, match="HTTPS"):
        RouteTable.from_json(route_file)


def test_forwarder_refuses_redirects():
    handler = _NoRedirect()

    assert handler.redirect_request(None, None, 302, "redirect", {}, "https://other.test") is None
