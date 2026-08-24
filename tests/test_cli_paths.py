import json
import runpy
import sys

import pytest

from scannerctl import cli
from scannerctl.contract import ScanResult, Verdict


class StubBackend:
    name = "stub"
    version = "8.30.1"

    def __init__(self, verdicts):
        self.verdicts = list(verdicts)

    def scan(self, payload):
        return self.verdicts.pop(0)


@pytest.fixture()
def config(tmp_path):
    path = tmp_path / "baseline.toml"
    path.write_text("title = 'test'\n")
    return path


def _stub_scanner(monkeypatch, verdicts, config, **kwargs):
    from scannerctl.runtime import Scanner

    def factory(args):
        return Scanner(StubBackend(verdicts), config, target_id="test", **kwargs)

    monkeypatch.setattr(cli, "_scanner", factory)


def test_scan_reads_stdin_and_reports_clean(monkeypatch, config, capsys):
    _stub_scanner(monkeypatch, [("clean", ())], config)
    monkeypatch.setattr(sys, "stdin", type("S", (), {"buffer": type("B", (), {"read": staticmethod(lambda: b"hello")})()})())

    assert cli.main(["scan", "--input", "-"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["verdict"] == "clean"
    assert payload["bytes_scanned"] == 5


def test_scan_refuses_oversized_input(monkeypatch, config, tmp_path):
    _stub_scanner(monkeypatch, [("clean", ())], config)
    source = tmp_path / "payload"
    source.write_bytes(b"0123456789")

    assert cli.main(["scan", "--input", str(source), "--max-bytes", "4"]) == 20


def test_scan_missing_input_file_exits_fail_closed(monkeypatch, config, tmp_path):
    _stub_scanner(monkeypatch, [("clean", ())], config)

    assert cli.main(["scan", "--input", str(tmp_path / "absent")]) == 20


def test_self_test_reports_both_canaries(monkeypatch, config, capsys):
    _stub_scanner(monkeypatch, [("clean", ()), ("block", ("rule-a",))], config)

    assert cli.main(["self-test"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["success"] is True
    assert payload["benign"]["verdict"] == "clean"
    assert payload["must_detect"]["verdict"] == "block"


def test_self_test_fails_when_polarity_is_wrong(monkeypatch, config, capsys):
    _stub_scanner(monkeypatch, [("clean", ()), ("clean", ())], config)

    assert cli.main(["self-test"]) == 20
    assert json.loads(capsys.readouterr().out)["success"] is False


def test_serve_refuses_to_start_when_the_canary_fails(monkeypatch, config, tmp_path):
    _stub_scanner(monkeypatch, [("clean", ()), ("clean", ())], config)
    routes = tmp_path / "routes.json"
    routes.write_text(json.dumps({"schema_version": "1", "routes": []}))

    assert cli.main(["serve", "--routes", str(routes)]) == 20


def test_serve_rejects_a_listen_address_without_a_port(monkeypatch, config, tmp_path):
    _stub_scanner(monkeypatch, [("clean", ()), ("block", ("rule-a",))], config)
    routes = tmp_path / "routes.json"
    routes.write_text(json.dumps({"schema_version": "1", "routes": []}))

    with pytest.raises(ValueError, match="HOST:PORT"):
        cli.main(["serve", "--routes", str(routes), "--listen", "127.0.0.1"])


def test_serve_binds_scans_and_closes_cleanly(monkeypatch, config, tmp_path, capsys):
    _stub_scanner(monkeypatch, [("clean", ()), ("block", ("rule-a",))], config)
    routes = tmp_path / "routes.json"
    routes.write_text(
        json.dumps(
            {
                "schema_version": "1",
                "routes": [{"host": "tenant.test", "upstream": "https://upstream.test"}],
            }
        )
    )
    served = {}

    def serve_forever(self):
        served["port"] = self.server_port
        served["metrics"] = self.metrics.render()
        raise KeyboardInterrupt

    monkeypatch.setattr("scannerctl.proxy.ProxyServer.serve_forever", serve_forever)

    assert cli.main(["serve", "--routes", str(routes), "--listen", "127.0.0.1:0"]) == 0
    assert served["port"] > 0
    assert "scannerctl_startup_canary_success 1" in served["metrics"]


def test_scanner_factory_builds_a_disabled_scanner(monkeypatch, config):
    monkeypatch.setattr(cli, "_defaults", lambda: (config.parent / "gitleaks", config))
    args = cli.build_parser().parse_args(
        ["scan", "--input", "-", "--disabled", "--config", str(config)]
    )
    scanner = cli._scanner(args)

    assert scanner.scan(b"anything").verdict is Verdict.DISABLED
    assert scanner.config_sha256


def test_bundle_root_prefers_the_packaged_layout(monkeypatch, tmp_path):
    bundled = tmp_path / "bundle" / "bin" / "scannerctl"
    bundled.parent.mkdir(parents=True)
    bundled.write_text("")
    monkeypatch.setattr(sys, "executable", str(bundled))

    assert cli._bundle_root() == bundled.parent.parent


def test_bundle_root_falls_back_to_the_source_tree(monkeypatch):
    monkeypatch.setattr(sys, "executable", "/usr/bin/python3")

    assert (cli._bundle_root() / "src" / "scannerctl" / "cli.py").exists()


def test_defaults_use_the_bundled_binary_when_present(monkeypatch, tmp_path):
    (tmp_path / "bin").mkdir()
    (tmp_path / "bin" / "gitleaks").write_text("")
    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "baseline.toml").write_text("title = 'bundled'\n")
    monkeypatch.setattr(cli, "_bundle_root", lambda: tmp_path)

    backend, resolved = cli._defaults()

    assert backend == tmp_path / "bin" / "gitleaks"
    assert resolved == tmp_path / "config" / "baseline.toml"


def test_module_entrypoint_runs_the_cli(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["scannerctl", "version"])

    with pytest.raises(SystemExit) as exit_info:
        runpy.run_module("scannerctl", run_name="__main__")

    assert exit_info.value.code == 0
    assert json.loads(capsys.readouterr().out)["schema_version"] == "1"


def test_result_serialisation_round_trips_through_the_contract():
    result = ScanResult(
        verdict=Verdict.BLOCK,
        backend="stub",
        backend_version="8.30.1",
        config_sha256="a" * 64,
        target_id="test",
        rule_ids=("rule-a",),
    )

    assert ScanResult.from_json(result.to_json()) == result
