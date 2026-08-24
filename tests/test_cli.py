import json

from scannerctl import cli


def test_version_is_machine_readable(capsys):
    assert cli.main(["version", "--format", "json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["schema_version"] == "1"
    assert payload["runtime_version"]


def test_scan_exit_codes_are_fail_closed(monkeypatch, tmp_path, capsys):
    payload = tmp_path / "payload"
    payload.write_text("hello")

    class Result:
        def __init__(self, verdict):
            self.verdict = type("V", (), {"value": verdict})()

        def to_json(self):
            return json.dumps({"schema_version": "1", "verdict": self.verdict.value})

    for verdict, expected in (("clean", 0), ("block", 10), ("error", 20), ("disabled", 20)):
        monkeypatch.setattr(cli, "_scan_file", lambda args, v=verdict: Result(v))
        assert cli.main(["scan", "--input", str(payload), "--format", "json"]) == expected


def test_defaults_honor_packaged_config_override(monkeypatch, tmp_path):
    config = tmp_path / "baseline.toml"
    config.write_text("title = 'test'\n")
    monkeypatch.setenv("SCANNERCTL_CONFIG", str(config))
    monkeypatch.setenv("SCANNERCTL_GITLEAKS", "/runtime/gitleaks")
    monkeypatch.setattr(cli, "_bundle_root", lambda: tmp_path / "missing")

    backend, resolved_config = cli._defaults()

    assert backend.as_posix() == "/runtime/gitleaks"
    assert resolved_config == config
