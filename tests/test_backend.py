import subprocess

from scannerctl.backend import GitleaksBackend


def _completed(
    returncode: int, stderr: str = "", stdout: str = ""
) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(["gitleaks"], returncode, stdout, stderr)


def _runner_for_scan(scan_result):
    def run(argv, **kwargs):
        if argv[1] == "version":
            return _completed(0, stdout="8.30.1\n")
        return scan_result

    return run


def test_backend_maps_zero_to_clean(tmp_path):
    seen = {}

    def run(argv, **kwargs):
        seen["argv"] = argv
        seen["kwargs"] = kwargs
        return _completed(0, stdout="8.30.1\n") if argv[1] == "version" else _completed(0)

    backend = GitleaksBackend(
        executable="/opt/scannerctl/gitleaks",
        config=tmp_path / "rules.toml",
        runner=run,
    )

    verdict, rule_ids = backend.scan(b"benign")

    assert verdict == "clean"
    assert rule_ids == ()
    assert "--no-git" in seen["argv"]
    assert seen["kwargs"]["timeout"] == 10


def test_backend_maps_findings_to_block_without_secret_text(tmp_path):
    backend = GitleaksBackend(
        executable="gitleaks",
        config=tmp_path / "rules.toml",
        runner=_runner_for_scan(
            _completed(1, '[{"RuleID":"private-key","Secret":"must-not-escape"}]')
        ),
    )

    verdict, rule_ids = backend.scan(b"secret material")

    assert verdict == "block"
    assert rule_ids == ("private-key",)
    assert "must-not-escape" not in repr(rule_ids)


def test_backend_maps_crash_timeout_and_missing_binary_to_error(tmp_path):
    errors = [
        _completed(2, "scanner crashed"),
        subprocess.TimeoutExpired(["gitleaks"], 10),
        FileNotFoundError("missing"),
    ]
    for outcome in errors:
        def run(*args, **kwargs):
            if isinstance(outcome, BaseException):
                raise outcome
            return outcome

        backend = GitleaksBackend("gitleaks", tmp_path / "rules.toml", runner=run)
        verdict, rule_ids = backend.scan(b"x")
        assert (verdict, rule_ids) == ("error", ())


def test_backend_version_mismatch_is_error(tmp_path):
    backend = GitleaksBackend(
        "gitleaks",
        tmp_path / "rules.toml",
        runner=lambda *a, **k: _completed(0, stdout="8.29.0\n"),
    )
    assert backend.scan(b"benign") == ("error", ())


def test_backend_rejects_finding_exit_without_structured_evidence(tmp_path):
    backend = GitleaksBackend(
        "gitleaks",
        tmp_path / "rules.toml",
        runner=_runner_for_scan(_completed(1, "malformed")),
    )

    assert backend.scan(b"x") == ("error", ())
