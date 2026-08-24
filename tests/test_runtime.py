from scannerctl.contract import Verdict
from scannerctl.runtime import Scanner


class FakeBackend:
    name = "fake"
    version = "1"

    def __init__(self, verdict="clean"):
        self.verdict = verdict

    def scan(self, payload):
        return self.verdict, ("canary",) if self.verdict == "block" else ()


def test_all_four_states_are_explicit(tmp_path):
    config = tmp_path / "rules.toml"
    config.write_text("rules")

    for value in ("clean", "block", "error"):
        result = Scanner(FakeBackend(value), config, target_id="target").scan(b"x")
        assert result.verdict is Verdict(value)

    result = Scanner(
        FakeBackend(), config, target_id="target", disabled=True
    ).scan(b"x")
    assert result.verdict is Verdict.DISABLED


def test_backend_exception_fails_closed_as_error(tmp_path):
    class Broken(FakeBackend):
        def scan(self, payload):
            raise RuntimeError("boom")

    config = tmp_path / "rules.toml"
    config.write_text("rules")
    result = Scanner(Broken(), config, target_id="target").scan(b"x")
    assert result.verdict is Verdict.ERROR


def test_malformed_backend_response_fails_closed_as_error(tmp_path):
    class Malformed(FakeBackend):
        def scan(self, payload):
            return "clean", None

    config = tmp_path / "rules.toml"
    config.write_text("rules")
    result = Scanner(Malformed(), config, target_id="target").scan(b"x")
    assert result.verdict is Verdict.ERROR


def test_startup_canary_requires_benign_clean_and_must_detect_block(tmp_path):
    class CanaryBackend(FakeBackend):
        def scan(self, payload):
            if b"SCANNERCTL_MUST_DETECT_" in payload:
                return "block", ("scannerctl-canary",)
            return "clean", ()

    config = tmp_path / "rules.toml"
    config.write_text("rules")
    scanner = Scanner(CanaryBackend(), config, target_id="target")

    canary = scanner.self_test()

    assert canary.success is True
    assert canary.benign.verdict is Verdict.CLEAN
    assert canary.must_detect.verdict is Verdict.BLOCK


def test_wrong_canary_polarity_is_failure(tmp_path):
    config = tmp_path / "rules.toml"
    config.write_text("rules")
    scanner = Scanner(FakeBackend("clean"), config, target_id="target")
    assert scanner.self_test().success is False
