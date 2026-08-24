from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path


class GitleaksBackend:
    name = "gitleaks"

    def __init__(
        self,
        executable: str | Path,
        config: str | Path,
        *,
        timeout: int = 10,
        expected_version: str = "8.30.1",
        runner=subprocess.run,
    ) -> None:
        self.executable = str(executable)
        self.config = str(config)
        self.timeout = timeout
        self.expected_version = expected_version
        self.runner = runner
        self.version = self._version()

    def _version(self) -> str:
        try:
            completed = self.runner(
                [self.executable, "version"],
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=False,
            )
            return completed.stdout.strip() if completed.returncode == 0 else ""
        except (OSError, subprocess.TimeoutExpired):
            return ""

    def scan(self, payload: bytes) -> tuple[str, tuple[str, ...]]:
        if self.version != self.expected_version:
            return "error", ()
        with tempfile.TemporaryDirectory(prefix="scannerctl-") as directory:
            source = Path(directory) / "payload"
            report = Path(directory) / "report.json"
            source.write_bytes(payload)
            try:
                completed = self.runner(
                    [
                        self.executable,
                        "detect",
                        "--no-git",
                        "--source",
                        str(source),
                        "--config",
                        self.config,
                        "--report-format",
                        "json",
                        "--report-path",
                        str(report),
                        "--redact",
                        "--no-banner",
                        "--exit-code",
                        "1",
                    ],
                    capture_output=True,
                    text=True,
                    timeout=self.timeout,
                    check=False,
                )
            except (OSError, subprocess.TimeoutExpired):
                return "error", ()
            if completed.returncode == 0:
                return "clean", ()
            if completed.returncode != 1:
                return "error", ()
            rule_ids = self._rule_ids(report, completed.stderr)
            if not rule_ids:
                return "error", ()
            return "block", rule_ids

    @staticmethod
    def _rule_ids(report: Path, fallback: str) -> tuple[str, ...]:
        raw = ""
        try:
            raw = report.read_text()
        except OSError:
            raw = fallback
        try:
            findings = json.loads(raw)
        except json.JSONDecodeError:
            return ()
        if not isinstance(findings, list):
            return ()
        return tuple(
            sorted(
                {
                    str(item["RuleID"])
                    for item in findings
                    if isinstance(item, dict) and item.get("RuleID")
                }
            )
        )
