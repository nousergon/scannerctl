from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass
from pathlib import Path

from scannerctl.contract import ScanResult, Verdict

_BENIGN = b"scannerctl startup canary: ordinary public text"
_MUST_DETECT = b"SCANNERCTL_MUST_DETECT_0123456789ABCDEF"


@dataclass(frozen=True)
class CanaryResult:
    success: bool
    benign: ScanResult
    must_detect: ScanResult


class Scanner:
    def __init__(
        self,
        backend,
        config: Path,
        *,
        target_id: str,
        disabled: bool = False,
    ) -> None:
        self.backend = backend
        self.config = Path(config)
        self.target_id = target_id
        self.disabled = disabled
        self.config_sha256 = self._digest_config()

    def _digest_config(self) -> str:
        try:
            return hashlib.sha256(self.config.read_bytes()).hexdigest()
        except OSError:
            return ""

    def scan(self, payload: bytes) -> ScanResult:
        started = time.monotonic()
        if self.disabled:
            verdict, rules = Verdict.DISABLED, ()
        elif not self.config_sha256:
            verdict, rules = Verdict.ERROR, ()
        else:
            try:
                raw_verdict, rules = self.backend.scan(payload)
                verdict = Verdict(raw_verdict)
                if not isinstance(rules, (list, tuple)) or any(
                    not isinstance(rule_id, str) for rule_id in rules
                ):
                    raise TypeError("backend returned malformed rule IDs")
                rules = tuple(rules)
            except (OSError, RuntimeError, TypeError, ValueError):
                verdict, rules = Verdict.ERROR, ()
        return ScanResult(
            verdict=verdict,
            backend=getattr(self.backend, "name", ""),
            backend_version=getattr(self.backend, "version", ""),
            config_sha256=self.config_sha256,
            duration_ms=max(0, round((time.monotonic() - started) * 1000)),
            bytes_scanned=len(payload),
            target_id=self.target_id,
            rule_ids=rules,
        )

    def self_test(self) -> CanaryResult:
        benign = self.scan(_BENIGN)
        must_detect = self.scan(_MUST_DETECT)
        return CanaryResult(
            success=(
                benign.verdict is Verdict.CLEAN
                and must_detect.verdict is Verdict.BLOCK
            ),
            benign=benign,
            must_detect=must_detect,
        )
