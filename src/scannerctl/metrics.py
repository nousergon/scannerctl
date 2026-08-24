from __future__ import annotations

import threading
import time

from scannerctl.contract import Verdict


class Metrics:
    def __init__(self, *, runtime_version: str, config_sha256: str) -> None:
        self.runtime_version = runtime_version
        self.config_sha256 = config_sha256
        self.counts = {verdict: 0 for verdict in Verdict}
        self.last_scan = 0.0
        self.last_canary = 0.0
        self.canary_success = 0
        self.duration_ms_total = 0
        self.bytes_total = 0
        self._lock = threading.Lock()

    def observe(self, verdict: Verdict, *, duration_ms: int, bytes_scanned: int) -> None:
        with self._lock:
            self.counts[verdict] += 1
            self.duration_ms_total += duration_ms
            self.bytes_total += bytes_scanned
            self.last_scan = time.time()

    def set_canary(self, *, success: bool) -> None:
        with self._lock:
            self.canary_success = int(success)
            self.last_canary = time.time()

    def render(self) -> str:
        with self._lock:
            lines = [
                "# TYPE scannerctl_scan_total counter",
                *[
                    f'scannerctl_scan_total{{verdict="{v.value}"}} {self.counts[v]}'
                    for v in Verdict
                ],
                f"scannerctl_scan_duration_milliseconds_total {self.duration_ms_total}",
                f"scannerctl_scan_bytes_total {self.bytes_total}",
                f"scannerctl_last_scan_timestamp_seconds {self.last_scan:g}",
                f"scannerctl_startup_canary_success {self.canary_success}",
                f"scannerctl_startup_canary_timestamp_seconds {self.last_canary:g}",
                (
                    "scannerctl_build_info{"
                    f'runtime_version="{self.runtime_version}",'
                    f'config_sha256="{self.config_sha256}"'
                    "} 1"
                ),
            ]
        return "\n".join(lines) + "\n"
