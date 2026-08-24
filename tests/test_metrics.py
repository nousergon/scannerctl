from scannerctl.contract import Verdict
from scannerctl.metrics import Metrics


def test_metrics_emit_all_states_and_no_data_is_zero_timestamp():
    metrics = Metrics(runtime_version="1.0.0", config_sha256="a" * 64)
    text = metrics.render()

    for verdict in Verdict:
        assert f'verdict="{verdict.value}"' in text
    assert "scannerctl_last_scan_timestamp_seconds 0" in text
    assert "scannerctl_startup_canary_success 0" in text


def test_metrics_record_verdict_and_canary():
    metrics = Metrics(runtime_version="1.0.0", config_sha256="a" * 64)
    metrics.observe(Verdict.BLOCK, duration_ms=4, bytes_scanned=20)
    metrics.set_canary(success=True)
    text = metrics.render()
    assert 'scannerctl_scan_total{verdict="block"} 1' in text
    assert "scannerctl_startup_canary_success 1" in text
    assert "scannerctl_last_scan_timestamp_seconds 0" not in text
