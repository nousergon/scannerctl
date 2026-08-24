import json

import pytest

from scannerctl.contract import ScanResult, Verdict


def test_result_round_trips_with_versioned_exhaustive_verdict():
    result = ScanResult(
        verdict=Verdict.CLEAN,
        backend="fake",
        backend_version="1.2.3",
        config_sha256="a" * 64,
        duration_ms=7,
        bytes_scanned=12,
        target_id="test-target",
    )

    payload = json.loads(result.to_json())

    assert payload["schema_version"] == "1"
    assert payload["verdict"] == "clean"
    assert payload["target_id"] == "test-target"
    assert ScanResult.from_json(json.dumps(payload)) == result


def test_unknown_verdict_is_rejected():
    with pytest.raises(ValueError, match="unknown verdict"):
        ScanResult.from_json('{"schema_version":"1","verdict":"maybe"}')


def test_unknown_schema_is_rejected():
    with pytest.raises(ValueError, match="schema_version"):
        ScanResult.from_json('{"schema_version":"2","verdict":"clean"}')


@pytest.mark.parametrize(
    "payload",
    [
        {"schema_version": "1", "verdict": "clean", "bytes_scanned": -1},
        {"schema_version": "1", "verdict": "clean", "duration_ms": "1"},
        {"schema_version": "1", "verdict": "clean", "config_sha256": "bad"},
        {"schema_version": "1", "verdict": "clean", "rule_ids": "not-a-list"},
        {"schema_version": "1", "verdict": "clean", "rule_ids": ["x", "x"]},
        {"schema_version": "1", "verdict": "clean", "unexpected": True},
    ],
)
def test_malformed_results_are_rejected(payload):
    with pytest.raises(ValueError):
        ScanResult.from_json(json.dumps(payload))


def test_clean_result_requires_complete_identity():
    with pytest.raises(ValueError, match="identity"):
        ScanResult.from_json('{"schema_version":"1","verdict":"clean"}')
