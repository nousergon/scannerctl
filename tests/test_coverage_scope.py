"""The coverage gate's *scope* is protected, not only its number.

repository-baseline-policy.md §4.2 C5: the way a coverage gate stops being
honest is by narrowing what it measures, which looks like an improvement in
every report. These tests fail on that narrowing.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
PACKAGE = REPO_ROOT / "src" / "scannerctl"


def _pyproject() -> dict:
    return tomllib.loads((REPO_ROOT / "pyproject.toml").read_text())


def test_coverage_measures_the_whole_source_tree():
    run = _pyproject()["tool"]["coverage"]["run"]

    assert run["source"] == ["src/scannerctl"]
    assert run.get("omit", []) == [], "omit narrows the denominator; keep it empty"


def test_every_source_module_is_inside_the_measured_scope():
    measured = REPO_ROOT / _pyproject()["tool"]["coverage"]["run"]["source"][0]
    modules = sorted(path.relative_to(REPO_ROOT) for path in PACKAGE.rglob("*.py"))

    assert modules, "no source modules found — the scope check would pass vacuously"
    for module in modules:
        assert (REPO_ROOT / module).is_relative_to(measured)


def test_the_floor_is_enforced_and_not_merely_reported():
    report = _pyproject()["tool"]["coverage"]["report"]
    addopts = _pyproject()["tool"]["pytest"]["ini_options"]["addopts"]

    assert "--cov" in addopts, "coverage must run on every invocation of the suite"
    assert report["fail_under"] == 100, (
        "the floor is a ratchet: raise it as coverage improves, never lower it "
        "to make a change pass (repository-baseline-policy.md §4.2 C3)"
    )


def test_exclusions_cannot_hide_executable_logic():
    excluded = _pyproject()["tool"]["coverage"]["report"]["exclude_lines"]

    assert set(excluded) <= {"pragma: no cover", "if __name__ == .__main__.:"}
