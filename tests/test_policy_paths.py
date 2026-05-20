from __future__ import annotations

from pathlib import Path

import pytest

from siftguard.policy.paths import (
    assert_not_inside_evidence_output,
    assert_output_under_runs,
    resolve_under,
    validate_output_path,
)


def test_output_under_runs_allowed(tmp_path):
    runs = tmp_path / "runs"
    runs.mkdir()

    output = validate_output_path(Path("case1/out.json"), runs)
    assert output == (runs / "case1/out.json").resolve()


def test_output_inside_evidence_rejected(tmp_path):
    runs = tmp_path / "runs"
    evidence = tmp_path / "cases"
    runs.mkdir()
    evidence.mkdir()

    with pytest.raises(ValueError, match="inside evidence root"):
        validate_output_path(evidence / "out.json", runs, evidence)


def test_traversal_outside_runs_rejected(tmp_path):
    runs = tmp_path / "runs"
    runs.mkdir()

    with pytest.raises(ValueError, match="outside base"):
        resolve_under(runs, Path("../escape/out.json"))


def test_absolute_outside_runs_rejected(tmp_path):
    runs = tmp_path / "runs"
    runs.mkdir()

    outside = tmp_path / "outside" / "out.json"
    with pytest.raises(ValueError, match="outside base"):
        validate_output_path(outside, runs)


def test_symlink_escape_rejected(tmp_path):
    runs = tmp_path / "runs"
    outside = tmp_path / "outside"
    runs.mkdir()
    outside.mkdir()

    link = runs / "linked_out"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation is not supported in this environment")

    with pytest.raises(ValueError, match="outside base"):
        validate_output_path(Path("linked_out/escape.txt"), runs)


def test_direct_assert_guards(tmp_path):
    runs = tmp_path / "runs"
    evidence = tmp_path / "cases"
    runs.mkdir()
    evidence.mkdir()

    safe = runs / "a.txt"
    assert_output_under_runs(safe, runs)

    with pytest.raises(ValueError, match="inside evidence root"):
        assert_not_inside_evidence_output(evidence / "x.txt", evidence)
