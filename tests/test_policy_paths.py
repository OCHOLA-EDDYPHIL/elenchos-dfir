from __future__ import annotations

import pytest

from siftguard.policy.paths import (
    assert_not_inside_evidence_output,
    assert_output_under_runs,
    resolve_under,
)
from siftguard.policy.tools import is_command_allowed


def test_policy_blocks_forbidden_command():
    allowed, reason = is_command_allowed(["rm", "-rf", "/tmp/x"])
    assert not allowed
    assert "forbidden executable" in reason


def test_policy_allows_harmless_command():
    allowed, reason = is_command_allowed(["python", "--version"])
    assert allowed
    assert reason == "allowed"


def test_resolve_under_rejects_traversal(tmp_path):
    base = tmp_path / "base"
    base.mkdir()

    with pytest.raises(ValueError):
        resolve_under(base, tmp_path / "../outside")


def test_output_path_guards(tmp_path):
    evidence = tmp_path / "cases"
    runs = tmp_path / "runs"
    evidence.mkdir()
    runs.mkdir()

    safe = runs / "case1" / "manifest.json"
    safe.parent.mkdir(parents=True)
    assert_output_under_runs(safe, runs)

    bad = evidence / "output.json"
    with pytest.raises(ValueError):
        assert_not_inside_evidence_output(bad, evidence)
