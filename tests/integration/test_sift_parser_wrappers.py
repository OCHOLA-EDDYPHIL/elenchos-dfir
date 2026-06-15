from __future__ import annotations

import os
from pathlib import Path

import pytest

from elenchos.audit.execution_ledger import read_events
from elenchos.parser.amcache import parse_amcache
from elenchos.parser.mft import parse_mft
from elenchos.parser.registry_runkeys import parse_registry_runkeys

pytestmark = pytest.mark.skipif(
    os.getenv("ELENCHOS_RUN_SIFT_INTEGRATION") != "1",
    reason="set ELENCHOS_RUN_SIFT_INTEGRATION=1 to run local SIFT parser tests",
)


def require_env_path(name: str) -> Path:
    value = os.getenv(name)
    if not value:
        pytest.fail(
            f"{name} is required when ELENCHOS_RUN_SIFT_INTEGRATION=1",
            pytrace=False,
        )
    path = Path(value)
    if not path.exists():
        pytest.fail(f"{name} does not point to an existing path", pytrace=False)
    if path.is_dir():
        pytest.fail(f"{name} must point to a file, not a directory", pytrace=False)
    return path


def assert_output_paths_under(output_files: list[str], root: Path) -> None:
    resolved_root = root.resolve()
    assert output_files
    for output_file in output_files:
        assert Path(output_file).resolve().is_relative_to(resolved_root)


def assert_audit_written(ledger_path: Path) -> None:
    events = read_events(ledger_path)
    assert events
    for event in events:
        assert event["command"]
        assert isinstance(event["exit_code"], int)
        assert isinstance(event["duration_ms"], int)
        assert event["stdout_path"] is not None
        assert event["stderr_path"] is not None
        assert event["status"] in {"success", "failed", "denied"}


def test_mft_wrapper_runs_with_local_sift_artifact(tmp_path: Path) -> None:
    mft_path = require_env_path("ELENCHOS_TEST_MFT_PATH")
    runs_root = tmp_path / "runs"
    ledger_path = runs_root / "CASE-INTEGRATION" / "audit.jsonl"

    result = parse_mft(
        case_id="CASE-INTEGRATION",
        artifact_id="EV-MFT-INTEGRATION",
        mft_path=mft_path,
        runs_root=runs_root,
        evidence_root=mft_path.parent,
        ledger_path=ledger_path,
    )

    assert result.status in {"success", "partial_success"}
    assert len(result.events) > 0
    assert isinstance(result.warnings, list)
    assert isinstance(result.errors, list)
    assert_output_paths_under(result.output_files, runs_root)
    assert_audit_written(ledger_path)


def test_registry_runkey_wrapper_runs_with_local_sift_artifacts(tmp_path: Path) -> None:
    hive_paths = (
        ("EV-REG-NTUSER-INTEGRATION", require_env_path("ELENCHOS_TEST_NTUSER_HIVE")),
        ("EV-REG-SOFTWARE-INTEGRATION", require_env_path("ELENCHOS_TEST_SOFTWARE_HIVE")),
    )
    runs_root = tmp_path / "runs"
    ledger_path = runs_root / "CASE-INTEGRATION" / "audit.jsonl"

    for artifact_id, hive_path in hive_paths:
        result = parse_registry_runkeys(
            case_id="CASE-INTEGRATION",
            artifact_id=artifact_id,
            hive_path=hive_path,
            runs_root=runs_root,
            evidence_root=hive_path.parent,
            ledger_path=ledger_path,
        )

        assert result.status in {"success", "partial_success", "failed"}
        assert isinstance(result.warnings, list)
        assert isinstance(result.errors, list)
        assert_output_paths_under(result.output_files, runs_root)
        if len(result.events) == 0:
            assert result.status != "success"
            assert result.warnings or result.errors

    assert_audit_written(ledger_path)


def test_amcache_wrapper_runs_with_local_sift_artifact(tmp_path: Path) -> None:
    amcache_path = require_env_path("ELENCHOS_TEST_AMCACHE_PATH")
    runs_root = tmp_path / "runs"
    ledger_path = runs_root / "CASE-INTEGRATION" / "audit.jsonl"

    result = parse_amcache(
        case_id="CASE-INTEGRATION",
        artifact_id="EV-AMCACHE-INTEGRATION",
        amcache_path=amcache_path,
        runs_root=runs_root,
        evidence_root=amcache_path.parent,
        ledger_path=ledger_path,
    )

    assert result.status in {"success", "partial_success"}
    assert len(result.events) > 0
    assert isinstance(result.warnings, list)
    assert isinstance(result.errors, list)
    assert_output_paths_under(result.output_files, runs_root)
    assert_audit_written(ledger_path)
