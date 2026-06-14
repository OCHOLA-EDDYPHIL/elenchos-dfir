from __future__ import annotations

import sys
from pathlib import Path

import pytest

from elenchos.audit.execution_ledger import read_events
from elenchos.runner.subprocess_runner import run_command


def test_runner_success_logs_audit(tmp_path):
    runs_root = tmp_path / "runs"
    ledger = runs_root / "audit.jsonl"

    result = run_command(
        [sys.executable, "-c", "print('ok')"],
        stdout_path=Path("case/stdout.txt"),
        stderr_path=Path("case/stderr.txt"),
        ledger_path=ledger,
        case_id="case1",
        tool_name="python_test",
        runs_root=runs_root,
    )

    assert result.status == "success"
    assert result.exit_code == 0
    assert result.stdout_path is not None
    assert result.stdout_sha256 is not None

    rows = read_events(ledger)
    assert len(rows) == 1
    event = rows[0]
    assert event["status"] == "success"
    assert event["case_id"] == "case1"
    assert event["tool_name"] == "python_test"
    assert event["command"] == [sys.executable, "-c", "print('ok')"]
    assert event["exit_code"] == 0
    assert isinstance(event["duration_ms"], int)
    assert event["stdout_path"] == result.stdout_path
    assert event["stderr_path"] == result.stderr_path
    assert event["stdout_sha256"] == result.stdout_sha256
    assert event["stderr_sha256"] == result.stderr_sha256


def test_runner_nonzero_logs_failed(tmp_path):
    runs_root = tmp_path / "runs"
    ledger = runs_root / "audit.jsonl"

    result = run_command(
        [sys.executable, "-c", "import sys\nprint('bad')\nsys.exit(3)"],
        stdout_path=Path("case/stdout.txt"),
        stderr_path=Path("case/stderr.txt"),
        ledger_path=ledger,
        case_id="case1",
        tool_name="python_fail",
        runs_root=runs_root,
    )

    assert result.status == "failed"
    assert result.exit_code == 3

    rows = read_events(ledger)
    event = rows[-1]
    assert event["status"] == "failed"
    assert event["case_id"] == "case1"
    assert event["tool_name"] == "python_fail"
    assert event["command"] == [
        sys.executable,
        "-c",
        "import sys\nprint('bad')\nsys.exit(3)",
    ]
    assert event["exit_code"] == 3
    assert isinstance(event["duration_ms"], int)
    assert event["stdout_path"] == result.stdout_path
    assert event["stderr_path"] == result.stderr_path
    assert event["stdout_sha256"] == result.stdout_sha256
    assert event["stderr_sha256"] == result.stderr_sha256


def test_runner_denied_command_logs_denied(tmp_path):
    ledger = tmp_path / "runs" / "audit.jsonl"

    result = run_command(
        ["rm", "-rf", "/tmp/x"],
        ledger_path=ledger,
        case_id="case1",
        tool_name="bad",
    )

    assert result.status == "denied"
    assert result.exit_code == -1
    rows = read_events(ledger)
    assert rows[-1]["status"] == "denied"


def test_runner_rejects_shell_metacharacter(tmp_path):
    result = run_command(["echo", "ok|cat"], ledger_path=tmp_path / "audit.jsonl")
    assert result.status == "denied"


def test_runner_rejects_string_command():
    with pytest.raises(TypeError, match="not a string"):
        run_command("python -V")


def test_runner_validates_output_paths_under_runs_root(tmp_path):
    runs_root = tmp_path / "runs"
    runs_root.mkdir()

    with pytest.raises(ValueError, match="outside base"):
        run_command(
            [sys.executable, "-c", "print('ok')"],
            stdout_path=tmp_path / "outside.txt",
            runs_root=runs_root,
        )


def test_runner_rejects_output_inside_evidence_root(tmp_path):
    evidence_root = tmp_path / "cases"
    evidence_root.mkdir()

    with pytest.raises(ValueError, match="inside evidence root"):
        run_command(
            [sys.executable, "-c", "print('ok')"],
            stdout_path=evidence_root / "out.txt",
            evidence_root=evidence_root,
        )


def test_runner_timeout_logs_failed(tmp_path):
    runs_root = tmp_path / "runs"
    ledger = runs_root / "audit.jsonl"

    result = run_command(
        [sys.executable, "-c", "import time\ntime.sleep(2)"],
        stderr_path=Path("case/stderr.txt"),
        timeout_seconds=1,
        ledger_path=ledger,
        case_id="case1",
        tool_name="python_timeout",
        runs_root=runs_root,
    )

    assert result.status == "failed"
    assert result.exit_code == -1
    assert result.stderr_path is not None
    assert result.stderr_sha256 is not None

    stderr_text = Path(result.stderr_path).read_text(encoding="utf-8")
    assert "timeout after 1 seconds" in stderr_text

    rows = read_events(ledger)
    assert rows[-1]["status"] == "failed"
