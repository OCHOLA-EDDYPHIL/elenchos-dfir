from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from elenchos.tui.runner import (
    ActiveRunError,
    active_run_lock_path,
    build_openclaw_command,
    build_wrapped_prompt,
    complete_active_run,
    ensure_no_active_run,
    make_output_dir,
    plan_output_dir,
    read_active_run_lock,
    write_active_run_lock,
    write_run_context,
)


def test_build_wrapped_prompt_includes_safety_handoff_and_analyst_prompt(tmp_path: Path):
    output_dir = tmp_path / "runs" / "case"

    prompt = build_wrapped_prompt(
        "Triage the ROCBA case and tell me what happened.",
        output_dir,
        "/mnt/evidence/rocba",
    )

    assert "Triage the ROCBA case and tell me what happened." in prompt
    assert "/mnt/evidence/rocba" in prompt
    assert str(output_dir) in prompt
    assert "bounded Elenchos tools" in prompt
    assert "raw evidence read-only" in prompt
    assert "prepared_manifest_path" in prompt
    assert "[model-rationale]" in prompt
    assert "[policy]" in prompt
    assert "Do not claim confirmed theft" in prompt
    assert "exfiltration" in prompt
    assert "memory findings" in prompt
    assert "malware" in prompt
    assert "attribution" in prompt
    assert "final compromise" in prompt


def test_build_openclaw_command_returns_argv_list_without_shell():
    command = build_openclaw_command("main", "Triage the case.")

    assert command == ["openclaw", "agent", "--agent", "main", "--message", "Triage the case."]
    assert command[2:4] == ["--agent", "main"]
    assert command[-2:] == ["--message", "Triage the case."]


def test_make_output_dir_creates_slugged_runs_directory(tmp_path: Path):
    output_dir = make_output_dir("ROCBA demo", runs_root=tmp_path / "runs")

    assert output_dir.is_dir()
    assert output_dir.parent == (tmp_path / "runs").resolve()
    assert output_dir.name.startswith("ROCBA-demo-")


def test_plan_output_dir_does_not_create_directory(tmp_path: Path):
    output_dir = plan_output_dir("ROCBA demo", runs_root=tmp_path / "runs")

    assert not output_dir.exists()
    assert output_dir.parent == (tmp_path / "runs").resolve()


def test_write_run_context_records_prompt_and_command_shape(tmp_path: Path):
    output_dir = tmp_path / "runs" / "case"
    wrapped = build_wrapped_prompt("Triage this case.", output_dir)

    context = write_run_context(
        output_dir=output_dir,
        case_id="case",
        agent="main",
        runs_root=tmp_path / "runs",
        source_root=None,
        analyst_prompt="Triage this case.",
        wrapped_prompt=wrapped,
    )

    stored = json.loads((output_dir / "run_context.json").read_text(encoding="utf-8"))
    assert context["analyst_prompt"] == "Triage this case."
    assert stored["wrapped_prompt"] == wrapped
    assert stored["prepare_case_timeout_seconds"] is None
    assert stored["openclaw_command_shape"] == [
        "openclaw",
        "agent",
        "--agent",
        "main",
        "--message",
        "<prompt>",
    ]


def test_write_run_context_records_configured_prepare_timeout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    output_dir = tmp_path / "runs" / "case"
    wrapped = build_wrapped_prompt("Triage this case.", output_dir)
    monkeypatch.setenv("ELENCHOS_PREPARE_TIMEOUT_SECONDS", "456")

    write_run_context(
        output_dir=output_dir,
        case_id="case",
        agent="main",
        runs_root=tmp_path / "runs",
        source_root=None,
        analyst_prompt="Triage this case.",
        wrapped_prompt=wrapped,
    )

    stored = json.loads((output_dir / "run_context.json").read_text(encoding="utf-8"))
    assert stored["prepare_case_timeout_seconds"] == 456


def test_active_lock_blocks_when_pid_is_alive(tmp_path: Path):
    runs_root = tmp_path / "runs"
    write_active_run_lock(
        runs_root=runs_root,
        pid=os.getpid(),
        output_dir=runs_root / "case",
        agent="main",
    )

    with pytest.raises(ActiveRunError):
        ensure_no_active_run(runs_root)


def test_stale_active_lock_does_not_block_launch(tmp_path: Path):
    runs_root = tmp_path / "runs"
    write_active_run_lock(
        runs_root=runs_root,
        pid=99999999,
        output_dir=runs_root / "case",
        agent="main",
    )

    ensure_no_active_run(runs_root)

    lock = read_active_run_lock(runs_root)
    assert lock is not None
    assert lock["status"] == "stale"


def test_active_lock_is_completed_on_process_exit(tmp_path: Path):
    runs_root = tmp_path / "runs"
    write_active_run_lock(
        runs_root=runs_root,
        pid=os.getpid(),
        output_dir=runs_root / "case",
        agent="main",
    )

    complete_active_run(runs_root=runs_root, pid=os.getpid(), returncode=1)

    lock = json.loads(active_run_lock_path(runs_root).read_text(encoding="utf-8"))
    assert lock["status"] == "failed"
    assert lock["returncode"] == 1
