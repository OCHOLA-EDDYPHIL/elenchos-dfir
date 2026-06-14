from __future__ import annotations

from pathlib import Path

from elenchos.tui.runner import build_default_prompt, build_openclaw_command, make_output_dir


def test_build_default_prompt_includes_safety_and_handoff_details(tmp_path: Path):
    output_dir = tmp_path / "runs" / "case"

    prompt = build_default_prompt("/mnt/evidence/rocba", output_dir)

    assert "/mnt/evidence/rocba" in prompt
    assert str(output_dir) in prompt
    assert "bounded Elenchos tools" in prompt
    assert "raw evidence read-only" in prompt
    assert "prepared_manifest_path" in prompt
    assert "Do not claim confirmed theft" in prompt
    assert "exfiltration" in prompt
    assert "memory findings" in prompt
    assert "malware" in prompt
    assert "attribution" in prompt
    assert "final compromise" in prompt


def test_build_openclaw_command_returns_argv_list_without_shell():
    command = build_openclaw_command("main", "Triage the case.")

    assert command == ["openclaw", "agent", "--agent", "main", "Triage the case."]


def test_make_output_dir_creates_slugged_runs_directory(tmp_path: Path):
    output_dir = make_output_dir("ROCBA demo", runs_root=tmp_path / "runs")

    assert output_dir.is_dir()
    assert output_dir.parent == (tmp_path / "runs").resolve()
    assert output_dir.name.startswith("ROCBA-demo-")
