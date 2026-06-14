from __future__ import annotations

import json
from pathlib import Path

import pytest

from elenchos.cli import main
from elenchos.tui import console


def test_cli_help_includes_tui(capsys):
    with pytest.raises(SystemExit):
        main(["--help"])

    assert "tui" in capsys.readouterr().out


def test_cli_tui_help_works_without_openclaw(capsys):
    with pytest.raises(SystemExit):
        main(["tui", "--help"])

    output = capsys.readouterr().out
    assert "Elenchos analyst case console" in output
    assert "--watch-only" in output
    assert "--once" in output


def test_cli_tui_watch_once_prints_snapshot_without_curses_or_openclaw(
    tmp_path: Path,
    capsys,
):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (tmp_path / "model_rationale.jsonl").write_text(
        json.dumps(
            {
                "timestamp_utc": "2026-06-14T00:00:00Z",
                "visible_message": "[model-rationale] Test rationale.",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    (tmp_path / "policy_decisions.jsonl").write_text(
        json.dumps(
            {
                "timestamp_utc": "2026-06-14T00:00:01Z",
                "visible_policy_message": (
                    "[policy] proposed inspect_run_state -> allowed: generated outputs only."
                ),
            }
        )
        + "\n",
        encoding="utf-8",
    )
    (run_dir / "run_job.json").write_text(
        json.dumps({"status": "completed", "returncode": 0}) + "\n",
        encoding="utf-8",
    )

    exit_code = main(["tui", "--watch-only", "--output-dir", str(tmp_path), "--once"])

    output = capsys.readouterr().out
    assert exit_code == 0
    assert "Elenchos Case Console" in output
    assert "[model-rationale] Test rationale." in output
    assert "[policy] proposed inspect_run_state -> allowed" in output


def test_cli_tui_watch_only_without_output_dir_fails_clearly(capsys):
    exit_code = main(["tui", "--watch-only", "--once"])

    assert exit_code == 2
    assert "output_dir is required with --watch-only" in capsys.readouterr().out


def test_no_arg_tui_prompt_resolution_does_not_require_source_root():
    assert console._resolve_analyst_prompt(  # noqa: SLF001
        prompt=None,
        prompt_file=None,
        watch_only=False,
    ) is None


def test_initial_output_dir_planning_does_not_create_run_dir(tmp_path: Path):
    runs_root = tmp_path / "runs"

    output_dir = console._resolve_initial_output_dir(  # noqa: SLF001
        output_dir=None,
        case_id="case",
        runs_root=runs_root,
        watch_only=False,
    )

    assert output_dir is not None
    assert output_dir.parent == runs_root.resolve()
    assert not output_dir.exists()


def test_output_dir_under_mnt_evidence_is_rejected():
    with pytest.raises(ValueError, match="must not be under /mnt/evidence"):
        console._resolve_initial_output_dir(  # noqa: SLF001
            output_dir=Path("/mnt/evidence/elenchos-tui-test"),
            case_id=None,
            runs_root=Path("runs"),
            watch_only=False,
        )


def test_launch_from_prompt_writes_context_and_lock(tmp_path: Path, monkeypatch):
    class FakeProcess:
        pid = 123456

        def poll(self):
            return None

    def fake_launch(agent: str, prompt: str, log_path: Path):
        assert agent == "main"
        assert "--message" not in prompt
        log_path.write_text("started\n", encoding="utf-8")
        return FakeProcess()

    monkeypatch.setattr(console, "launch_openclaw", fake_launch)
    monkeypatch.setattr(console, "process_is_alive", lambda pid: False, raising=False)
    runs_root = tmp_path / "runs"
    output_dir = runs_root / "case"

    error, process, status = console._launch_from_prompt(  # noqa: SLF001
        output_dir=output_dir,
        agent="main",
        analyst_prompt="Triage this case.",
        case_id="case",
        runs_root=runs_root,
        source_root=None,
    )

    assert error is None
    assert process is not None
    assert status == "running pid=123456"
    context = json.loads((output_dir / "run_context.json").read_text(encoding="utf-8"))
    assert context["analyst_prompt"] == "Triage this case."
    lock = json.loads((runs_root / ".elenchos-active-run.json").read_text(encoding="utf-8"))
    assert lock["status"] == "running"
    assert lock["output_dir"] == str(output_dir)


def test_transcript_mirror_is_constrained_to_generated_roots(tmp_path: Path):
    non_generated = tmp_path / "case"
    non_generated.mkdir()
    generated = tmp_path / "runs" / "case"
    generated.mkdir(parents=True)
    (generated / "model_rationale.jsonl").write_text(
        json.dumps(
            {
                "timestamp_utc": "2026-06-14T00:00:00Z",
                "visible_message": "[model-rationale] Test rationale.",
            }
        )
        + "\n",
        encoding="utf-8",
    )

    non_generated_state = console.read_console_state(non_generated)
    generated_state = console.read_console_state(generated)

    console._mirror_visible_transcript(non_generated, non_generated_state)  # noqa: SLF001
    console._mirror_visible_transcript(generated, generated_state)  # noqa: SLF001

    assert not (non_generated / "case_console_transcript.md").exists()
    assert (generated / "case_console_transcript.md").is_file()
