from __future__ import annotations

import json
from pathlib import Path

import pytest

from elenchos.cli import main


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
