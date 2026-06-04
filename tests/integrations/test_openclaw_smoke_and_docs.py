from __future__ import annotations

import subprocess
from pathlib import Path


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def test_openclaw_siftguard_smoke_runs_in_dry_run_mode(tmp_path: Path):
    output_dir = tmp_path / "runs" / "openclaw-smoke"
    result = subprocess.run(
        [
            str(repo_root() / ".venv" / "bin" / "python"),
            str(repo_root() / "scripts" / "openclaw_siftguard_smoke.py"),
            "--dry-run",
            "--output-dir",
            str(output_dir),
        ],
        cwd=repo_root(),
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert "validation_status=pass" in result.stdout
    assert (output_dir / "openclaw-trace" / "prepare_case.stdout").is_file()
    assert (output_dir / "openclaw-trace" / "run_case.stderr").is_file()
    assert (output_dir / "openclaw-trace" / "summary.json").is_file()


def test_openclaw_docs_state_model_agnostic_core_and_provider_config():
    docs = (repo_root() / "docs" / "openclaw-mcp-workflow.md").read_text(encoding="utf-8")
    readme = (repo_root() / "README.md").read_text(encoding="utf-8")
    combined = f"{docs}\n{readme}".casefold()

    assert "model-agnostic" in combined
    assert "openclaw controls provider and model selection" in combined
    assert "model output is not forensic evidence" in combined
    assert "prepare_case -> run_case -> summarize_run -> validate_run_outputs" in combined
