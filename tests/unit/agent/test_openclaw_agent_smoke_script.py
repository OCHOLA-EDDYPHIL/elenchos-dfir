from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path


def repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def run_smoke_script(run_root: Path) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["RUN_ROOT"] = str(run_root)
    return subprocess.run(
        [str(repo_root() / "scripts" / "openclaw-agent-smoke.sh")],
        cwd=repo_root(),
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


def test_openclaw_agent_smoke_script_runs_constrained_synthetic_workflow(
    tmp_path: Path,
):
    run_root = tmp_path / "runs" / "CASE-AGENT-OPENCLAW-SMOKE"
    result = run_smoke_script(run_root)

    assert result.returncode == 0, result.stdout + result.stderr
    output_dir = run_root / "agent-run"
    for filename in ("agent_run.json", "audit.jsonl", "findings.json", "report.md"):
        assert (output_dir / filename).is_file()
        assert f"{filename}" in result.stdout

    agent_run = json.loads((output_dir / "agent_run.json").read_text(encoding="utf-8"))
    assert agent_run["case_id"] == "CASE-AGENT-OPENCLAW-SMOKE"
    assert agent_run["status"] == "completed"
    assert agent_run["output_refs"]["agent_run"] == "agent_run.json"
    assert agent_run["output_refs"]["audit"] == "audit.jsonl"
    assert agent_run["output_refs"]["findings"] == "findings.json"
    assert agent_run["output_refs"]["report"] == "report.md"

    audit_lines = (output_dir / "audit.jsonl").read_text(encoding="utf-8").splitlines()
    audit_events = [json.loads(line)["event_type"] for line in audit_lines]
    assert "agent_run_started" in audit_events
    assert "agent_run_completed" in audit_events


def test_openclaw_agent_smoke_script_rejects_non_generated_run_root(tmp_path: Path):
    result = run_smoke_script(tmp_path / "case-work")

    assert result.returncode == 2
    assert "RUN_ROOT must be under" in result.stderr
