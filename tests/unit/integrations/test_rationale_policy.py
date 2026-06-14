from __future__ import annotations

from pathlib import Path

import pytest

from elenchos.integrations.rationale_policy import evaluate_action_policy


@pytest.mark.parametrize(
    "action",
    [
        "inspect_run_state",
        "validate_run_outputs",
        "emit_claim_boundary",
        "poll_case_run",
    ],
)
def test_policy_allows_safe_actions(tmp_path: Path, action: str):
    output_dir = tmp_path / "runs" / "case" / "agent-run"

    result = evaluate_action_policy(output_dir=output_dir, proposed_action=action)

    assert result["decision"] == "allowed"
    assert result["normalized_action"] == action
    assert (output_dir / "policy_decisions.jsonl").is_file()


@pytest.mark.parametrize(
    "action",
    [
        "arbitrary_shell",
        "inspect_raw_evidence",
        "claim_confirmed_exfiltration",
        "upgrade_finding_status",
    ],
)
def test_policy_rejects_unsafe_actions(tmp_path: Path, action: str):
    result = evaluate_action_policy(
        output_dir=tmp_path / "runs" / "case" / "agent-run",
        proposed_action=action,
    )

    assert result["decision"] == "rejected"
    assert result["normalized_action"] is None


def test_policy_rejects_unknown_action(tmp_path: Path):
    result = evaluate_action_policy(
        output_dir=tmp_path / "runs" / "case" / "agent-run",
        proposed_action="invent_tool",
    )

    assert result["decision"] == "rejected"
    assert "allowlist" in str(result["reason"])


@pytest.mark.parametrize(
    "field",
    ["shell", "command", "executable", "argv", "raw_evidence_path", "evidence_write_path"],
)
def test_policy_rejects_model_supplied_unsafe_action_args(tmp_path: Path, field: str):
    result = evaluate_action_policy(
        output_dir=tmp_path / "runs" / "case" / "agent-run",
        proposed_action="inspect_run_state",
        action_args={field: "/mnt/evidence/secret"},
    )

    assert result["decision"] == "rejected"
    assert field in result["rejected_fields"][0]


def test_policy_rejects_duplicate_active_start(tmp_path: Path):
    output_dir = tmp_path / "runs" / "case" / "agent-run"
    output_dir.mkdir(parents=True)
    (output_dir / "run_job.json").write_text(
        '{"status":"running","job_id":"job_000001"}\n',
        encoding="utf-8",
    )

    result = evaluate_action_policy(
        output_dir=output_dir,
        proposed_action="start_case_run",
    )

    assert result["decision"] == "rejected"
    assert "active run job" in str(result["reason"])
