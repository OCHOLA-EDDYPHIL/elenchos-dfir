from __future__ import annotations

import json
from pathlib import Path

import pytest

from elenchos.integrations.tool_adapter import dispatch_tool


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_minimal_generated_run(output_dir: Path) -> None:
    _write_json(output_dir / "agent_run.json", {"case_id": "case", "status": "completed"})
    _write_json(
        output_dir / "findings.json",
        {"findings": [{"finding_id": "f1", "status": "needs_review"}]},
    )
    _write_json(
        output_dir / "case_questions.json",
        {
            "questions": [
                {
                    "question_id": "q_exfiltration",
                    "question": "Was exfiltration supported?",
                    "status": "not_assessed",
                    "reason": "unsupported",
                }
            ],
            "claim_boundaries": [
                {
                    "final_wording": "Generated boundary wording.",
                    "scope_boundary": "Generated scope boundary.",
                    "recommended_next_artifacts": ["network telemetry"],
                }
            ],
        },
    )
    (output_dir / "report.md").write_text("# Report\n", encoding="utf-8")


def test_record_rationale_policy_and_claim_boundary_tools(tmp_path: Path):
    output_dir = tmp_path / "runs" / "case" / "agent-run"
    _write_minimal_generated_run(output_dir)

    state = dispatch_tool("inspect_run_state", {"output_dir": str(output_dir)})
    rationale = dispatch_tool(
        "record_model_rationale",
        {
            "output_dir": str(output_dir),
            "phase": "validation",
            "visible_message": "[model-rationale] Validate generated outputs.",
            "proposed_action": "validate_run_outputs",
            "rationale_summary": "Validation is the next safe bounded action.",
            "basis_files": state["basis_files"],
            "observed_state": state,
            "forbidden_claims_avoided": ["confirmed exfiltration"],
            "confidence": "medium",
        },
    )
    policy = dispatch_tool(
        "evaluate_action_policy",
        {
            "output_dir": str(output_dir),
            "proposed_action": "validate_run_outputs",
            "action_args": {"output_dir": str(output_dir)},
            "rationale_id": rationale["rationale_id"],
        },
    )
    boundary = dispatch_tool("emit_claim_boundary", {"output_dir": str(output_dir)})

    assert state["claim_boundary_required"] is True
    assert rationale["rationale_id"] == "rationale_000001"
    assert policy["decision"] == "allowed"
    assert policy["visible_policy_message"].startswith("[policy]")
    assert boundary["claim_boundaries"][0]["final_wording"] == "Generated boundary wording."
    assert (output_dir / "model_rationale.jsonl").is_file()
    assert (output_dir / "policy_decisions.jsonl").is_file()


def test_record_model_rationale_rejects_unsupported_confirmed_claim(tmp_path: Path):
    output_dir = tmp_path / "runs" / "case" / "agent-run"
    _write_minimal_generated_run(output_dir)

    with pytest.raises(ValueError, match="unsupported final forensic claims"):
        dispatch_tool(
            "record_model_rationale",
            {
                "output_dir": str(output_dir),
                "phase": "unsafe",
                "visible_message": "[model-rationale] confirmed exfiltration occurred.",
                "proposed_action": "validate_run_outputs",
                "rationale_summary": "confirmed exfiltration",
                "basis_files": [],
                "confidence": "low",
            },
        )
