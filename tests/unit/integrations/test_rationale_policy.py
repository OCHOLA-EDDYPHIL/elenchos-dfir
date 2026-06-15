from __future__ import annotations

import json
from pathlib import Path

import pytest

from elenchos.integrations.rationale_policy import evaluate_action_policy


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _append_jsonl(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, sort_keys=True))
        handle.write("\n")


def _write_valid_case_prep(path: Path) -> None:
    artifact = path.parent / "extracted" / "mft" / "$MFT"
    artifact.parent.mkdir(parents=True, exist_ok=True)
    artifact.write_bytes(b"mft")
    path.write_text(
        (
            "{"
            '"case_id":"case",'
            '"coverage_gaps":[],'
            '"prepared_artifacts":[{'
            '"artifact_id":"prep_mft",'
            '"artifact_type":"mft",'
            '"parser_eligible":true,'
            '"path":"extracted/mft/$MFT",'
            '"source_id":"src1",'
            '"status":"available"}],'
            '"sources":[{'
            '"analysis_scope":"primary",'
            '"display_name":"source.E01",'
            '"kind":"ewf_e01",'
            '"role":"disk_image",'
            '"source_id":"src1",'
            '"status":"available"}],'
            '"warnings":[]'
            "}\n"
        ),
        encoding="utf-8",
    )


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


def test_policy_allows_valid_prepared_manifest_path(tmp_path: Path):
    output_dir = tmp_path / "runs" / "case" / "run"
    case_prep = tmp_path / "runs" / "case" / "prep" / "case_prep.json"
    _write_valid_case_prep(case_prep)

    result = evaluate_action_policy(
        output_dir=output_dir,
        proposed_action="start_case_run",
        action_args={
            "output_dir": str(output_dir),
            "prepared_manifest_path": str(case_prep),
        },
    )

    assert result["decision"] == "allowed"
    assert result["safety_checks"]["prepared_manifest_valid"] is True
    assert str(result["policy_decision"]["visible_policy_message"]).startswith("[policy]")


def test_policy_allows_prepare_case_source_root_as_bounded_tool_input(tmp_path: Path):
    result = evaluate_action_policy(
        output_dir=tmp_path / "runs" / "case" / "prep",
        proposed_action="prepare_case",
        action_args={
            "output_dir": str(tmp_path / "runs" / "case" / "prep"),
            "source_root": "/mnt/evidence/rocba",
        },
    )

    assert result["decision"] == "allowed"
    assert result["safety_checks"]["no_model_supplied_evidence_paths"] is True


def test_policy_rejects_start_case_run_after_validation_pass(tmp_path: Path):
    output_dir = tmp_path / "runs" / "case" / "agent-run"
    _write_json(output_dir / "validation_summary.json", {"validation_status": "pass"})
    _write_json(output_dir / "run_job.json", {"status": "completed", "returncode": 0})

    result = evaluate_action_policy(
        output_dir=output_dir,
        proposed_action="start_case_run",
    )

    assert result["decision"] == "rejected"
    assert result["reason"] == "run already completed and validation passed"
    assert "run already completed and validation passed" in (
        output_dir / "policy_decisions.jsonl"
    ).read_text(encoding="utf-8")


def test_post_validation_action_cap_forces_stop(tmp_path: Path):
    output_dir = tmp_path / "runs" / "case" / "agent-run"
    _write_json(output_dir / "validation_summary.json", {"validation_status": "pass"})
    for index, action in enumerate(
        ["summarize_run", "emit_claim_boundary", "summarize_run"],
        start=1,
    ):
        _append_jsonl(
            output_dir / "policy_decisions.jsonl",
            {
                "policy_decision_id": f"policy_{index:06d}",
                "timestamp_utc": f"2026-01-01T00:00:0{index}Z",
                "proposed_action": action,
                "decision": "allowed",
                "reason": "post validation",
                "safety_checks": {},
                "rejected_fields": [],
                "normalized_action": action,
            },
        )

    result = evaluate_action_policy(
        output_dir=output_dir,
        proposed_action="summarize_run",
    )

    assert result["decision"] == "rejected"
    assert "max_post_validation_actions" in str(result["reason"])
    finalization = output_dir / "orchestration_finalization.json"
    assert finalization.is_file()
    assert '"status": "DONE"' in finalization.read_text(encoding="utf-8")
