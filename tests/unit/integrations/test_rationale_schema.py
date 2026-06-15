from __future__ import annotations

from elenchos.integrations.rationale_schema import (
    ModelRationaleRecord,
    PolicyDecisionRecord,
    RunStateSummary,
)


def test_model_rationale_record_round_trips_required_fields():
    record = ModelRationaleRecord(
        rationale_id="rationale_000001",
        timestamp_utc="2026-01-01T00:00:00Z",
        phase="validation",
        visible_message="[model-rationale] Validate generated outputs.",
        proposed_action="validate_run_outputs",
        rationale_summary="Validation is the next bounded action.",
        basis_files=["runs/case/agent-run/findings.json"],
        observed_state={"validation_status": None},
        forbidden_claims_avoided=["confirmed theft"],
        confidence="medium",
    )

    payload = record.to_dict()

    assert payload["rationale_id"] == "rationale_000001"
    assert payload["proposed_action"] == "validate_run_outputs"
    assert payload["observed_state"] == {"validation_status": None}


def test_policy_decision_record_round_trips_required_fields():
    record = PolicyDecisionRecord(
        policy_decision_id="policy_000001",
        timestamp_utc="2026-01-01T00:00:00Z",
        rationale_id="rationale_000001",
        proposed_action="poll_case_run",
        decision="allowed",
        reason="reads generated progress only",
        safety_checks={"action_allowlisted": True},
        rejected_fields=[],
        normalized_action="poll_case_run",
    )

    assert record.to_dict()["decision"] == "allowed"
    assert record.to_dict()["normalized_action"] == "poll_case_run"


def test_run_state_summary_round_trips_counts():
    summary = RunStateSummary(
        case_id="case",
        output_dir="runs/case/agent-run",
        agent_run_dir="runs/case/agent-run",
        required_outputs_present={"findings.json": True},
        finding_status_counts={"needs_review": 1},
        case_question_status_counts={"not_assessed": 2},
        coverage_gap_count=3,
        self_correction_count=1,
        validation_status=None,
        active_job=None,
        recommended_next_actions=["validate_run_outputs"],
        allowed_actions=["validate_run_outputs"],
        claim_boundary_required=True,
        basis_files=["runs/case/agent-run/findings.json"],
    )

    assert summary.to_dict()["claim_boundary_required"] is True
    assert summary.to_dict()["finding_status_counts"] == {"needs_review": 1}
