from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from siftguard.agent.models import (
    AgentArtifactRef,
    AgentCorrection,
    AgentPhase,
    AgentPlan,
    AgentRun,
    AgentRunStatus,
    AgentState,
    AgentStep,
    AgentStepStatus,
    CorrectionAction,
    CorrectionTrigger,
)
from siftguard.validation.models import EvidenceRef

TIMESTAMP = "2026-01-01T00:00:00Z"


def synthetic_evidence_ref() -> EvidenceRef:
    return EvidenceRef(
        artifact_id="artifact_syn_mft",
        parser="mftecmd",
        source="$MFT",
        raw_record_ref="csv:mft.csv:2",
        timestamp_field="Created0x10",
        description="Synthetic parser row reference.",
    )


def make_step(phase: AgentPhase, *, status: AgentStepStatus = AgentStepStatus.PENDING) -> AgentStep:
    return AgentStep(
        step_id=f"step_{phase.value}",
        phase=phase,
        status=status,
        action=f"siftguard.{phase.value}",
        inputs={"artifact_ids": ["artifact_syn_mft"]},
        outputs={"result_ref": f"runs/synthetic/{phase.value}.json"},
    )


def make_plan() -> AgentPlan:
    phases = [
        AgentPhase.INVENTORY,
        AgentPhase.PARSE,
        AgentPhase.CORRELATE,
        AgentPhase.VALIDATE,
        AgentPhase.REPORT,
        AgentPhase.VERIFY,
    ]
    return AgentPlan(
        plan_id="plan_syn_001",
        case_id="case_syn_001",
        objective="Run the constrained SIFTGuard workflow over synthetic artifacts.",
        steps=[make_step(phase) for phase in phases],
        created_at=TIMESTAMP,
    )


def make_correction() -> AgentCorrection:
    return AgentCorrection(
        correction_id="correction_syn_001",
        trigger=CorrectionTrigger.UNSUPPORTED_FINDING,
        diagnosis="Synthetic finding was marked confirmed without support.",
        action=CorrectionAction.DOWNGRADE_FINDING,
        result="Finding status changed to needs_review.",
        related_step_id="step_verify",
        evidence_refs=[synthetic_evidence_ref()],
        created_at=TIMESTAMP,
    )


def test_agent_plan_can_include_required_phases_in_order():
    plan = make_plan()

    assert [step.phase.value for step in plan.steps] == [
        "inventory",
        "parse",
        "correlate",
        "validate",
        "report",
        "verify",
    ]
    assert AgentPlan.from_dict(plan.to_dict()).to_dict() == plan.to_dict()


def test_agent_state_tracks_required_fields():
    correction = make_correction()
    state = AgentState(
        case_id="case_syn_001",
        artifacts=[
            AgentArtifactRef(
                artifact_id="artifact_syn_mft",
                artifact_type="mft",
                relative_path="$MFT",
                sha256="a" * 64,
            )
        ],
        completed_steps=["step_inventory", "step_parse"],
        attempts={"step_parse": 2},
        errors=["first parse output was missing"],
        corrections=[correction],
        final_status=AgentRunStatus.NEEDS_REVIEW,
    )
    payload = state.to_dict()

    assert payload["case_id"] == "case_syn_001"
    assert payload["artifacts"][0]["artifact_id"] == "artifact_syn_mft"
    assert payload["completed_steps"] == ["step_inventory", "step_parse"]
    assert payload["attempts"] == {"step_parse": 2}
    assert payload["errors"] == ["first parse output was missing"]
    assert payload["corrections"] == [correction.to_dict()]
    assert payload["final_status"] == "needs_review"
    assert AgentState.from_dict(payload).to_dict() == payload


def test_agent_correction_includes_auditable_contract_fields():
    payload = make_correction().to_dict()

    assert payload["trigger"] == "unsupported_finding"
    assert payload["diagnosis"] == "Synthetic finding was marked confirmed without support."
    assert payload["action"] == "downgrade_finding"
    assert payload["result"] == "Finding status changed to needs_review."
    assert payload["related_step_id"] == "step_verify"
    assert payload["evidence_refs"][0]["raw_record_ref"] == "csv:mft.csv:2"
    assert AgentCorrection.from_dict(payload).to_dict() == payload


@pytest.mark.parametrize(
    ("field_name", "payload"),
    [
        ("command", {"command": "python parser.py"}),
        ("shell", {"safe": {"shell": "/bin/bash"}}),
        ("argv", {"items": [{"argv": ["python", "-m", "siftguard"]}]}),
        ("powershell", {"nested": [{"safe": {"powershell": "Get-ChildItem"}}]}),
    ],
)
def test_agent_step_rejects_shell_command_style_input(field_name, payload):
    with pytest.raises(ValueError, match=field_name):
        AgentStep(
            step_id="step_parse",
            phase=AgentPhase.PARSE,
            status=AgentStepStatus.PENDING,
            inputs=payload,
        )


def test_agent_step_rejects_shell_command_style_output():
    with pytest.raises(ValueError, match="raw_command"):
        AgentStep(
            step_id="step_parse",
            phase=AgentPhase.PARSE,
            status=AgentStepStatus.PENDING,
            outputs={"raw_command": "MFTECmd.exe -f evidence"},
        )


def test_agent_step_rejects_invalid_phase_and_status_values():
    with pytest.raises(ValueError, match="invalid phase"):
        AgentStep(
            step_id="step_memory",
            phase="memory",
            status=AgentStepStatus.PENDING,
        )

    with pytest.raises(ValueError, match="invalid step status"):
        AgentStep(
            step_id="step_parse",
            phase=AgentPhase.PARSE,
            status="confirmed",
        )


def test_agent_run_serializes_deterministically_and_round_trips():
    plan = make_plan()
    completed_step = make_step(AgentPhase.INVENTORY, status=AgentStepStatus.COMPLETED)
    correction = make_correction()
    state = AgentState(
        case_id="case_syn_001",
        artifacts=[AgentArtifactRef("artifact_syn_mft", "mft", "$MFT", "a" * 64)],
        completed_steps=[completed_step.step_id],
        attempts={completed_step.step_id: 1},
        errors=[],
        corrections=[correction],
        final_status=AgentRunStatus.NEEDS_REVIEW,
    )
    run = AgentRun(
        run_id="run_syn_001",
        case_id="case_syn_001",
        status=AgentRunStatus.NEEDS_REVIEW,
        plan=plan,
        state=state,
        started_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        completed_at="2026-01-01T00:05:00Z",
        max_iterations=3,
        max_normalized_events=5000,
        event_selection_profile="forensic-triage",
        steps=[completed_step],
        corrections=[correction],
        output_refs={
            "agent_run": "runs/synthetic/agent_run.json",
            "audit": "runs/synthetic/audit.jsonl",
        },
        warnings=["Synthetic verification requires analyst review."],
        errors=[],
    )

    payload = run.to_dict()
    encoded = run.to_json()

    assert encoded == json.dumps(payload, sort_keys=True, separators=(",", ":"))
    assert payload["started_at"] == TIMESTAMP
    assert payload["max_normalized_events"] == 5000
    assert payload["event_selection_profile"] == "forensic-triage"
    assert json.loads(encoded) == payload
    assert AgentRun.from_dict(payload).to_dict() == payload


def test_agent_run_rejects_case_id_mismatch():
    plan = make_plan()
    state = AgentState(case_id="case_other")

    with pytest.raises(ValueError, match="state case_id"):
        AgentRun(
            run_id="run_syn_001",
            case_id="case_syn_001",
            status=AgentRunStatus.RUNNING,
            plan=plan,
            state=state,
            started_at=TIMESTAMP,
            max_iterations=3,
        )


def test_agent_run_rejects_invalid_max_normalized_events():
    plan = make_plan()
    state = AgentState(case_id="case_syn_001")

    with pytest.raises(ValueError, match="max_normalized_events"):
        AgentRun(
            run_id="run_syn_001",
            case_id="case_syn_001",
            status=AgentRunStatus.RUNNING,
            plan=plan,
            state=state,
            started_at=TIMESTAMP,
            max_iterations=3,
            max_normalized_events=0,
        )
