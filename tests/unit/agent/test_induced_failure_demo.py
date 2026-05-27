from __future__ import annotations

import json
from pathlib import Path

from siftguard.agent.models import (
    AgentPhase,
    AgentPlan,
    AgentRun,
    AgentRunStatus,
    AgentState,
    AgentStep,
    AgentStepStatus,
    CorrectionAction,
)
from siftguard.agent.self_correction import apply_self_correction
from siftguard.agent.verifier import (
    VerificationFailureKind,
    VerificationStatus,
    verify_agent_outputs,
)
from siftguard.audit.execution_ledger import read_events

CASE_ID = "CASE-SYN-DEMO-001"
TIMESTAMP = "2026-01-01T00:00:00Z"
FIXTURE_PATH = Path("tests/fixtures/agent/unsupported_confirmed_finding.json")


def fixed_clock() -> str:
    return TIMESTAMP


def load_demo_finding() -> dict[str, object]:
    return json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))


def make_agent_run() -> AgentRun:
    phases = [
        AgentPhase.INVENTORY,
        AgentPhase.PARSE,
        AgentPhase.CORRELATE,
        AgentPhase.VALIDATE,
        AgentPhase.REPORT,
        AgentPhase.VERIFY,
    ]
    plan = AgentPlan(
        plan_id=f"plan_{CASE_ID}",
        case_id=CASE_ID,
        objective="Demonstrate synthetic unsupported finding self-correction.",
        steps=[
            AgentStep(
                step_id=f"step_{phase.value}",
                phase=phase,
                status=AgentStepStatus.PENDING,
                action=f"siftguard.agent.{phase.value}",
            )
            for phase in phases
        ],
        created_at=TIMESTAMP,
    )
    return AgentRun(
        run_id=f"run_{CASE_ID}",
        case_id=CASE_ID,
        status=AgentRunStatus.RUNNING,
        plan=plan,
        state=AgentState(case_id=CASE_ID, final_status=AgentRunStatus.RUNNING),
        started_at=TIMESTAMP,
        max_iterations=7,
        steps=[
            AgentStep(
                step_id="step_parse",
                phase=AgentPhase.PARSE,
                status=AgentStepStatus.COMPLETED,
                outputs={"normalized_events": "normalized_events.json"},
            ),
            AgentStep(
                step_id="step_correlate",
                phase=AgentPhase.CORRELATE,
                status=AgentStepStatus.COMPLETED,
                outputs={"subject_timelines": "subject_timelines.json"},
            ),
            AgentStep(
                step_id="step_validate",
                phase=AgentPhase.VALIDATE,
                status=AgentStepStatus.COMPLETED,
                outputs={"findings": "findings.json"},
            ),
            AgentStep(
                step_id="step_report",
                phase=AgentPhase.REPORT,
                status=AgentStepStatus.COMPLETED,
                outputs={"report": "report.md"},
            ),
        ],
        output_refs={
            "normalized_events": "normalized_events.json",
            "subject_timelines": "subject_timelines.json",
            "findings": "findings.json",
            "report": "report.md",
            "agent_run": "agent_run.json",
        },
    )


def write_demo_outputs(output_dir: Path, finding: dict[str, object]) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "normalized_events.json").write_text(
        json.dumps({"case_id": CASE_ID, "event_count": 0, "events": []}) + "\n",
        encoding="utf-8",
    )
    (output_dir / "subject_timelines.json").write_text(
        json.dumps({"case_id": CASE_ID, "timeline_count": 0, "timelines": []}) + "\n",
        encoding="utf-8",
    )
    (output_dir / "findings.json").write_text(
        json.dumps(
            {
                "case_id": CASE_ID,
                "finding_count": 1,
                "findings": [finding],
                "validation_results": [
                    {
                        "finding": finding,
                        "original_requested_status": "confirmed",
                        "final_status": "confirmed",
                        "validation_notes": ["synthetic induced failure"],
                    }
                ],
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    (output_dir / "report.md").write_text(
        "\n".join(
            [
                "# Case Report",
                "",
                "## Confirmed Findings",
                f"- `{finding['finding_id']}` {finding['claim']}",
                "",
            ]
        ),
        encoding="utf-8",
    )


def finding_status(output_dir: Path) -> str:
    payload = json.loads((output_dir / "findings.json").read_text(encoding="utf-8"))
    return str(payload["findings"][0]["status"])


def test_induced_unsupported_confirmed_finding_demo_is_corrected(tmp_path: Path):
    output_dir = tmp_path / "runs" / CASE_ID
    audit_path = output_dir / "audit.jsonl"
    agent_run_path = output_dir / "agent_run.json"
    finding = load_demo_finding()
    finding_id = str(finding["finding_id"])
    run = make_agent_run()
    write_demo_outputs(output_dir, finding)

    assert finding["status"] == "confirmed"
    assert finding["evidence_refs"] == []
    assert finding_status(output_dir) == "confirmed"

    verification = verify_agent_outputs(
        case_id=CASE_ID,
        output_dir=output_dir,
        agent_run=run,
        audit_log_path=audit_path,
        clock=fixed_clock,
    )

    assert verification.status is VerificationStatus.FAILED
    assert {
        failure.kind for failure in verification.failures
    } == {
        VerificationFailureKind.MISSING_EVIDENCE_REFS,
        VerificationFailureKind.UNSUPPORTED_CONFIRMED_FINDING,
    }
    assert {failure.finding_id for failure in verification.failures} == {finding_id}

    correction = apply_self_correction(
        case_id=CASE_ID,
        output_dir=output_dir,
        agent_run=run,
        verification_result=verification,
        audit_log_path=audit_path,
        inventory_recheck=lambda: {"artifact_count": 0},
        clock=fixed_clock,
    )
    agent_run_path.write_text(
        json.dumps(run.to_dict(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    assert correction.corrected is True
    assert finding_status(output_dir) == "needs_review"
    assert run.corrections[-1].action is CorrectionAction.DOWNGRADE_FINDING

    agent_run_payload = json.loads(agent_run_path.read_text(encoding="utf-8"))
    assert agent_run_payload["corrections"][-1]["action"] == "downgrade_finding"
    assert agent_run_payload["corrections"][-1]["result"] == (
        "Finding status changed to needs_review."
    )

    followup = verify_agent_outputs(
        case_id=CASE_ID,
        output_dir=output_dir,
        agent_run=run,
        audit_log_path=audit_path,
        clock=fixed_clock,
    )

    assert followup.status is VerificationStatus.PASSED
    assert followup.failures == []
    report = (output_dir / "report.md").read_text(encoding="utf-8")
    assert "## Confirmed Findings\n- No confirmed findings." in report
    assert "Status: `needs_review`" in report

    events = read_events(audit_path)
    verification_events = [
        event for event in events if event["event_type"] == "verification_failed"
    ]
    correction_events = [
        event for event in events if event["event_type"] == "correction_applied"
    ]
    assert [event["failure_kind"] for event in verification_events] == [
        "missing_evidence_refs",
        "unsupported_confirmed_finding",
    ]
    assert correction_events[-1]["correction_action"] == "downgrade_finding"
    assert correction_events[-1]["correction"]["diagnosis"].startswith(
        f"Finding {finding_id} was confirmed"
    )
    assert correction_events[-1]["correction"]["result"] == (
        "Finding status changed to needs_review."
    )
