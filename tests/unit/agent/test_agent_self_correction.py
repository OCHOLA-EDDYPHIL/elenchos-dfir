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
    CorrectionTrigger,
)
from siftguard.agent.self_correction import apply_self_correction
from siftguard.agent.verifier import (
    VerificationFailure,
    VerificationFailureKind,
    VerificationResult,
    VerificationStatus,
    verify_agent_outputs,
)
from siftguard.audit.execution_ledger import read_events

CASE_ID = "CASE-SYN-CORRECT-001"
TIMESTAMP = "2026-01-01T00:00:00Z"


def fixed_clock() -> str:
    return TIMESTAMP


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
        objective="Correct synthetic generated outputs.",
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
        },
    )


def write_generated_outputs(output_dir: Path, findings: list[dict[str, object]]) -> None:
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
                "finding_count": len(findings),
                "findings": findings,
                "validation_results": [
                    {
                        "finding": finding,
                        "original_requested_status": finding["status"],
                        "final_status": finding["status"],
                        "validation_notes": ["synthetic"],
                    }
                    for finding in findings
                ],
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    lines = ["# Case Report", "", "## Confirmed Findings"]
    for finding in findings:
        lines.append(f"- `{finding['finding_id']}` {finding['claim']}")
    lines.append("")
    (output_dir / "report.md").write_text("\n".join(lines), encoding="utf-8")


def unsupported_finding(finding_id: str, status: str) -> dict[str, object]:
    return {
        "finding_id": finding_id,
        "claim": f"Synthetic unsupported {status} finding.",
        "status": status,
        "confidence": "high",
        "kind": "conclusion",
        "evidence_refs": [],
        "audit_event_refs": [],
        "artifact_hashes": [],
        "raw_record_refs": [],
        "rationale": "Synthetic unsupported rationale.",
        "limitations": [],
        "supports_final_report": False,
    }


def verification_failure_result(finding_id: str, *, status: str) -> VerificationResult:
    failures = [
        VerificationFailure(
            kind=VerificationFailureKind.MISSING_EVIDENCE_REFS,
            message=f"{status} finding lacks evidence_refs.",
            phase=AgentPhase.VALIDATE,
            step_id="step_validate",
            finding_id=finding_id,
        )
    ]
    if status == "confirmed":
        failures.append(
            VerificationFailure(
                kind=VerificationFailureKind.UNSUPPORTED_CONFIRMED_FINDING,
                message="confirmed finding lacks final-report support.",
                phase=AgentPhase.VALIDATE,
                step_id="step_validate",
                finding_id=finding_id,
            )
        )
    return VerificationResult(
        case_id=CASE_ID,
        status=VerificationStatus.FAILED,
        checked_at=TIMESTAMP,
        failures=failures,
    )


def test_unsupported_confirmed_finding_is_downgraded_and_audited(tmp_path: Path):
    output_dir = tmp_path / "runs" / CASE_ID
    finding_id = "F-SYN-CONFIRMED-UNSUPPORTED"
    write_generated_outputs(output_dir, [unsupported_finding(finding_id, "confirmed")])
    run = make_agent_run()

    result = apply_self_correction(
        case_id=CASE_ID,
        output_dir=output_dir,
        agent_run=run,
        verification_result=verification_failure_result(finding_id, status="confirmed"),
        audit_log_path=output_dir / "audit.jsonl",
        inventory_recheck=lambda: {"artifact_count": 0},
        clock=fixed_clock,
    )

    corrected = json.loads((output_dir / "findings.json").read_text(encoding="utf-8"))
    corrected_finding = corrected["findings"][0]
    assert result.corrected is True
    assert corrected_finding["status"] == "needs_review"
    assert corrected_finding["supports_final_report"] is False
    assert "evidence support" in corrected_finding["limitations"][0]
    assert [correction.action for correction in run.corrections] == [
        CorrectionAction.RECHECK_INVENTORY,
        CorrectionAction.DOWNGRADE_FINDING,
    ]
    assert run.corrections[1].trigger is CorrectionTrigger.UNSUPPORTED_FINDING
    assert run.corrections[1].diagnosis
    assert run.corrections[1].result == "Finding status changed to needs_review."

    events = read_events(output_dir / "audit.jsonl")
    for event in events:
        assert event["event_type"] == event["action"]
        assert event["timestamp_utc"] == TIMESTAMP
        assert event["case_id"] == CASE_ID
        assert isinstance(event["duration_ms"], int)
        assert isinstance(event["output_refs"], dict)
    applied_events = [event for event in events if event["action"] == "correction_applied"]
    assert len(applied_events) == 2
    assert applied_events[-1]["correction_id"] == "correction_000002"
    assert applied_events[-1]["correction_action"] == "downgrade_finding"
    assert applied_events[-1]["correction_trigger"] == "unsupported_finding"
    assert run.to_dict()["corrections"][1]["action"] == "downgrade_finding"


def test_unsupported_inferred_finding_is_downgraded_to_needs_review(tmp_path: Path):
    output_dir = tmp_path / "runs" / CASE_ID
    finding_id = "F-SYN-INFERRED-UNSUPPORTED"
    write_generated_outputs(output_dir, [unsupported_finding(finding_id, "inferred")])
    run = make_agent_run()

    apply_self_correction(
        case_id=CASE_ID,
        output_dir=output_dir,
        agent_run=run,
        verification_result=verification_failure_result(finding_id, status="inferred"),
        inventory_recheck=lambda: {"artifact_count": 0},
        clock=fixed_clock,
    )

    corrected = json.loads((output_dir / "findings.json").read_text(encoding="utf-8"))
    assert corrected["findings"][0]["status"] == "needs_review"
    assert run.corrections[-1].action is CorrectionAction.DOWNGRADE_FINDING


def test_missing_parser_output_uses_safe_retry_callback(tmp_path: Path):
    output_dir = tmp_path / "runs" / CASE_ID
    write_generated_outputs(output_dir, [])
    parser_output = output_dir / "normalized_events.json"
    parser_output.unlink()
    run = make_agent_run()
    failure = VerificationFailure(
        kind=VerificationFailureKind.MISSING_PARSER_OUTPUT,
        message="Parser output reference does not exist.",
        phase=AgentPhase.PARSE,
        step_id="step_parse",
        path="normalized_events.json",
    )

    def retry(_failure: VerificationFailure) -> bool:
        parser_output.write_text(
            json.dumps({"case_id": CASE_ID, "event_count": 0, "events": []}) + "\n",
            encoding="utf-8",
        )
        return True

    result = apply_self_correction(
        case_id=CASE_ID,
        output_dir=output_dir,
        agent_run=run,
        verification_result=VerificationResult(
            case_id=CASE_ID,
            status=VerificationStatus.FAILED,
            checked_at=TIMESTAMP,
            failures=[failure],
        ),
        parser_retry=retry,
        clock=fixed_clock,
    )

    assert result.corrected is True
    assert parser_output.exists()
    assert run.corrections[0].trigger is CorrectionTrigger.MISSING_OUTPUT
    assert run.corrections[0].action is CorrectionAction.RETRY


def test_report_only_unsupported_claim_is_removed_by_regenerating_report(tmp_path: Path):
    output_dir = tmp_path / "runs" / CASE_ID
    finding_id = "F-SYN-SUPPORTED"
    write_generated_outputs(
        output_dir,
        [
            {
                **unsupported_finding(finding_id, "needs_review"),
                "supports_final_report": False,
            }
        ],
    )
    report_path = output_dir / "report.md"
    report_path.write_text(
        "# Case Report\n\n## Confirmed Findings\n- `F-SYN-GHOST` Synthetic ghost.\n",
        encoding="utf-8",
    )
    run = make_agent_run()
    failure = VerificationFailure(
        kind=VerificationFailureKind.REPORTED_FINDING_MISSING,
        message="Markdown report references a finding absent from validated output.",
        phase=AgentPhase.REPORT,
        step_id="step_report",
        path="report.md",
        finding_id="F-SYN-GHOST",
    )

    result = apply_self_correction(
        case_id=CASE_ID,
        output_dir=output_dir,
        agent_run=run,
        verification_result=VerificationResult(
            case_id=CASE_ID,
            status=VerificationStatus.FAILED,
            checked_at=TIMESTAMP,
            failures=[failure],
        ),
        clock=fixed_clock,
    )

    assert result.corrected is True
    assert "F-SYN-GHOST" not in report_path.read_text(encoding="utf-8")
    assert run.corrections[0].action is CorrectionAction.RETRY
    assert verify_agent_outputs(
        case_id=CASE_ID,
        output_dir=output_dir,
        agent_run=run,
        clock=fixed_clock,
    ).status is VerificationStatus.PASSED
