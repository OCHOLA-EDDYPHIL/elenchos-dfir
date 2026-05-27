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
)
from siftguard.agent.verifier import (
    VerificationFailureKind,
    VerificationResult,
    VerificationStatus,
    verify_agent_outputs,
)
from siftguard.audit.execution_ledger import read_events

CASE_ID = "CASE-SYN-VERIFY-001"
TIMESTAMP = "2026-01-01T00:00:00Z"
SYNTHETIC_HASH = "sha256:" + ("a" * 64)


def fixed_clock() -> str:
    return TIMESTAMP


def _plan_step(phase: AgentPhase) -> AgentStep:
    return AgentStep(
        step_id=f"step_{phase.value}",
        phase=phase,
        status=AgentStepStatus.PENDING,
        action=f"siftguard.agent.{phase.value}",
    )


def _run_step(phase: AgentPhase, outputs: dict[str, object] | None = None) -> AgentStep:
    return AgentStep(
        step_id=f"step_{phase.value}",
        phase=phase,
        status=AgentStepStatus.COMPLETED,
        started_at=TIMESTAMP,
        completed_at=TIMESTAMP,
        outputs=dict(outputs or {}),
        action=f"siftguard.agent.{phase.value}",
    )


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
        objective="Verify synthetic agent outputs.",
        steps=[_plan_step(phase) for phase in phases],
        created_at=TIMESTAMP,
    )
    return AgentRun(
        run_id=f"run_{CASE_ID}",
        case_id=CASE_ID,
        status=AgentRunStatus.RUNNING,
        plan=plan,
        state=AgentState(case_id=CASE_ID, final_status=AgentRunStatus.RUNNING),
        started_at=TIMESTAMP,
        max_iterations=6,
        steps=[
            _run_step(AgentPhase.INVENTORY),
            _run_step(AgentPhase.PARSE, {"normalized_events": "normalized_events.json"}),
            _run_step(AgentPhase.CORRELATE, {"subject_timelines": "subject_timelines.json"}),
            _run_step(AgentPhase.VALIDATE, {"findings": "findings.json"}),
            _run_step(AgentPhase.REPORT, {"report": "report.md"}),
        ],
        output_refs={
            "normalized_events": "normalized_events.json",
            "findings": "findings.json",
            "report": "report.md",
        },
    )


def supported_finding(finding_id: str = "F-SYN-SUPPORTED-001") -> dict[str, object]:
    return {
        "finding_id": finding_id,
        "claim": "Synthetic supported finding.",
        "status": "confirmed",
        "confidence": "high",
        "kind": "conclusion",
        "evidence_refs": [
            {
                "evidence_id": "EV-SYN-001",
                "artifact_id": None,
                "parser": "mftecmd",
                "source": "$MFT",
                "raw_record_ref": "csv:mft.csv:2",
                "timestamp_field": "Created0x10",
                "description": "Synthetic evidence reference.",
            }
        ],
        "audit_event_refs": ["evt_000001"],
        "artifact_hashes": [SYNTHETIC_HASH],
        "raw_record_refs": [],
        "rationale": "Synthetic evidence supports this finding.",
        "limitations": [],
        "supports_final_report": True,
    }


def write_outputs(
    output_dir: Path,
    *,
    findings: list[dict[str, object]] | None = None,
    report_ids: list[str] | None = None,
    write_parser_output: bool = True,
) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    if write_parser_output:
        (output_dir / "normalized_events.json").write_text(
            json.dumps({"case_id": CASE_ID, "event_count": 0, "events": []}) + "\n",
            encoding="utf-8",
        )
    finding_rows = list(findings if findings is not None else [supported_finding()])
    (output_dir / "findings.json").write_text(
        json.dumps(
            {
                "case_id": CASE_ID,
                "finding_count": len(finding_rows),
                "findings": finding_rows,
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    ids = list(report_ids if report_ids is not None else [str(finding_rows[0]["finding_id"])])
    report_lines = ["# Case Report", "", "## Confirmed Findings"]
    report_lines.extend(f"- `{finding_id}` Synthetic reported finding." for finding_id in ids)
    report_lines.append("")
    (output_dir / "report.md").write_text("\n".join(report_lines), encoding="utf-8")


def failure_kinds(result) -> set[VerificationFailureKind]:
    return {failure.kind for failure in result.failures}


def test_missing_parser_output_emits_machine_readable_failure(tmp_path: Path):
    output_dir = tmp_path / "runs" / CASE_ID
    write_outputs(output_dir, write_parser_output=False)

    result = verify_agent_outputs(
        case_id=CASE_ID,
        output_dir=output_dir,
        agent_run=make_agent_run(),
        clock=fixed_clock,
    )

    assert result.status is VerificationStatus.FAILED
    assert VerificationFailureKind.MISSING_PARSER_OUTPUT in failure_kinds(result)
    failure = result.failures[0].to_dict()
    assert failure["kind"] == "missing_parser_output"
    assert failure["phase"] == "parse"
    assert failure["path"] == "normalized_events.json"


def test_confirmed_finding_without_evidence_refs_emits_failures(tmp_path: Path):
    output_dir = tmp_path / "runs" / CASE_ID
    unsupported = supported_finding()
    unsupported["evidence_refs"] = []
    unsupported["supports_final_report"] = False
    write_outputs(output_dir, findings=[unsupported])

    result = verify_agent_outputs(
        case_id=CASE_ID,
        output_dir=output_dir,
        agent_run=make_agent_run(),
        clock=fixed_clock,
    )

    assert VerificationFailureKind.MISSING_EVIDENCE_REFS in failure_kinds(result)
    assert VerificationFailureKind.UNSUPPORTED_CONFIRMED_FINDING in failure_kinds(result)
    assert {failure.finding_id for failure in result.failures} == {"F-SYN-SUPPORTED-001"}


def test_inferred_finding_without_evidence_refs_emits_failure(tmp_path: Path):
    output_dir = tmp_path / "runs" / CASE_ID
    inferred = supported_finding("F-SYN-INFERRED-001")
    inferred["status"] = "inferred"
    inferred["evidence_refs"] = []
    inferred["artifact_hashes"] = []
    inferred["supports_final_report"] = False
    write_outputs(output_dir, findings=[inferred])

    result = verify_agent_outputs(
        case_id=CASE_ID,
        output_dir=output_dir,
        agent_run=make_agent_run(),
        clock=fixed_clock,
    )

    assert failure_kinds(result) == {VerificationFailureKind.MISSING_EVIDENCE_REFS}
    assert result.failures[0].finding_id == "F-SYN-INFERRED-001"


def test_reported_finding_absent_from_validated_findings_emits_failure(tmp_path: Path):
    output_dir = tmp_path / "runs" / CASE_ID
    write_outputs(output_dir, report_ids=["F-SYN-MISSING-001"])

    result = verify_agent_outputs(
        case_id=CASE_ID,
        output_dir=output_dir,
        agent_run=make_agent_run(),
        clock=fixed_clock,
    )

    assert failure_kinds(result) == {VerificationFailureKind.REPORTED_FINDING_MISSING}
    assert result.failures[0].finding_id == "F-SYN-MISSING-001"


def test_unsupported_confirmed_finding_is_detected(tmp_path: Path):
    output_dir = tmp_path / "runs" / CASE_ID
    unsupported = supported_finding("F-SYN-UNSUPPORTED-001")
    unsupported["artifact_hashes"] = []
    unsupported["supports_final_report"] = False
    write_outputs(output_dir, findings=[unsupported])

    result = verify_agent_outputs(
        case_id=CASE_ID,
        output_dir=output_dir,
        agent_run=make_agent_run(),
        clock=fixed_clock,
    )

    assert failure_kinds(result) == {VerificationFailureKind.UNSUPPORTED_CONFIRMED_FINDING}
    assert result.failures[0].finding_id == "F-SYN-UNSUPPORTED-001"


def test_verification_failures_are_written_to_audit_jsonl(tmp_path: Path):
    output_dir = tmp_path / "runs" / CASE_ID
    audit_path = output_dir / "audit.jsonl"
    write_outputs(output_dir, write_parser_output=False)

    verify_agent_outputs(
        case_id=CASE_ID,
        output_dir=output_dir,
        agent_run=make_agent_run(),
        audit_log_path=audit_path,
        clock=fixed_clock,
    )

    events = read_events(audit_path)
    assert [event["action"] for event in events] == [
        "verification_started",
        "verification_failed",
        "verification_completed",
    ]
    assert events[1]["failure"]["kind"] == "missing_parser_output"
    assert events[-1]["failure_count"] == 1


def test_successful_verification_has_no_failures_and_round_trips(tmp_path: Path):
    output_dir = tmp_path / "runs" / CASE_ID
    write_outputs(output_dir)

    result = verify_agent_outputs(
        case_id=CASE_ID,
        output_dir=output_dir,
        agent_run=make_agent_run(),
        clock=fixed_clock,
    )

    assert result.status is VerificationStatus.PASSED
    assert result.failures == []
    payload = result.to_dict()
    assert payload["failure_count"] == 0
    assert VerificationResult.from_dict(payload).to_dict() == payload
