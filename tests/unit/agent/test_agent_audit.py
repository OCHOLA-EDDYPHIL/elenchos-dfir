from __future__ import annotations

from pathlib import Path

from siftguard.agent.audit import (
    append_agent_audit_event,
    record_agent_step_event,
    record_correction_event,
    record_verification_failure,
)
from siftguard.agent.models import (
    AgentCorrection,
    AgentPhase,
    AgentStep,
    AgentStepStatus,
    CorrectionAction,
    CorrectionTrigger,
)
from siftguard.audit.execution_ledger import read_events

CASE_ID = "CASE-SYN-AUDIT-001"
RUN_ID = "run_CASE-SYN-AUDIT-001"
TIMESTAMP = "2026-01-01T00:00:00Z"


def fixed_clock() -> str:
    return TIMESTAMP


def test_append_agent_audit_event_writes_stable_base_shape(tmp_path: Path):
    ledger = tmp_path / "audit.jsonl"

    append_agent_audit_event(
        ledger,
        event_type="agent_run_started",
        case_id=CASE_ID,
        run_id=RUN_ID,
        status="running",
        output_refs={"agent_run": "agent_run.json"},
        clock=fixed_clock,
    )

    events = read_events(ledger)
    assert events == [
        {
            "action": "agent_run_started",
            "attempt": None,
            "case_id": CASE_ID,
            "correction_action": None,
            "correction_id": None,
            "correction_trigger": None,
            "duration_ms": 0,
            "event_id": "evt_000001",
            "event_type": "agent_run_started",
            "failure_kind": None,
            "finding_id": None,
            "output_refs": {"agent_run": "agent_run.json"},
            "phase": None,
            "run_id": RUN_ID,
            "status": "running",
            "step_id": None,
            "timestamp_utc": TIMESTAMP,
        }
    ]


def test_record_agent_step_event_includes_step_context(tmp_path: Path):
    ledger = tmp_path / "audit.jsonl"
    step = AgentStep(
        step_id="step_parse",
        phase=AgentPhase.PARSE,
        status=AgentStepStatus.COMPLETED,
        action="siftguard.agent.parse",
        attempt=2,
        max_attempts=2,
        outputs={"normalized_events": "normalized_events.json"},
    )

    record_agent_step_event(
        ledger,
        event_type="agent_step_completed",
        case_id=CASE_ID,
        run_id=RUN_ID,
        step=step,
        status=step.status.value,
        output_refs={"normalized_events": "normalized_events.json"},
        clock=fixed_clock,
    )

    event = read_events(ledger)[0]
    assert event["event_type"] == "agent_step_completed"
    assert event["step_id"] == "step_parse"
    assert event["phase"] == "parse"
    assert event["attempt"] == 2
    assert event["duration_ms"] == 0
    assert event["output_refs"] == {"normalized_events": "normalized_events.json"}


def test_record_verification_failure_includes_machine_readable_failure_fields(
    tmp_path: Path,
):
    ledger = tmp_path / "audit.jsonl"
    failure = {
        "kind": "missing_parser_output",
        "message": "Parser output reference does not exist.",
        "severity": "error",
        "phase": "parse",
        "step_id": "step_parse",
        "path": "normalized_events.json",
        "finding_id": None,
    }

    record_verification_failure(
        ledger,
        case_id=CASE_ID,
        run_id=RUN_ID,
        failure=failure,
        status="failed",
        output_refs={"normalized_events": "normalized_events.json"},
        clock=fixed_clock,
    )

    event = read_events(ledger)[0]
    assert event["event_type"] == "verification_failed"
    assert event["failure_kind"] == "missing_parser_output"
    assert event["step_id"] == "step_parse"
    assert event["phase"] == "parse"
    assert event["failure"] == failure


def test_record_correction_event_includes_correction_context(tmp_path: Path):
    ledger = tmp_path / "audit.jsonl"
    correction = AgentCorrection(
        correction_id="correction_000001",
        trigger=CorrectionTrigger.UNSUPPORTED_FINDING,
        diagnosis="Finding lacks evidence support.",
        action=CorrectionAction.DOWNGRADE_FINDING,
        result="Finding status changed to needs_review.",
        created_at=TIMESTAMP,
        related_step_id="step_verify",
    )

    record_correction_event(
        ledger,
        event_type="correction_applied",
        case_id=CASE_ID,
        run_id=RUN_ID,
        correction=correction,
        status="completed",
        output_refs={"findings": "findings.json"},
        clock=fixed_clock,
    )

    event = read_events(ledger)[0]
    assert event["event_type"] == "correction_applied"
    assert event["step_id"] == "step_verify"
    assert event["correction_id"] == "correction_000001"
    assert event["correction_action"] == "downgrade_finding"
    assert event["correction_trigger"] == "unsupported_finding"
    assert event["correction"]["result"] == "Finding status changed to needs_review."
