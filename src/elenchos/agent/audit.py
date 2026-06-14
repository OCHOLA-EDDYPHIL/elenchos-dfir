from __future__ import annotations

from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from elenchos.agent.models import AgentCorrection, AgentStep
from elenchos.audit.execution_ledger import append_event, make_event_id, read_events, utc_now

Clock = Callable[[], str]


def append_agent_audit_event(
    ledger_path: Path,
    *,
    event_type: str,
    case_id: str,
    status: str,
    clock: Clock = utc_now,
    run_id: str | None = None,
    step_id: str | None = None,
    phase: str | None = None,
    attempt: int | None = None,
    duration_ms: int = 0,
    output_refs: Mapping[str, str] | None = None,
    failure_kind: str | None = None,
    finding_id: str | None = None,
    correction_id: str | None = None,
    correction_action: str | None = None,
    correction_trigger: str | None = None,
    failure: Mapping[str, Any] | None = None,
    correction: Mapping[str, Any] | None = None,
    error: str | None = None,
    extra: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    if duration_ms < 0:
        raise ValueError("duration_ms must be >= 0")

    event: dict[str, Any] = {
        "event_id": make_event_id(len(read_events(ledger_path)) + 1),
        "timestamp_utc": clock(),
        "event_type": event_type,
        "action": event_type,
        "case_id": case_id,
        "run_id": run_id,
        "step_id": step_id,
        "phase": phase,
        "attempt": attempt,
        "status": status,
        "duration_ms": duration_ms,
        "output_refs": dict(output_refs or {}),
        "failure_kind": failure_kind,
        "finding_id": finding_id,
        "correction_id": correction_id,
        "correction_action": correction_action,
        "correction_trigger": correction_trigger,
    }
    if failure is not None:
        event["failure"] = dict(failure)
    if correction is not None:
        event["correction"] = dict(correction)
    if error is not None:
        event["error"] = error
    if extra is not None:
        event.update(dict(extra))

    append_event(ledger_path, event)
    return event


def record_agent_step_event(
    ledger_path: Path,
    *,
    event_type: str,
    case_id: str,
    run_id: str,
    step: AgentStep,
    status: str,
    clock: Clock,
    output_refs: Mapping[str, str] | None = None,
    error: str | None = None,
) -> dict[str, Any]:
    return append_agent_audit_event(
        ledger_path,
        event_type=event_type,
        case_id=case_id,
        run_id=run_id,
        step_id=step.step_id,
        phase=step.phase.value,
        attempt=step.attempt,
        status=status,
        output_refs=output_refs,
        error=error,
        clock=clock,
    )


def record_verification_failure(
    ledger_path: Path,
    *,
    case_id: str,
    run_id: str | None,
    failure: Mapping[str, Any],
    status: str,
    clock: Clock,
    output_refs: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    phase = failure.get("phase")
    step_id = failure.get("step_id")
    finding_id = failure.get("finding_id")
    failure_kind = failure.get("kind")
    return append_agent_audit_event(
        ledger_path,
        event_type="verification_failed",
        case_id=case_id,
        run_id=run_id,
        step_id=step_id if isinstance(step_id, str) else None,
        phase=phase if isinstance(phase, str) else None,
        status=status,
        output_refs=output_refs,
        failure_kind=failure_kind if isinstance(failure_kind, str) else None,
        finding_id=finding_id if isinstance(finding_id, str) else None,
        failure=failure,
        clock=clock,
    )


def record_correction_event(
    ledger_path: Path,
    *,
    event_type: str,
    case_id: str,
    run_id: str,
    correction: AgentCorrection,
    status: str,
    clock: Clock,
    output_refs: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    return append_agent_audit_event(
        ledger_path,
        event_type=event_type,
        case_id=case_id,
        run_id=run_id,
        step_id=correction.related_step_id,
        status=status,
        output_refs=output_refs,
        correction_id=correction.correction_id,
        correction_action=correction.action.value,
        correction_trigger=correction.trigger.value,
        correction=correction.to_dict(),
        clock=clock,
    )
