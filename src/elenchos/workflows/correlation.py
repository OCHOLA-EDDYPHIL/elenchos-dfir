from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from elenchos.audit.execution_ledger import append_event, make_event_id, utc_now
from elenchos.correlation.event_schema import ParserEvent, RawRecordRef
from elenchos.correlation.models import TimelineEvent, TimelineEventType
from elenchos.correlation.timeline import build_subject_timelines
from elenchos.policy.paths import is_relative_to
from elenchos.reporting.markdown_report import render_markdown_report
from elenchos.validation.claims import (
    ClaimValidationResult,
    candidates_from_subject_timelines,
    validate_claim_candidates,
)
from elenchos.validation.models import EvidenceRef

Clock = Callable[[], str]

GENERATED_OUTPUT_PARTS = {"runs", "outputs", "analysis"}
WORKFLOW_ACTIONS = (
    "workflow_started",
    "input_loaded",
    "timelines_built",
    "claims_validated",
    "report_rendered",
    "workflow_completed",
)


@dataclass(slots=True)
class CorrelationWorkflowResult:
    case_id: str
    output_dir: Path
    timelines_path: Path
    findings_path: Path
    report_path: Path | None
    audit_path: Path
    event_count: int
    timeline_count: int
    finding_count: int

    def to_dict(self) -> dict[str, object]:
        return {
            "case_id": self.case_id,
            "output_dir": str(self.output_dir),
            "timelines_path": str(self.timelines_path),
            "findings_path": str(self.findings_path),
            "report_path": str(self.report_path) if self.report_path is not None else None,
            "audit_path": str(self.audit_path),
            "event_count": self.event_count,
            "timeline_count": self.timeline_count,
            "finding_count": self.finding_count,
        }


def _require_non_empty_string(name: str, value: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} must be a non-empty string")
    return value


def _is_generated_output_path(path: Path) -> bool:
    parts = tuple(part.casefold() for part in path.parts)
    if any(part in GENERATED_OUTPUT_PARTS for part in parts):
        return True
    return any(
        left == "reports" and right == "generated"
        for left, right in zip(parts, parts[1:], strict=False)
    )


def _validate_input_path(input_path: Path) -> Path:
    resolved = input_path.resolve()
    if not resolved.exists():
        raise ValueError(f"normalized input JSON does not exist: {input_path}")
    if resolved.is_dir():
        raise ValueError(f"normalized input JSON path is a directory: {input_path}")
    return resolved


def _validate_output_dir(output_dir: Path, input_path: Path) -> Path:
    resolved = output_dir.resolve()
    cwd = Path.cwd().resolve()
    if resolved == input_path.resolve():
        raise ValueError("output_dir must not be the input file")
    if resolved == cwd:
        raise ValueError("output_dir must not be the repository root")
    if not _is_generated_output_path(resolved):
        raise ValueError(
            "output_dir must be under an ignored generated output path such as "
            "runs/, outputs/, analysis/, or reports/generated/"
        )
    return resolved


def _resolve_output_path(output_dir: Path, name: str) -> Path:
    path = (output_dir / name).resolve()
    if not is_relative_to(path, output_dir):
        raise ValueError(f"output path '{path}' must be under output_dir '{output_dir}'")
    return path


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _load_json_object(input_path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(input_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"malformed normalized input JSON: {exc.msg}") from exc
    if not isinstance(payload, dict):
        raise ValueError("normalized input JSON must be an object")
    return payload


def _event_rows(payload: dict[str, Any]) -> list[dict[str, Any]]:
    rows = payload.get("events", payload.get("normalized_events"))
    if not isinstance(rows, list):
        raise ValueError("normalized input JSON must contain an events list")
    if not all(isinstance(row, dict) for row in rows):
        raise ValueError("normalized input events must contain only objects")
    return [dict(row) for row in rows]


def _validate_case_id(case_id: str, payload: dict[str, Any]) -> None:
    input_case_id = payload.get("case_id")
    if input_case_id is not None and input_case_id != case_id:
        raise ValueError(
            f"input case_id '{input_case_id}' does not match requested case_id '{case_id}'"
        )


def _raw_record_ref_to_string(raw_record_ref: RawRecordRef | None) -> str | None:
    if raw_record_ref is None:
        return None
    if raw_record_ref.source_path and raw_record_ref.row_number is not None:
        return f"csv:{Path(raw_record_ref.source_path).name}:{raw_record_ref.row_number}"
    if raw_record_ref.record_id:
        return raw_record_ref.record_id
    if raw_record_ref.source_path:
        return f"file:{Path(raw_record_ref.source_path).name}"
    if raw_record_ref.byte_offset is not None:
        return f"byte:{raw_record_ref.byte_offset}"
    return None


def _parser_event_type(event: ParserEvent) -> TimelineEventType:
    if event.event_type == "file_created":
        return TimelineEventType.DROP
    if event.event_type == "registry_run_key":
        return TimelineEventType.PERSISTENCE
    if event.event_type == "amcache_execution":
        return TimelineEventType.EXECUTION
    return TimelineEventType.OBSERVATION


def _path_from_parser_event(event: ParserEvent) -> str | None:
    if event.path:
        return event.path
    if event.event_type == "registry_run_key" and event.value_data:
        return event.value_data
    return None


def _basename_from_path(path: str | None) -> str | None:
    if path is None:
        return None
    normalized = path.replace("\\", "/").rstrip("/")
    if not normalized:
        return None
    return normalized.rsplit("/", 1)[-1] or None


def _details_from_parser_event(event: ParserEvent) -> dict[str, str | int | float | bool | None]:
    details: dict[str, str | int | float | bool | None] = {
        "parser_event_id": event.event_id,
        "parser_event_type": event.event_type,
        "artifact_id": event.artifact_id,
        "artifact_type": event.artifact_type,
        "status": event.status,
        "confidence": event.confidence,
    }
    optional_values = {
        "timestamp_description": event.timestamp_description,
        "key_path": event.key_path,
        "value_name": event.value_name,
        "value_data": event.value_data,
        "sha256": event.sha256,
    }
    details.update({key: value for key, value in optional_values.items() if value is not None})
    for key, value in event.metadata.items():
        details[f"metadata.{key}"] = value
    return details


def _evidence_refs_from_parser_event(event: ParserEvent) -> list[EvidenceRef]:
    raw_record_ref = (
        _raw_record_ref_to_string(event.raw_record_ref)
        if isinstance(event.raw_record_ref, RawRecordRef)
        else None
    )
    refs: list[EvidenceRef] = []
    for ref in event.evidence_refs:
        refs.append(
            EvidenceRef(
                artifact_id=ref,
                parser=event.parser_name,
                source=event.artifact_type,
                raw_record_ref=raw_record_ref,
                timestamp_field=event.timestamp_description,
                description=f"Normalized parser event {event.event_id}.",
            )
        )
    return refs


def _timeline_event_from_parser_event(event: ParserEvent) -> TimelineEvent:
    path = _path_from_parser_event(event)
    subject = path or event.subject or event.value_name or event.key_path or event.event_id
    timestamp = event.timestamp_utc if isinstance(event.timestamp_utc, str) else None
    return TimelineEvent(
        event_type=_parser_event_type(event),
        timestamp=timestamp,
        subject=subject,
        source=event.parser_name,
        details=_details_from_parser_event(event),
        evidence_refs=_evidence_refs_from_parser_event(event),
        path=path,
        basename=_basename_from_path(path) or event.subject,
    )


def _timeline_event_from_row(row: dict[str, Any], index: int) -> TimelineEvent:
    try:
        event_type = row.get("event_type")
        if event_type in {item.value for item in TimelineEventType}:
            return TimelineEvent.from_dict(row)
        return _timeline_event_from_parser_event(ParserEvent.from_dict(row))
    except Exception as exc:
        raise ValueError(f"invalid normalized event at index {index}: {exc}") from exc


def _timeline_events_from_payload(case_id: str, payload: dict[str, Any]) -> list[TimelineEvent]:
    _validate_case_id(case_id, payload)
    return [_timeline_event_from_row(row, index) for index, row in enumerate(_event_rows(payload))]


def _audit_path_value(path: Path) -> str:
    resolved = path.resolve()
    cwd = Path.cwd().resolve()
    if is_relative_to(resolved, cwd):
        return resolved.relative_to(cwd).as_posix()
    return str(resolved)


def _append_workflow_audit(
    audit_path: Path,
    *,
    counter: int,
    action: str,
    case_id: str,
    timestamp_utc: str,
    input_path: Path,
    output_dir: Path,
    output_path: Path | None = None,
    counts: dict[str, int] | None = None,
) -> None:
    if action not in WORKFLOW_ACTIONS:
        raise ValueError(f"unsupported workflow audit action: {action}")
    event: dict[str, object] = {
        "event_id": make_event_id(counter),
        "timestamp_utc": timestamp_utc,
        "action": action,
        "case_id": case_id,
        "input_path": _audit_path_value(input_path),
        "output_dir": _audit_path_value(output_dir),
    }
    if output_path is not None:
        event["output_path"] = _audit_path_value(output_path)
    if counts is not None:
        event["counts"] = dict(counts)
    append_event(audit_path, event)


def run_correlation_workflow(
    *,
    case_id: str,
    input_path: Path,
    output_dir: Path,
    include_report: bool = True,
    clock: Clock = utc_now,
) -> CorrelationWorkflowResult:
    case_id = _require_non_empty_string("case_id", case_id)
    resolved_input = _validate_input_path(input_path)
    resolved_output_dir = _validate_output_dir(output_dir, resolved_input)
    resolved_output_dir.mkdir(parents=True, exist_ok=True)

    timelines_path = _resolve_output_path(resolved_output_dir, "subject_timelines.json")
    findings_path = _resolve_output_path(resolved_output_dir, "findings.json")
    report_path = _resolve_output_path(resolved_output_dir, "report.md") if include_report else None
    audit_path = _resolve_output_path(resolved_output_dir, "audit.jsonl")
    if audit_path.exists():
        audit_path.unlink()

    audit_counter = 1
    _append_workflow_audit(
        audit_path,
        counter=audit_counter,
        action="workflow_started",
        case_id=case_id,
        timestamp_utc=clock(),
        input_path=resolved_input,
        output_dir=resolved_output_dir,
    )

    payload = _load_json_object(resolved_input)
    events = _timeline_events_from_payload(case_id, payload)
    audit_counter += 1
    _append_workflow_audit(
        audit_path,
        counter=audit_counter,
        action="input_loaded",
        case_id=case_id,
        timestamp_utc=clock(),
        input_path=resolved_input,
        output_dir=resolved_output_dir,
        counts={"event_count": len(events)},
    )

    timelines = build_subject_timelines(events)
    _write_json(
        timelines_path,
        {
            "case_id": case_id,
            "timeline_count": len(timelines),
            "timelines": [timeline.to_dict() for timeline in timelines],
        },
    )
    audit_counter += 1
    _append_workflow_audit(
        audit_path,
        counter=audit_counter,
        action="timelines_built",
        case_id=case_id,
        timestamp_utc=clock(),
        input_path=resolved_input,
        output_dir=resolved_output_dir,
        output_path=timelines_path,
        counts={"timeline_count": len(timelines)},
    )

    candidates = candidates_from_subject_timelines(timelines)
    validation_results: list[ClaimValidationResult] = validate_claim_candidates(candidates)
    findings = [result.finding for result in validation_results]
    _write_json(
        findings_path,
        {
            "case_id": case_id,
            "finding_count": len(findings),
            "findings": [finding.to_dict() for finding in findings],
            "validation_results": [result.to_dict() for result in validation_results],
        },
    )
    audit_counter += 1
    _append_workflow_audit(
        audit_path,
        counter=audit_counter,
        action="claims_validated",
        case_id=case_id,
        timestamp_utc=clock(),
        input_path=resolved_input,
        output_dir=resolved_output_dir,
        output_path=findings_path,
        counts={"finding_count": len(findings)},
    )

    if report_path is not None:
        report = render_markdown_report(
            case_id=case_id,
            timelines=timelines,
            findings=findings,
            limitations=["Generated from existing normalized parser output."],
        )
        report_path.write_text(report, encoding="utf-8")
        audit_counter += 1
        _append_workflow_audit(
            audit_path,
            counter=audit_counter,
            action="report_rendered",
            case_id=case_id,
            timestamp_utc=clock(),
            input_path=resolved_input,
            output_dir=resolved_output_dir,
            output_path=report_path,
            counts={"finding_count": len(findings), "timeline_count": len(timelines)},
        )

    audit_counter += 1
    _append_workflow_audit(
        audit_path,
        counter=audit_counter,
        action="workflow_completed",
        case_id=case_id,
        timestamp_utc=clock(),
        input_path=resolved_input,
        output_dir=resolved_output_dir,
        counts={
            "event_count": len(events),
            "timeline_count": len(timelines),
            "finding_count": len(findings),
        },
    )

    return CorrelationWorkflowResult(
        case_id=case_id,
        output_dir=resolved_output_dir,
        timelines_path=timelines_path,
        findings_path=findings_path,
        report_path=report_path,
        audit_path=audit_path,
        event_count=len(events),
        timeline_count=len(timelines),
        finding_count=len(findings),
    )


def load_normalized_timeline_events(*, case_id: str, input_path: Path) -> list[TimelineEvent]:
    resolved_input = _validate_input_path(input_path)
    payload = _load_json_object(resolved_input)
    return _timeline_events_from_payload(case_id, payload)
