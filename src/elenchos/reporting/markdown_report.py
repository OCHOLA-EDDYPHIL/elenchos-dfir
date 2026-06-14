from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from elenchos.correlation.models import SubjectTimeline
from elenchos.progress import (
    ALLOWED_PROGRESS_PHASES,
    ALLOWED_PROGRESS_STATUSES,
    validate_progress_message,
)
from elenchos.validation.models import ClaimStatus, EvidenceRef, Finding


@dataclass(slots=True)
class ReportInput:
    case_id: str
    timelines: Sequence[SubjectTimeline] = ()
    findings: Sequence[Finding] = ()
    limitations: Sequence[str] = ()
    coverage_summary: Mapping[str, Any] | None = None
    progress_events: Sequence[Mapping[str, Any]] = ()

    def __post_init__(self) -> None:
        self.case_id = _validate_required_string("case_id", self.case_id)
        self.timelines = _validate_timelines(self.timelines)
        self.findings = _validate_findings(self.findings)
        self.limitations = _validate_string_sequence("limitations", self.limitations)
        if self.coverage_summary is not None and not isinstance(
            self.coverage_summary,
            Mapping,
        ):
            raise TypeError("coverage_summary must be a mapping when provided")
        self.progress_events = _validate_progress_events(self.progress_events)


@dataclass(slots=True)
class _FindingSections:
    confirmed: list[Finding]
    inferred: list[Finding]
    rejected: list[Finding]
    needs_review: list[tuple[Finding, str | None]]


def _validate_required_string(name: str, value: str | None) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} must be a non-empty string")
    return value


def _validate_string_sequence(name: str, values: Sequence[str]) -> tuple[str, ...]:
    value_tuple = tuple(values)
    if not all(isinstance(value, str) and value for value in value_tuple):
        raise ValueError(f"{name} must contain only non-empty strings")
    return value_tuple


def _validate_timelines(values: Sequence[SubjectTimeline]) -> tuple[SubjectTimeline, ...]:
    value_tuple = tuple(values)
    if not all(isinstance(value, SubjectTimeline) for value in value_tuple):
        raise TypeError("timelines must contain only SubjectTimeline instances")
    return value_tuple


def _validate_findings(values: Sequence[Finding]) -> tuple[Finding, ...]:
    value_tuple = tuple(values)
    if not all(isinstance(value, Finding) for value in value_tuple):
        raise TypeError("findings must contain only validated Finding instances")
    return value_tuple


def _validate_progress_events(values: Sequence[Mapping[str, Any]]) -> tuple[Mapping[str, str], ...]:
    value_tuple = tuple(values)
    sanitized: list[Mapping[str, str]] = []
    required = {"timestamp", "case_id", "phase", "status", "message"}
    for value in value_tuple:
        if not isinstance(value, Mapping):
            raise TypeError("progress_events must contain only mappings")
        if set(value) != required:
            raise ValueError("progress events must contain exactly required fields")
        row: dict[str, str] = {}
        for key in sorted(required):
            item = value[key]
            if not isinstance(item, str) or not item:
                raise ValueError("progress event fields must be non-empty strings")
            row[key] = item
        if row["phase"] not in ALLOWED_PROGRESS_PHASES:
            raise ValueError("progress event phase is not allowed")
        if row["status"] not in ALLOWED_PROGRESS_STATUSES:
            raise ValueError("progress event status is not allowed")
        row["message"] = validate_progress_message(row["message"])
        sanitized.append(row)
    return tuple(sanitized)


def _finding_sort_key(finding: Finding) -> tuple[str, str]:
    return (finding.finding_id, finding.claim)


def _timeline_sort_key(timeline: SubjectTimeline) -> tuple[str, bool, str]:
    return (
        timeline.subject.casefold(),
        timeline.ambiguous,
        timeline.ambiguity_reason or "",
    )


def _evidence_identity(ref: EvidenceRef) -> str:
    return ref.evidence_id or ref.artifact_id or "unknown"


def _evidence_sort_key(ref: EvidenceRef) -> tuple[str, str, str, str, str]:
    return (
        ref.evidence_id or "",
        ref.artifact_id or "",
        ref.parser,
        ref.source,
        ref.raw_record_ref or "",
    )


def _dedupe_evidence_refs(refs: Sequence[EvidenceRef]) -> list[EvidenceRef]:
    deduped: list[EvidenceRef] = []
    seen: set[str] = set()
    for ref in refs:
        key = json.dumps(ref.to_dict(), sort_keys=True, separators=(",", ":"))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(ref)
    return sorted(deduped, key=_evidence_sort_key)


def _format_evidence_ids(refs: Sequence[EvidenceRef]) -> str:
    if not refs:
        return "none"
    return ", ".join(f"`{_evidence_identity(ref)}`" for ref in refs)


def _format_inline_values(values: Sequence[str]) -> str:
    return ", ".join(f"`{value}`" for value in values)


def _format_evidence_ref(ref: EvidenceRef) -> str:
    parts = [
        f"- Evidence: `{_evidence_identity(ref)}`",
        f"parser=`{ref.parser}`",
        f"source=`{ref.source}`",
    ]
    if ref.raw_record_ref:
        parts.append(f"raw=`{ref.raw_record_ref}`")
    if ref.timestamp_field:
        parts.append(f"timestamp_field=`{ref.timestamp_field}`")
    if ref.description:
        parts.append(f"description={ref.description}")
    return " ".join(parts)


def _is_supported_confirmed(finding: Finding) -> bool:
    return (
        finding.status is ClaimStatus.CONFIRMED
        and finding.supports_final_report
        and bool(finding.evidence_refs)
    )


def _is_supported_inferred(finding: Finding) -> bool:
    return (
        finding.status is ClaimStatus.INFERRED
        and finding.supports_final_report
        and bool(finding.evidence_refs)
        and bool(finding.rationale)
    )


def _categorize_findings(findings: Sequence[Finding]) -> _FindingSections:
    confirmed: list[Finding] = []
    inferred: list[Finding] = []
    rejected: list[Finding] = []
    needs_review: list[tuple[Finding, str | None]] = []

    for finding in findings:
        if _is_supported_confirmed(finding):
            confirmed.append(finding)
            continue
        if _is_supported_inferred(finding):
            inferred.append(finding)
            continue
        if finding.status is ClaimStatus.REJECTED:
            rejected.append(finding)
            continue
        if finding.status is ClaimStatus.NEEDS_REVIEW:
            needs_review.append((finding, None))
            continue

        note = (
            f"Renderer note: unsupported {finding.status.value} finding shown for review, "
            f"not as {finding.status.value}."
        )
        needs_review.append((finding, note))

    return _FindingSections(
        confirmed=sorted(confirmed, key=_finding_sort_key),
        inferred=sorted(inferred, key=_finding_sort_key),
        rejected=sorted(rejected, key=_finding_sort_key),
        needs_review=sorted(needs_review, key=lambda item: _finding_sort_key(item[0])),
    )


def _collect_limitations(report: ReportInput, sections: _FindingSections) -> list[str]:
    limitations = set(report.limitations)
    for finding in (
        *sections.confirmed,
        *sections.inferred,
        *sections.rejected,
        *(item[0] for item in sections.needs_review),
    ):
        limitations.update(finding.limitations)
    for _finding, note in sections.needs_review:
        if note is not None:
            limitations.add(note)
    return sorted(limitations, key=lambda value: (value.casefold(), value))


def _collect_evidence_refs(
    timelines: Sequence[SubjectTimeline],
    sections: _FindingSections,
) -> list[EvidenceRef]:
    refs: list[EvidenceRef] = []
    for timeline in timelines:
        refs.extend(timeline.collect_evidence_refs())
    for finding in (
        *sections.confirmed,
        *sections.inferred,
        *sections.rejected,
        *(item[0] for item in sections.needs_review),
    ):
        refs.extend(finding.evidence_refs)
    return _dedupe_evidence_refs(refs)


def _render_case_summary(
    lines: list[str],
    report: ReportInput,
    sections: _FindingSections,
) -> None:
    lines.extend(
        [
            "## Case Summary",
            f"- Case ID: `{report.case_id}`",
            f"- Subject timelines: {len(report.timelines)}",
            f"- Confirmed findings: {len(sections.confirmed)}",
            f"- Inferred findings: {len(sections.inferred)}",
            f"- Rejected claims: {len(sections.rejected)}",
            f"- Needs-review items: {len(sections.needs_review)}",
            "",
        ]
    )


def _render_coverage_summary(lines: list[str], coverage: Mapping[str, Any] | None) -> None:
    lines.append("## Evidence Coverage")
    if not coverage:
        lines.extend(["- Coverage summary was not provided.", ""])
        return

    lines.extend(
        [
            f"- Selection profile: `{coverage.get('selection_profile', 'unknown')}`",
            f"- Max normalized events: `{coverage.get('max_normalized_events')}`",
            f"- Normalized events written: {coverage.get('normalized_events_written', 0)}",
        ]
    )

    per_artifact = coverage.get("per_artifact")
    if isinstance(per_artifact, list) and per_artifact:
        lines.append("- Parser status by artifact:")
        for item in per_artifact:
            if not isinstance(item, Mapping):
                continue
            artifact_id = item.get("artifact_id", "unknown")
            artifact_type = item.get("artifact_type", "unknown")
            status = item.get("parser_status", "unknown")
            selected = item.get("normalized_rows_selected", 0)
            bounded = item.get("bounded", False)
            lines.append(
                f"  - `{artifact_id}` type=`{artifact_type}` status=`{status}` "
                f"selected={selected} bounded={str(bool(bounded)).lower()}"
            )

    notes = coverage.get("selection_notes")
    if isinstance(notes, Mapping) and notes:
        rendered = ", ".join(
            f"{key}={value}" for key, value in sorted(notes.items()) if isinstance(value, int)
        )
        if rendered:
            lines.append(f"- Selection notes: {rendered}")
    lines.append("")


def _render_execution_progress(
    lines: list[str],
    progress_events: Sequence[Mapping[str, str]],
) -> None:
    if not progress_events:
        return
    lines.append("## Execution Progress")
    for event in progress_events:
        lines.append(
            f"- Phase: `{event['phase']}`; status=`{event['status']}`; "
            f"timestamp=`{event['timestamp']}`; {event['message']}"
        )
    lines.append("")


def _render_subject_timelines(lines: list[str], timelines: Sequence[SubjectTimeline]) -> None:
    lines.append("## Subject Timeline")
    if not timelines:
        lines.extend(["- No subject timelines.", ""])
        return

    for timeline in sorted(timelines, key=_timeline_sort_key):
        lines.append(f"- Subject: `{timeline.subject}`")
        if timeline.ambiguous:
            reason = timeline.ambiguity_reason or "Ambiguity reason was not provided."
            lines.append(f"  - Ambiguous: yes; reason: {reason}")
        else:
            lines.append("  - Ambiguous: no")
        if not timeline.events:
            lines.append("  - Events: none")
            continue
        for event in timeline.events:
            timestamp = event.timestamp or "unknown"
            details = json.dumps(event.details, sort_keys=True, separators=(",", ":"))
            event_line = (
                f"  - `{timestamp}` {event.event_type.value} source=`{event.source}` "
                f"evidence={_format_evidence_ids(event.evidence_refs)}"
            )
            if details != "{}":
                event_line += f" details=`{details}`"
            if event.ambiguous:
                reason = event.ambiguity_reason or "Ambiguity reason was not provided."
                event_line += f" ambiguous=yes reason={reason}"
            lines.append(event_line)
    lines.append("")


def _render_finding(lines: list[str], finding: Finding, note: str | None = None) -> None:
    lines.append(f"- `{finding.finding_id}` {finding.claim}")
    lines.append(
        "  - "
        f"Status: `{finding.status.value}`; confidence=`{finding.confidence.value}`; "
        f"kind=`{finding.kind.value}`"
    )
    if note is not None:
        lines.append(f"  - {note}")
    if finding.rationale:
        lines.append(f"  - Rationale: {finding.rationale}")
    if finding.evidence_refs:
        for ref in finding.evidence_refs:
            lines.append(f"  {_format_evidence_ref(ref)}")
    if finding.audit_event_refs:
        lines.append(f"  - Audit events: {_format_inline_values(finding.audit_event_refs)}")
    if finding.raw_record_refs:
        lines.append(f"  - Raw records: {_format_inline_values(finding.raw_record_refs)}")
    if finding.artifact_hashes:
        lines.append(f"  - Artifact hashes: {_format_inline_values(finding.artifact_hashes)}")
    if finding.limitations:
        lines.append(f"  - Limitations: {'; '.join(finding.limitations)}")


def _render_finding_list(
    lines: list[str],
    heading: str,
    findings: Sequence[Finding],
    empty_text: str,
) -> None:
    lines.append(heading)
    if not findings:
        lines.extend([f"- {empty_text}", ""])
        return
    for finding in findings:
        _render_finding(lines, finding)
    lines.append("")


def _render_needs_review(
    lines: list[str],
    findings: Sequence[tuple[Finding, str | None]],
) -> None:
    lines.append("## Needs Review")
    if not findings:
        lines.extend(["- No needs-review items.", ""])
        return
    for finding, note in findings:
        _render_finding(lines, finding, note)
    lines.append("")


def _render_limitations(lines: list[str], limitations: Sequence[str]) -> None:
    lines.append("## Limitations")
    if not limitations:
        lines.extend(["- No additional limitations.", ""])
        return
    for limitation in limitations:
        lines.append(f"- {limitation}")
    lines.append("")


def _render_evidence_references(lines: list[str], refs: Sequence[EvidenceRef]) -> None:
    lines.append("## Evidence References")
    if not refs:
        lines.extend(["- No evidence references.", ""])
        return
    for ref in refs:
        lines.append(_format_evidence_ref(ref))
    lines.append("")


def _render_report(report: ReportInput) -> str:
    sections = _categorize_findings(report.findings)
    timelines = tuple(sorted(report.timelines, key=_timeline_sort_key))
    limitations = _collect_limitations(report, sections)
    evidence_refs = _collect_evidence_refs(timelines, sections)

    lines = ["# Case Report", ""]
    _render_case_summary(lines, report, sections)
    _render_coverage_summary(lines, report.coverage_summary)
    _render_execution_progress(lines, report.progress_events)
    _render_subject_timelines(lines, timelines)
    _render_finding_list(
        lines,
        "## Confirmed Findings",
        sections.confirmed,
        "No confirmed findings.",
    )
    _render_finding_list(
        lines,
        "## Inferred Findings",
        sections.inferred,
        "No inferred findings.",
    )
    _render_finding_list(
        lines,
        "## Rejected Claims",
        sections.rejected,
        "No rejected claims.",
    )
    _render_needs_review(lines, sections.needs_review)
    _render_limitations(lines, limitations)
    _render_evidence_references(lines, evidence_refs)
    return "\n".join(lines).rstrip() + "\n"


def render_markdown_report(
    *,
    case_id: str,
    timelines: Sequence[SubjectTimeline],
    findings: Sequence[Finding],
    limitations: Sequence[str] = (),
    coverage_summary: Mapping[str, Any] | None = None,
    progress_events: Sequence[Mapping[str, Any]] = (),
) -> str:
    report = ReportInput(
        case_id=case_id,
        timelines=timelines,
        findings=findings,
        limitations=limitations,
        coverage_summary=coverage_summary,
        progress_events=progress_events,
    )
    return _render_report(report)


def generate_markdown_report(*args: Any, **kwargs: Any) -> str:
    if len(args) == 1 and isinstance(args[0], ReportInput) and not kwargs:
        return _render_report(args[0])
    if args:
        raise TypeError("generate_markdown_report accepts a ReportInput or keyword arguments")
    return render_markdown_report(**kwargs)
