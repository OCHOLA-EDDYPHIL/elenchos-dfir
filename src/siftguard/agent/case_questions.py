from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from siftguard.agent.case_manifest_adapter import AdaptedCaseManifest
from siftguard.agent.casebook import Casebook, CasebookAnalysisWindow, CasebookQuestion

QUESTION_STATUSES = {"confirmed", "inferred", "needs_review", "not_assessed", "rejected"}
UNSUPPORTED_EXPECTED_STATUSES = {"not_assessed"}
GENERIC_CANDIDATE_MARKERS = (
    "project",
    "confidential",
    "proposal",
    "prototype",
    "engineering",
    "research",
    "design",
    "archive",
    "document",
)
REGISTRY_USER_ACTIVITY_TYPES = {
    "userassist",
    "recentdocs",
    "opensavepidlmru",
    "lastvisitedpidlmru",
    "typedpaths",
}


@dataclass(frozen=True, slots=True)
class EventEvidence:
    event_id: str
    artifact_id: str
    evidence_class: str
    evidence_ref: dict[str, Any]
    provenance: dict[str, Any]
    timestamp_utc: str | None
    in_analysis_window: bool
    subject: str | None
    path: str | None
    event_type: str | None


def _utc_datetime(value: str | None) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    text = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _window_bounds(window: CasebookAnalysisWindow) -> tuple[datetime, datetime]:
    start = _utc_datetime(window.start)
    end = _utc_datetime(window.end)
    if start is None or end is None:
        raise ValueError(f"invalid analysis window timestamps: {window.id}")
    return start, end


def _in_any_window(value: str | None, windows: tuple[CasebookAnalysisWindow, ...]) -> bool:
    timestamp = _utc_datetime(value)
    if timestamp is None:
        return False
    return any(start <= timestamp <= end for start, end in map(_window_bounds, windows))


def _raw_record_ref(row: dict[str, Any]) -> str | None:
    raw = row.get("raw_record_ref")
    if isinstance(raw, dict):
        source_path = raw.get("source_path")
        row_number = raw.get("row_number")
        record_id = raw.get("record_id")
        byte_offset = raw.get("byte_offset")
        if isinstance(source_path, str) and isinstance(row_number, int):
            return f"csv:{Path(source_path).name}:{row_number}"
        if isinstance(record_id, str) and record_id:
            return record_id
        if isinstance(source_path, str) and source_path:
            return f"file:{Path(source_path).name}"
        if isinstance(byte_offset, int):
            return f"byte:{byte_offset}"
    if isinstance(raw, str) and raw:
        return raw
    return None


def _artifact_type_from_event(row: dict[str, Any]) -> str:
    value = row.get("artifact_type")
    return value if isinstance(value, str) else "unknown"


def _parser_from_event(row: dict[str, Any]) -> str:
    value = row.get("parser_name")
    return value if isinstance(value, str) else "unknown"


def _event_type(row: dict[str, Any]) -> str:
    value = row.get("event_type")
    return value if isinstance(value, str) else "unknown"


def _evidence_class_from_event(row: dict[str, Any]) -> str:
    artifact_type = _artifact_type_from_event(row).casefold()
    parser = _parser_from_event(row).casefold()
    event_type = _event_type(row)
    metadata = row.get("metadata", {})
    artifact_family = ""
    if isinstance(metadata, dict):
        value = metadata.get("artifact_family")
        artifact_family = value if isinstance(value, str) else ""
    if (
        row.get("artifact_family") == "registry_user_activity"
        or artifact_family == "registry_user_activity"
        or artifact_type in REGISTRY_USER_ACTIVITY_TYPES
    ):
        if artifact_type in REGISTRY_USER_ACTIVITY_TYPES:
            return artifact_type
        return "registry_user_activity"
    if artifact_type == "amcache" or parser == "amcacheparser" or event_type == "amcache_execution":
        return "amcache"
    if artifact_type in {"registry", "registry_hive"} or parser == "recmd":
        return "registry_run_keys"
    if artifact_type == "mft" or parser == "mftecmd":
        return "mft"
    return artifact_type or "unknown"


def _evidence_class_from_ref(ref: dict[str, Any]) -> str:
    parser = str(ref.get("parser", "")).casefold()
    source = str(ref.get("source", "")).casefold()
    if source in REGISTRY_USER_ACTIVITY_TYPES or source == "registry_user_activity":
        return source
    if parser == "amcacheparser" or "amcache" in source:
        return "amcache"
    if parser == "recmd" or "registry" in source or "ntuser" in source or "software" in source:
        return "registry_run_keys"
    if parser == "mftecmd" or "mft" in source:
        return "mft"
    return source or "unknown"


def _source_by_id(adapted: AdaptedCaseManifest) -> dict[str, dict[str, Any]]:
    return {source["source_id"]: source for source in adapted.sources}


def _artifact_source_by_id(adapted: AdaptedCaseManifest) -> dict[str, dict[str, Any]]:
    return {
        artifact["artifact_id"]: artifact
        for artifact in adapted.prepared_artifacts
        if isinstance(artifact.get("artifact_id"), str)
    }


def _provenance_for_artifact(
    artifact_id: str,
    *,
    adapted: AdaptedCaseManifest,
) -> dict[str, Any]:
    artifact_by_id = _artifact_source_by_id(adapted)
    source_by_id = _source_by_id(adapted)
    artifact = artifact_by_id.get(artifact_id, {})
    source_id = artifact.get("source_id")
    source = source_by_id.get(source_id, {}) if isinstance(source_id, str) else {}
    return {
        "artifact_id": artifact_id,
        "artifact_type": artifact.get("artifact_type"),
        "source_id": source_id,
        "source_role": artifact.get("source_role"),
        "source_display_name": source.get("display_name"),
        "source_ref": source.get("source_ref") or source.get("sanitized_path"),
    }


def _event_evidence(
    row: dict[str, Any],
    *,
    adapted: AdaptedCaseManifest,
    casebook: Casebook,
) -> EventEvidence:
    artifact_id = row.get("artifact_id")
    if not isinstance(artifact_id, str) or not artifact_id:
        refs = row.get("evidence_refs")
        artifact_id = refs[0] if isinstance(refs, list) and refs else "unknown"
    event_id = row.get("event_id")
    evidence_id = event_id if isinstance(event_id, str) and event_id else artifact_id
    timestamp_utc = row.get("timestamp_utc")
    timestamp = timestamp_utc if isinstance(timestamp_utc, str) else None
    subject = row.get("subject")
    path = row.get("path")
    evidence_ref = {
        "evidence_id": evidence_id,
        "artifact_id": artifact_id,
        "parser": _parser_from_event(row),
        "source": _artifact_type_from_event(row),
        "raw_record_ref": _raw_record_ref(row),
        "timestamp_field": row.get("timestamp_description"),
        "description": f"Normalized parser event {evidence_id}.",
        "event_id": evidence_id,
        "event_type": _event_type(row),
        "timestamp_utc": timestamp,
        "path": path if isinstance(path, str) else None,
    }
    return EventEvidence(
        event_id=evidence_id,
        artifact_id=artifact_id,
        evidence_class=_evidence_class_from_event(row),
        evidence_ref=evidence_ref,
        provenance=_provenance_for_artifact(artifact_id, adapted=adapted),
        timestamp_utc=timestamp,
        in_analysis_window=_in_any_window(timestamp, casebook.analysis_windows),
        subject=subject if isinstance(subject, str) else None,
        path=path if isinstance(path, str) else None,
        event_type=_event_type(row),
    )


def _dedupe_dicts(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    output: list[dict[str, Any]] = []
    for row in rows:
        key = json.dumps(row, sort_keys=True, separators=(",", ":"))
        if key in seen:
            continue
        seen.add(key)
        output.append(row)
    return sorted(output, key=lambda item: json.dumps(item, sort_keys=True))


def _finding_question_ids(finding: dict[str, Any]) -> set[str]:
    value = finding.get("case_question_ids", [])
    if not isinstance(value, list):
        return set()
    return {item for item in value if isinstance(item, str) and item}


def _finding_evidence_classes(finding: dict[str, Any]) -> set[str]:
    refs = finding.get("evidence_refs", [])
    if not isinstance(refs, list):
        return set()
    return {
        _evidence_class_from_ref(ref)
        for ref in refs
        if isinstance(ref, dict)
    }


def _linked_findings(
    question: CasebookQuestion,
    findings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    question_classes = set(question.evidence_classes)
    linked: list[dict[str, Any]] = []
    for finding in findings:
        if question.id in _finding_question_ids(finding):
            linked.append(finding)
            continue
        finding_classes = _finding_evidence_classes(finding)
        if question_classes and (
            question_classes & finding_classes
            or (
                "registry_user_activity" in question_classes
                and finding_classes & REGISTRY_USER_ACTIVITY_TYPES
            )
        ):
            linked.append(finding)
    return sorted(linked, key=lambda item: str(item.get("finding_id", "")))


def _is_profile_candidate(evidence: EventEvidence, casebook: Casebook) -> bool:
    haystack = " ".join(
        value for value in (evidence.path, evidence.subject) if isinstance(value, str)
    ).casefold()
    if not haystack:
        return True
    profile = casebook.triage_profile
    markers = tuple(marker.casefold() for marker in profile.keywords) + GENERIC_CANDIDATE_MARKERS
    if any(marker in haystack for marker in markers):
        return True
    if evidence.path is not None:
        path = evidence.path.replace("\\", "/").casefold()
        if any(marker.casefold() in path for marker in profile.sensitive_paths):
            return True
        suffix = Path(path).suffix.casefold()
        if suffix and suffix in profile.file_extensions:
            return True
    return False


def _events_for_question(
    question: CasebookQuestion,
    events: list[EventEvidence],
    *,
    casebook: Casebook,
) -> list[EventEvidence]:
    wanted = set(question.evidence_classes)
    matched = [
        event
        for event in events
        if (
            not wanted
            or event.evidence_class in wanted
            or (
                "registry_user_activity" in wanted
                and event.evidence_class in REGISTRY_USER_ACTIVITY_TYPES
            )
        )
    ]
    if question.status_policy == "case_window_activity":
        window_events = [event for event in matched if event.in_analysis_window]
        return window_events or matched
    if question.status_policy == "file_candidate_triage":
        project_events = [event for event in matched if _is_profile_candidate(event, casebook)]
        return project_events or matched[:10]
    return matched


def _same_source_provenance(events: list[EventEvidence]) -> bool:
    source_ids = {
        event.provenance.get("source_id")
        for event in events
        if isinstance(event.provenance.get("source_id"), str)
    }
    return len(source_ids) == 1 and bool(source_ids)


def _has_raw_record_support(events: list[EventEvidence]) -> bool:
    return bool(events) and all(event.evidence_ref.get("raw_record_ref") for event in events)


def _can_confirm(question: CasebookQuestion, events: list[EventEvidence]) -> bool:
    if question.expected_status in UNSUPPORTED_EXPECTED_STATUSES:
        return False
    if question.status_policy in {"file_candidate_triage", "registry_persistence"}:
        return False
    classes = {event.evidence_class for event in events}
    return (
        len(events) >= 2
        and len(classes) >= 2
        and any(event.in_analysis_window for event in events)
        and _same_source_provenance(events)
        and _has_raw_record_support(events)
    )


def _can_infer(
    question: CasebookQuestion,
    events: list[EventEvidence],
    linked_findings: list[dict[str, Any]],
) -> bool:
    if question.expected_status in UNSUPPORTED_EXPECTED_STATUSES:
        return False
    classes = {event.evidence_class for event in events}
    if len(events) >= 2 and len(classes) >= 2:
        return True
    return any(finding.get("status") == "inferred" for finding in linked_findings)


def _question_status(
    question: CasebookQuestion,
    events: list[EventEvidence],
    linked_findings: list[dict[str, Any]],
) -> tuple[str, str]:
    if (
        question.expected_status in UNSUPPORTED_EXPECTED_STATUSES
        or question.supported_by_scope is False
    ):
        reason = question.gap_reason or "Question requires unsupported artifact classes."
        return "not_assessed", reason
    if any(finding.get("status") == "rejected" for finding in linked_findings):
        return "rejected", "Linked validated finding rejected or contradicted this question."
    if _can_confirm(question, events):
        return (
            "confirmed",
            "Multiple independent supported artifacts align with the case window "
            "and same-source provenance.",
        )
    if _can_infer(question, events, linked_findings):
        return (
            "inferred",
            "Multiple independent supported evidence references point to related activity.",
        )
    if events or linked_findings:
        return (
            "needs_review",
            "Relevant evidence exists but support is incomplete or context-dependent.",
        )
    return (
        "needs_review",
        "No selected supported evidence answered this question; manual review remains required.",
    )


def _summary_for_question(
    *,
    status: str,
    question: CasebookQuestion,
    events: list[EventEvidence],
) -> str:
    if status == "not_assessed":
        return question.gap_reason or "Not assessed under the current final artifact scope."
    if not events:
        return "No selected normalized events directly answered this question."
    classes = ", ".join(sorted({event.evidence_class for event in events}))
    window_count = sum(1 for event in events if event.in_analysis_window)
    return (
        f"Reviewed {len(events)} selected event(s) across {classes}; "
        f"{window_count} event(s) fell inside the case analysis window."
    )


def _gaps_for_question(
    *,
    status: str,
    question: CasebookQuestion,
    events: list[EventEvidence],
) -> list[str]:
    if status == "not_assessed":
        return [question.gap_reason or "Unsupported by current final artifact scope."]
    gaps: list[str] = []
    if not events:
        gaps.append("No selected normalized events matched this question.")
    if status == "needs_review":
        gaps.append("Current evidence does not meet inferred or confirmed thresholds.")
    return gaps


def _next_steps_for_question(
    *,
    status: str,
    question: CasebookQuestion,
) -> list[str]:
    if status == "not_assessed":
        return [
            question.gap_reason
            or "Collect and parse the unsupported artifact classes needed for this question."
        ]
    if status == "needs_review":
        return [
            "Review linked events and full source artifacts manually before drawing conclusions."
        ]
    if status == "inferred":
        return ["Validate inferred relationship against source artifacts and case context."]
    if status == "confirmed":
        return ["Preserve supporting artifacts and document analyst review of the confirmed scope."]
    return ["Review rejected claim rationale and contradicting evidence."]


def _question_record(
    *,
    question: CasebookQuestion,
    events: list[EventEvidence],
    linked_findings: list[dict[str, Any]],
) -> dict[str, Any]:
    status, reason = _question_status(question, events, linked_findings)
    linked_finding_ids = sorted(
        finding["finding_id"]
        for finding in linked_findings
        if isinstance(finding.get("finding_id"), str)
    )
    linked_evidence_refs = _dedupe_dicts([event.evidence_ref for event in events])
    provenance_refs = _dedupe_dicts([event.provenance for event in events])
    return {
        "question_id": question.id,
        "question": question.question,
        "status": status,
        "supported_by_current_scope": question.supported_by_scope is not False,
        "evidence_classes_checked": list(question.evidence_classes),
        "linked_finding_ids": linked_finding_ids,
        "linked_evidence_refs": linked_evidence_refs,
        "source_provenance_refs": provenance_refs,
        "summary": _summary_for_question(status=status, question=question, events=events),
        "reason": reason,
        "gaps": _gaps_for_question(status=status, question=question, events=events),
        "recommended_next_manual_review": _next_steps_for_question(
            status=status,
            question=question,
        ),
    }


def evaluate_case_questions(
    *,
    casebook: Casebook,
    adapted: AdaptedCaseManifest,
    normalized_events: list[dict[str, Any]],
    findings: list[dict[str, Any]],
    created_at: str,
) -> dict[str, Any]:
    event_evidence = [
        _event_evidence(row, adapted=adapted, casebook=casebook)
        for row in normalized_events
        if isinstance(row, dict)
    ]
    questions: list[dict[str, Any]] = []
    for question in casebook.case_questions:
        events = _events_for_question(question, event_evidence, casebook=casebook)
        linked = _linked_findings(question, findings)
        questions.append(_question_record(question=question, events=events, linked_findings=linked))
    status_counts: dict[str, int] = {status: 0 for status in sorted(QUESTION_STATUSES)}
    for record in questions:
        status = record["status"]
        status_counts[status] = status_counts.get(status, 0) + 1
    return {
        "case_id": casebook.case_id,
        "casebook_id": casebook.case_id,
        "created_at": created_at,
        "questions": questions,
        "status_counts": status_counts,
    }


def question_mappings_for_findings(
    *,
    case_questions: dict[str, Any],
    findings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    mappings: list[dict[str, Any]] = []
    questions = case_questions.get("questions", [])
    if not isinstance(questions, list):
        return mappings
    for finding in findings:
        finding_id = finding.get("finding_id")
        if not isinstance(finding_id, str):
            continue
        linked_questions = [
            question
            for question in questions
            if isinstance(question, dict) and finding_id in question.get("linked_finding_ids", [])
        ]
        if not linked_questions:
            continue
        question_ids = sorted(str(question["question_id"]) for question in linked_questions)
        finding["case_question_ids"] = question_ids
        mappings.append(
            {
                "finding_id": finding_id,
                "case_question_ids": question_ids,
            }
        )
    return mappings


def render_case_question_report(
    *,
    case_id: str,
    case_questions: dict[str, Any],
    findings: list[dict[str, Any]],
    coverage_summary: dict[str, Any],
    adapted: AdaptedCaseManifest,
    user_activity_summary: dict[str, Any] | None = None,
) -> str:
    questions = [
        question
        for question in case_questions.get("questions", [])
        if isinstance(question, dict)
    ]
    supported = [q for q in questions if q.get("status") in {"confirmed", "inferred"}]
    needs_review = [q for q in questions if q.get("status") == "needs_review"]
    not_assessed = [q for q in questions if q.get("status") == "not_assessed"]
    lines = ["# Case Report", ""]
    lines.extend(["## Case Questions Summary"])
    if not questions:
        lines.append("- No case questions were available.")
    for question in questions:
        lines.append(
            f"- `{question.get('question_id')}` status=`{question.get('status')}`: "
            f"{question.get('summary')}"
        )
    lines.append("")
    lines.append("## Supported Findings")
    if not supported:
        lines.append("- No inferred or confirmed case-question findings.")
    for question in supported:
        linked = ", ".join(f"`{item}`" for item in question.get("linked_finding_ids", []))
        lines.append(
            f"- `{question.get('question_id')}` {question.get('question')} "
            f"status=`{question.get('status')}` linked_findings={linked or 'none'}"
        )
        lines.append(f"  - Reason: {question.get('reason')}")
    lines.append("")
    lines.append("## Needs Review")
    if not needs_review:
        lines.append("- No case-question items require review.")
    for question in needs_review:
        lines.append(f"- `{question.get('question_id')}` {question.get('question')}")
        lines.append(f"  - Reason: {question.get('reason')}")
        for gap in question.get("gaps", []):
            lines.append(f"  - Gap: {gap}")
    for finding in sorted(findings, key=lambda item: str(item.get("finding_id", ""))):
        if finding.get("status") != "needs_review":
            continue
        lines.append(f"- `{finding.get('finding_id')}` {finding.get('claim')}")
        if finding.get("rationale"):
            lines.append(f"  - Rationale: {finding.get('rationale')}")
    lines.append("")
    user_activity_findings = [
        finding
        for finding in findings
        if finding.get("artifact_family") == "registry_user_activity"
    ]
    event_counts = {}
    event_counts_by_profile = {}
    user_activity_gaps = []
    prepared_hive_scope_warnings = []
    profile_coverage = {}
    if user_activity_summary is not None:
        raw_counts = user_activity_summary.get("event_counts_by_artifact_type", {})
        if isinstance(raw_counts, dict):
            event_counts = raw_counts
        raw_profile_counts = user_activity_summary.get("event_counts_by_profile", {})
        if isinstance(raw_profile_counts, dict):
            event_counts_by_profile = raw_profile_counts
        raw_gaps = user_activity_summary.get("coverage_gaps", [])
        if isinstance(raw_gaps, list):
            user_activity_gaps = [gap for gap in raw_gaps if isinstance(gap, dict)]
        raw_scope_warnings = user_activity_summary.get("prepared_hive_scope_warnings", [])
        if isinstance(raw_scope_warnings, list):
            prepared_hive_scope_warnings = [
                warning for warning in raw_scope_warnings if isinstance(warning, dict)
            ]
        raw_profile_coverage = user_activity_summary.get("profile_coverage", {})
        if isinstance(raw_profile_coverage, dict):
            profile_coverage = raw_profile_coverage
    lines.append("## User Profile Hive Coverage")
    if profile_coverage:
        lines.append(
            f"- Status: `{profile_coverage.get('status')}`; "
            f"discovered={profile_coverage.get('discovered_profile_count', 0)}, "
            f"available={profile_coverage.get('available_profile_count', 0)}, "
            f"failed={profile_coverage.get('failed_profile_count', 0)}, "
            f"parsed={profile_coverage.get('parsed_profile_count', 0)}"
        )
        profile_ids = profile_coverage.get("available_profile_ids", [])
        if isinstance(profile_ids, list) and profile_ids:
            rendered_profiles = ", ".join(f"`{profile}`" for profile in profile_ids[:8])
            lines.append(f"- Available prepared profile hives: {rendered_profiles}")
    else:
        lines.append("- No NTUSER.DAT profile coverage summary was generated.")
    lines.append("")
    lines.append("## User Activity Summary")
    if not user_activity_findings and not event_counts:
        lines.append("- No Registry user-activity events were normalized.")
    for artifact_type, count in sorted(event_counts.items()):
        lines.append(f"- `{artifact_type}` events: {count}")
    lines.append("")
    lines.append("## User Activity Summary by Profile")
    if not event_counts_by_profile:
        lines.append("- No per-profile Registry user-activity events were normalized.")
    for profile_id, count in sorted(event_counts_by_profile.items()):
        lines.append(f"- `{profile_id}` events: {count}")
    lines.append("")
    category_sections = (
        (
            "File Access / Recent Document Candidates",
            {"file_access_candidate", "cloud_or_transfer_candidate"},
        ),
        ("Program Use Candidates", {"program_use_candidate"}),
        ("Typed Path / User Navigation Candidates", {"typed_path_navigation_candidate"}),
    )
    for title, categories in category_sections:
        lines.append(f"## {title}")
        category_findings = [
            finding
            for finding in user_activity_findings
            if finding.get("finding_category") in categories
        ]
        if not category_findings:
            lines.append("- No candidates in this category.")
        for finding in sorted(category_findings, key=lambda item: str(item.get("finding_id", ""))):
            refs = finding.get("linked_event_ids", [])
            rendered_refs = (
                ", ".join(f"`{ref}`" for ref in refs[:3])
                if isinstance(refs, list)
                else ""
            )
            lines.append(
                f"- `{finding.get('finding_id')}` status=`{finding.get('status')}` "
                f"{finding.get('claim')}"
            )
            if finding.get("rationale"):
                lines.append(f"  - Reason: {finding.get('rationale')}")
            profile_ids = finding.get("profile_ids", [])
            if isinstance(profile_ids, list) and profile_ids:
                rendered_profiles = ", ".join(f"`{profile}`" for profile in profile_ids[:5])
                lines.append(f"  - Profiles: {rendered_profiles}")
            if rendered_refs:
                lines.append(f"  - Evidence refs: {rendered_refs}")
            lines.append(
                "  - Limitation: Candidate evidence is not proof of theft or exfiltration."
            )
        lines.append("")
    lines.append("## Parser Coverage and User-Activity Gaps")
    if prepared_hive_scope_warnings:
        lines.append(
            "- Registry user-activity partial profile coverage: coverage is limited "
            "to the prepared NTUSER.DAT hive(s); one or more additional profile "
            "hives were not extracted."
        )
        lines.append(
            "  - Next step: extract and inventory all user profile NTUSER.DAT hives."
        )
    if not user_activity_gaps:
        lines.append("- No Registry user-activity parser/key gaps were recorded.")
    for gap in user_activity_gaps:
        profile_label = ""
        if gap.get("profile_id"):
            profile_label = f" profile=`{gap.get('profile_id')}`"
        lines.append(
            f"- `{gap.get('artifact_type')}`{profile_label} "
            f"reason=`{gap.get('reason')}`: "
            f"{gap.get('impact')}"
        )
        if gap.get("recommended_next_step"):
            lines.append(f"  - Next step: {gap.get('recommended_next_step')}")
    lines.append("")
    lines.append("## Not Assessed / Scope Gaps")
    if not not_assessed:
        lines.append("- No unsupported case questions were marked not_assessed.")
    for question in not_assessed:
        lines.append(f"- `{question.get('question_id')}` {question.get('question')}")
        for gap in question.get("gaps", []):
            lines.append(f"  - Gap: {gap}")
    lines.append("")
    lines.append("## Evidence Provenance Summary")
    lines.append(f"- Case ID: `{case_id}`")
    lines.append(f"- Source records: {len(adapted.sources)}")
    lines.append(f"- Prepared parser artifacts: {len(adapted.evidence_manifest.artifacts)}")
    lines.append(
        f"- Normalized events written: {coverage_summary.get('normalized_events_written', 0)}"
    )
    parser_statuses = [
        item.get("parser_status")
        for item in coverage_summary.get("per_artifact", [])
        if isinstance(item, dict)
    ]
    if parser_statuses:
        rendered = ", ".join(sorted(str(status) for status in parser_statuses))
        lines.append(f"- Parser statuses observed: {rendered}")
    if adapted.memory_sources:
        lines.append("- Memory sources: inventoried only; final scope marks memory not_assessed.")
    lines.append("")
    lines.append("## Analyst Next Steps")
    next_steps: list[str] = []
    for question in questions:
        for item in question.get("recommended_next_manual_review", []):
            if isinstance(item, str) and item not in next_steps:
                next_steps.append(item)
    if not next_steps:
        lines.append("- No additional manual next steps were generated.")
    for item in next_steps:
        lines.append(f"- {item}")
    return "\n".join(lines).rstrip() + "\n"
