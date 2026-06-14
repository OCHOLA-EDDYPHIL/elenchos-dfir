from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from elenchos.agent.case_manifest_adapter import AdaptedCaseManifest
from elenchos.agent.casebook import Casebook, CasebookAnalysisWindow, CasebookQuestion
from elenchos.agent.claim_boundaries import build_claim_boundary_records

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
EXECUTION_SPECIFIC_EVIDENCE_CLASSES = {"amcache", "prefetch", "event_log_execution"}
REPORT_TOP_N = 10
REPORT_DISPLAY_MAX_CHARS = 120
_HEX_BYTE_DUMP_RE = re.compile(r"^(?:[0-9A-Fa-f]{2}[-\s]?){20,}$")
_PRINTABLE_RUN_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9 ._:/\\?=&{}()[\]-]{2,}")
_REPORT_WORD_BOUNDARY_RE = re.compile(r"[\s,;:]+")


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
    if (
        question.expected_status in UNSUPPORTED_EXPECTED_STATUSES
        or question.supported_by_scope is False
    ):
        return []
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
    if (
        question.status_policy == "multi_artifact_execution_presence"
        and not classes & EXECUTION_SPECIFIC_EVIDENCE_CLASSES
    ):
        return False
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
    if question.status_policy == "multi_artifact_execution_presence":
        if not classes & EXECUTION_SPECIFIC_EVIDENCE_CLASSES:
            return False
        if len(events) >= 2 and len(classes) >= 2:
            return True
        return any(
            finding.get("status") == "inferred"
            and (
                _finding_evidence_classes(finding) & EXECUTION_SPECIFIC_EVIDENCE_CLASSES
            )
            for finding in linked_findings
        )
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
    result = {
        "case_id": adapted.case_id,
        "casebook_id": casebook.case_id,
        "casebook_reusable_template": casebook.reusable_template,
        "created_at": created_at,
        "questions": questions,
        "status_counts": status_counts,
    }
    result["claim_boundaries"] = build_claim_boundary_records(
        casebook=casebook,
        case_questions=result,
    )
    return result


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


def _report_text(value: object, *, max_chars: int = REPORT_DISPLAY_MAX_CHARS) -> str:
    text = "" if value is None else str(value)
    cleaned = "".join(
        char if char.isprintable() and char not in "\r\n\t" else " "
        for char in text
    )
    collapsed = " ".join(cleaned.split())
    if len(collapsed) <= max_chars:
        return collapsed
    if max_chars <= 3:
        return "." * max_chars
    limit = max_chars - 3
    candidate = collapsed[:limit].rstrip()
    min_boundary = min(max(12, limit // 2), max(0, limit - 1))
    boundary = -1
    for match in _REPORT_WORD_BOUNDARY_RE.finditer(candidate):
        if match.start() >= min_boundary:
            boundary = match.start()
    if boundary == -1:
        for separator in ("/", "\\", "-", "_", "."):
            position = candidate.rfind(separator, min_boundary)
            if position > boundary:
                boundary = position
    if boundary > 0:
        candidate = candidate[:boundary].rstrip(" ,;:-_/\\.")
    candidate = candidate.rstrip(" ,;:-_/\\.")
    return f"{candidate}..." if candidate else "..."


def _hex_bytes(value: str) -> bytes | None:
    text = value.strip()
    if not _HEX_BYTE_DUMP_RE.match(text):
        return None
    cleaned = re.sub(r"[^0-9A-Fa-f]", "", text)
    if len(cleaned) < 40 or len(cleaned) % 2:
        return None
    try:
        return bytes.fromhex(cleaned)
    except ValueError:
        return None


def _printable_runs(decoded: str) -> list[str]:
    normalized = decoded.replace("\x00", " ")
    runs = [
        _report_text(match.group(), max_chars=REPORT_DISPLAY_MAX_CHARS)
        for match in _PRINTABLE_RUN_RE.finditer(normalized)
    ]
    return [
        run for run in runs
        if len(run) >= 4 and any(char.isalpha() for char in run)
    ]


def _best_printable_run(runs: list[str]) -> str | None:
    if not runs:
        return None
    extensions = (".exe", ".dll", ".lnk", ".docx", ".xlsx", ".pptx", ".pdf", ".jpg", ".png")

    def score(value: str) -> tuple[int, int, str]:
        lowered = value.casefold()
        has_extension = int(any(extension in lowered for extension in extensions))
        return has_extension, len(value), value

    return sorted(dict.fromkeys(runs), key=score, reverse=True)[0]


def _decode_hex_display_value(value: str) -> str | None:
    raw = _hex_bytes(value)
    if raw is None:
        return None
    runs: list[str] = []
    for encoding in ("utf-16le", "utf-8", "latin-1"):
        try:
            decoded = raw.decode(encoding, errors="ignore")
        except LookupError:
            continue
        runs.extend(_printable_runs(decoded))
    return _best_printable_run(runs)


def _first_linked_event_id(finding: dict[str, Any]) -> str | None:
    refs = finding.get("linked_event_ids", [])
    if isinstance(refs, list):
        for ref in refs:
            if isinstance(ref, str) and ref:
                return ref
    evidence_refs = finding.get("evidence_refs", [])
    if isinstance(evidence_refs, list):
        for ref in evidence_refs:
            if isinstance(ref, dict) and isinstance(ref.get("evidence_id"), str):
                return ref["evidence_id"]
    return None


def _candidate_target_from_claim(claim: str) -> str:
    marker = "candidate:"
    if marker in claim.casefold():
        start = claim.casefold().rfind(marker)
        return claim[start + len(marker):].strip()
    if claim.casefold().startswith("timeline for "):
        return claim.removeprefix("Timeline for ").removesuffix(
            " has incomplete correlation coverage."
        ).strip().strip('"')
    return claim


def _report_display_value(value: object, *, event_id: str | None = None) -> str:
    text = _report_text(value, max_chars=10_000)
    decoded = _decode_hex_display_value(text)
    if decoded is not None:
        return _report_text(decoded)
    if _hex_bytes(text) is not None:
        ref = event_id or "unknown-event"
        return f"[decoded MRU value unavailable; see normalized_events.json:{ref}]"
    return _report_text(text)


def _finding_category(finding: dict[str, Any]) -> str:
    for key in ("finding_category", "category", "kind"):
        value = finding.get(key)
        if isinstance(value, str) and value:
            return value
    return "finding"


def _evidence_count(finding: dict[str, Any]) -> int:
    refs = finding.get("evidence_refs", [])
    return len(refs) if isinstance(refs, list) else 0


def _top_findings(
    findings: list[dict[str, Any]],
    *,
    statuses: set[str] | None = None,
    categories: set[str] | None = None,
    predicate: Any | None = None,
) -> list[dict[str, Any]]:
    selected = []
    for finding in findings:
        status = finding.get("status")
        category = _finding_category(finding)
        if statuses is not None and status not in statuses:
            continue
        if categories is not None and category not in categories:
            continue
        if predicate is not None and not predicate(finding):
            continue
        selected.append(finding)
    return sorted(
        selected,
        key=lambda item: (-_evidence_count(item), str(item.get("finding_id", ""))),
    )


def _finding_summary_line(finding: dict[str, Any]) -> str:
    finding_id = _report_text(finding.get("finding_id", "unknown-finding"))
    status = _report_text(finding.get("status", "unknown"))
    category = _report_text(_finding_category(finding).replace("_", " "))
    claim = str(finding.get("claim", ""))
    target = _candidate_target_from_claim(claim)
    display = _report_display_value(target, event_id=_first_linked_event_id(finding))
    evidence_refs = _evidence_count(finding)
    profile_ids = finding.get("profile_ids", [])
    profile_text = ""
    if isinstance(profile_ids, list) and profile_ids:
        profile_text = f"; profiles={', '.join(_report_text(item) for item in profile_ids[:3])}"
    return (
        f"- `{finding_id}` status=`{status}`; {category}: {display}; "
        f"evidence_refs={evidence_refs}{profile_text}"
    )


def _append_top_findings(
    lines: list[str],
    findings: list[dict[str, Any]],
    *,
    empty_text: str,
    omitted_label: str,
) -> None:
    if not findings:
        lines.append(f"- {empty_text}")
        return
    for finding in findings[:REPORT_TOP_N]:
        lines.append(_finding_summary_line(finding))
    if len(findings) > REPORT_TOP_N:
        lines.append(
            f"- {len(findings) - REPORT_TOP_N} additional {omitted_label} omitted; "
            "see findings.json and case_questions.json for the full list."
        )


def _status_counts(rows: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        status = row.get("status")
        if isinstance(status, str):
            counts[status] = counts.get(status, 0) + 1
    return dict(sorted(counts.items()))


def _parser_status_counts(coverage_summary: dict[str, Any]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in coverage_summary.get("per_artifact", []):
        if not isinstance(item, dict):
            continue
        status = item.get("parser_status")
        if isinstance(status, str):
            counts[status] = counts.get(status, 0) + 1
    return dict(sorted(counts.items()))


def _parser_gap_count(coverage_summary: dict[str, Any]) -> int:
    count = 0
    for item in coverage_summary.get("per_artifact", []):
        if isinstance(item, dict) and isinstance(item.get("coverage_gaps"), list):
            count += len(item["coverage_gaps"])
    return count


def _amcache_event_count(coverage_summary: dict[str, Any]) -> int:
    total = 0
    for item in coverage_summary.get("per_artifact", []):
        if not isinstance(item, dict) or item.get("artifact_type") != "amcache":
            continue
        value = item.get("normalized_rows_selected", item.get("source_events_seen", 0))
        if isinstance(value, int):
            total += value
    return total


def _compact_counts(counts: dict[str, int]) -> str:
    if not counts:
        return "none"
    return ", ".join(f"{key}={value}" for key, value in sorted(counts.items()))


def _question_answer(question: dict[str, Any]) -> str:
    question_id = question.get("question_id")
    status = question.get("status")
    if question_id == "q_when_activity" and status == "confirmed":
        return (
            "selected MFT, Amcache, Registry, and user-activity evidence contains "
            "timestamped activity inside the configured case window."
        )
    if question_id == "q_program_presence_execution" and status == "confirmed":
        return (
            "confirmed, narrowly: Amcache and related timeline evidence provide "
            "execution-relevant artifact presence; this does not label activity as malicious."
        )
    if question_id == "q_project_file_candidates":
        return "candidate project/file relevance was identified for analyst review."
    if status == "not_assessed":
        gaps = question.get("gaps", [])
        if isinstance(gaps, list) and gaps:
            return _report_text(gaps[0])
        return "not assessed under the current supported artifact scope."
    return _report_text(question.get("summary", "manual review remains required."))


def _question_line(question: dict[str, Any]) -> str:
    question_id = _report_text(question.get("question_id", "unknown-question"))
    status = _report_text(question.get("status", "unknown"))
    checked = question.get("evidence_classes_checked", [])
    checked_text = ", ".join(str(item) for item in checked) if isinstance(checked, list) else "none"
    linked = question.get("linked_finding_ids", [])
    refs = question.get("linked_evidence_refs", [])
    linked_count = len(linked) if isinstance(linked, list) else 0
    ref_count = len(refs) if isinstance(refs, list) else 0
    answer = _question_answer(question)
    answer_lower = answer.casefold()
    status_lower = status.casefold()
    status_and_answer = (
        answer
        if answer_lower.startswith(f"{status_lower}:")
        or answer_lower.startswith(f"{status_lower},")
        else f"{status}: {answer}"
    )
    return (
        f"- `{question_id}` — {status_and_answer} "
        f"Checked: {checked_text or 'none'}; linked_findings={linked_count}; "
        f"evidence_refs={ref_count}."
    )


def _is_program_or_execution_finding(finding: dict[str, Any]) -> bool:
    category = _finding_category(finding)
    claim = str(finding.get("claim", "")).casefold()
    return (
        category == "program_use_candidate"
        or "execution" in claim
        or ".exe" in claim
        or "amcache" in claim
    )


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
    not_assessed = [q for q in questions if q.get("status") == "not_assessed"]
    claim_boundaries = [
        boundary
        for boundary in case_questions.get("claim_boundaries", [])
        if isinstance(boundary, dict)
    ]
    supported_findings = _top_findings(findings, statuses={"confirmed", "inferred"})
    needs_review_findings = _top_findings(findings, statuses={"needs_review"})
    user_activity_findings = [
        finding
        for finding in findings
        if finding.get("artifact_family") == "registry_user_activity"
    ]
    user_activity_highlights = _top_findings(
        user_activity_findings,
        categories={
            "file_access_candidate",
            "typed_path_navigation_candidate",
            "cloud_or_transfer_candidate",
        },
    )
    program_highlights = _top_findings(findings, predicate=_is_program_or_execution_finding)

    event_counts: dict[str, int] = {}
    event_counts_by_profile: dict[str, int] = {}
    user_activity_gaps: list[dict[str, Any]] = []
    profile_coverage: dict[str, Any] = {}
    if user_activity_summary is not None:
        raw_counts = user_activity_summary.get("event_counts_by_artifact_type", {})
        if isinstance(raw_counts, dict):
            event_counts = {
                str(key): value for key, value in raw_counts.items()
                if isinstance(value, int)
            }
        raw_profile_counts = user_activity_summary.get("event_counts_by_profile", {})
        if isinstance(raw_profile_counts, dict):
            event_counts_by_profile = {
                str(key): value for key, value in raw_profile_counts.items()
                if isinstance(value, int)
            }
        raw_gaps = user_activity_summary.get("coverage_gaps", [])
        if isinstance(raw_gaps, list):
            user_activity_gaps = [gap for gap in raw_gaps if isinstance(gap, dict)]
        raw_profile_coverage = user_activity_summary.get("profile_coverage", {})
        if isinstance(raw_profile_coverage, dict):
            profile_coverage = raw_profile_coverage

    lines = ["# Case Report", ""]
    lines.append("## Executive Summary")
    lines.append("- Bounded autonomous run completed for the prepared case manifest.")
    lines.append("- Amcache transaction sidecars were staged and used when present.")
    lines.append(
        f"- Amcache produced {_amcache_event_count(coverage_summary)} "
        "normalized execution-relevant event(s)."
    )
    profile_status = profile_coverage.get("status", "not_summarized")
    discovered_profiles = profile_coverage.get("discovered_profile_count", 0)
    parsed_profiles = profile_coverage.get("parsed_profile_count", 0)
    lines.append(
        f"- NTUSER profile hives considered: discovered={discovered_profiles}, "
        f"parsed={parsed_profiles}, status=`{profile_status}`."
    )
    for boundary in claim_boundaries:
        final_wording = boundary.get("final_wording")
        scope_boundary = boundary.get("scope_boundary")
        if isinstance(final_wording, str) and final_wording:
            lines.append(f"- {final_wording}")
        if isinstance(scope_boundary, str) and scope_boundary:
            lines.append(f"- {scope_boundary}")
    if adapted.memory_sources:
        lines.append(
            "- Memory remains `not_assessed`; memory forensics is outside the current "
            "final scope."
        )
    lines.append(
        "- Full traceability remains in JSON outputs and `audit.jsonl`; this report "
        "shows curated highlights only."
    )
    lines.append("")

    lines.append("## Case Questions Summary")
    if not questions:
        lines.append("- No case questions were available.")
    for question in questions:
        lines.append(_question_line(question))
    lines.append("")

    lines.append("## Supported Findings")
    _append_top_findings(
        lines,
        supported_findings,
        empty_text="No confirmed or inferred findings were generated.",
        omitted_label="supported finding(s)",
    )
    lines.append("")

    lines.append("## Needs Review Highlights")
    _append_top_findings(
        lines,
        needs_review_findings,
        empty_text="No needs_review findings were generated.",
        omitted_label="needs_review finding(s)",
    )
    lines.append("")

    lines.append("## User Activity Highlights")
    lines.append("- Candidate evidence requires direct support before claim conclusions.")
    _append_top_findings(
        lines,
        user_activity_highlights,
        empty_text="No file/user-activity candidate highlights were generated.",
        omitted_label="user-activity candidate(s)",
    )
    lines.append("")

    lines.append("## Program / Execution-Relevant Artifact Highlights")
    lines.append(
        "- Execution-relevant artifacts require analyst review before labeling activity "
        "as malicious."
    )
    _append_top_findings(
        lines,
        program_highlights,
        empty_text="No program/execution-relevant highlights were generated.",
        omitted_label="program/execution candidate(s)",
    )
    lines.append("")

    lines.append("## Parser Coverage Summary")
    lines.append(f"- Prepared parser artifacts: {len(adapted.evidence_manifest.artifacts)}")
    lines.append(
        f"- Normalized events written: {coverage_summary.get('normalized_events_written', 0)}"
    )
    lines.append(f"- Parser statuses: {_compact_counts(_parser_status_counts(coverage_summary))}")
    lines.append(f"- Amcache events: {_amcache_event_count(coverage_summary)}")
    lines.append(f"- User-activity events: {_compact_counts(event_counts)}")
    if event_counts_by_profile:
        profile_counts = _compact_counts(event_counts_by_profile)
        lines.append(f"- User-activity events by profile: {profile_counts}")
    if profile_coverage:
        lines.append(
            f"- Profile hive coverage: discovered={discovered_profiles}, "
            f"available={profile_coverage.get('available_profile_count', 0)}, "
            f"failed={profile_coverage.get('failed_profile_count', 0)}, "
            f"parsed={parsed_profiles}, status=`{profile_status}`."
        )
    total_gap_count = (
        len(adapted.coverage_gaps) + len(user_activity_gaps) + _parser_gap_count(coverage_summary)
    )
    lines.append(f"- Coverage gaps recorded: {total_gap_count}")
    lines.append("")

    lines.append("## Not Assessed / Scope Gaps")
    lines.append("What Elenchos did not assess within the submitted artifact scope:")
    for boundary in claim_boundaries:
        final_wording = boundary.get("final_wording")
        scope_boundary = boundary.get("scope_boundary")
        if isinstance(final_wording, str) and final_wording:
            lines.append(f"- {final_wording}")
        if isinstance(scope_boundary, str) and scope_boundary:
            lines.append(f"- {scope_boundary}")
    if adapted.memory_sources:
        lines.append("- Memory forensics was not performed; memory remains `not_assessed`.")
    lines.append("- Candidate evidence requires analyst review before incident conclusions.")
    if not not_assessed:
        lines.append("- No unsupported case questions were marked not_assessed.")
    for question in not_assessed:
        lines.append(f"- `{question.get('question_id')}`: {_question_answer(question)}")
    lines.append("")

    lines.append("## Evidence Provenance Summary")
    lines.append(f"- Case ID: `{case_id}`")
    lines.append(f"- Source records: {len(adapted.sources)}")
    lines.append(f"- Prepared parser artifacts: {len(adapted.evidence_manifest.artifacts)}")
    lines.append("- Every finding links back to prepared artifact IDs in JSON outputs.")
    if adapted.memory_sources:
        lines.append("- Memory sources: inventoried only; final scope marks memory not_assessed.")
    lines.append("")

    lines.append("## Traceability")
    lines.append("- `findings.json`: complete finding records and evidence refs.")
    lines.append("- `normalized_events.json`: normalized parser events.")
    lines.append("- `case_questions.json`: full question-to-finding mappings.")
    lines.append("- `audit.jsonl`: step-by-step execution audit.")
    lines.append("- `decision_trace.json`: product-level forensic decisions.")
    lines.append("- `gap_analysis.json`: unsupported areas and coverage gaps.")
    lines.append("")

    lines.append("## Analyst Next Steps")
    lines.append("- Review the top candidate files/programs against full JSON evidence refs.")
    lines.append(
        "- Inspect complete evidence mappings in `case_questions.json` and `findings.json`."
    )
    lines.append(
        "- Collect and parse additional artifacts before drawing conclusions for "
        "claim areas marked not_assessed."
    )
    lines.append("- Preserve generated JSON outputs and `audit.jsonl` with the case record.")
    lines.append("- Do not treat candidate file activity as proof of unsupported claims.")
    return "\n".join(lines).rstrip() + "\n"
