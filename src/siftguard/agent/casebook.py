from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from siftguard.agent.models import BLOCKED_EXECUTION_KEYS

CASEBOOK_YAML_REJECTION = "YAML casebooks are not supported in the final sprint; use JSON."
CASEBOOK_CLAIM_BOUNDARY_STATUSES = {
    "confirmed",
    "inferred",
    "needs_review",
    "not_assessed",
    "rejected",
}


@dataclass(frozen=True, slots=True)
class CasebookTriageProfile:
    keywords: tuple[str, ...]
    sensitive_paths: tuple[str, ...]
    file_extensions: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class CasebookFact:
    id: str
    fact: str


@dataclass(frozen=True, slots=True)
class CasebookKeyDate:
    id: str
    date: str
    description: str


@dataclass(frozen=True, slots=True)
class CasebookAnalysisWindow:
    id: str
    start: str
    end: str
    description: str


@dataclass(frozen=True, slots=True)
class CasebookQuestion:
    id: str
    question: str
    supported_by_scope: bool | str
    evidence_classes: tuple[str, ...]
    status_policy: str | None = None
    expected_status: str | None = None
    gap_reason: str | None = None


@dataclass(frozen=True, slots=True)
class CasebookClaimBoundary:
    claim_area: str
    question_ids: tuple[str, ...]
    related_question_ids: tuple[str, ...]
    emit_when_all_statuses: tuple[str, ...]
    final_wording: str
    scope_boundary: str
    recommended_next_artifacts: tuple[str, ...]
    initial_investigative_pressure: str | None = None


@dataclass(frozen=True, slots=True)
class Casebook:
    case_id: str
    display_name: str
    time_zone: str | None
    triage_profile: CasebookTriageProfile
    case_facts: tuple[CasebookFact, ...]
    key_dates: tuple[CasebookKeyDate, ...]
    analysis_windows: tuple[CasebookAnalysisWindow, ...]
    case_questions: tuple[CasebookQuestion, ...]
    claim_boundaries: tuple[CasebookClaimBoundary, ...] = ()
    path: Path | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "display_name": self.display_name,
            "time_zone": self.time_zone,
            "triage_profile": {
                "keywords": list(self.triage_profile.keywords),
                "sensitive_paths": list(self.triage_profile.sensitive_paths),
                "file_extensions": list(self.triage_profile.file_extensions),
            },
            "case_facts": [
                {
                    "id": item.id,
                    "fact": item.fact,
                }
                for item in self.case_facts
            ],
            "key_dates": [
                {
                    "id": item.id,
                    "date": item.date,
                    "description": item.description,
                }
                for item in self.key_dates
            ],
            "analysis_windows": [
                {
                    "id": item.id,
                    "start": item.start,
                    "end": item.end,
                    "description": item.description,
                }
                for item in self.analysis_windows
            ],
            "case_questions": [
                {
                    "id": item.id,
                    "question": item.question,
                    "supported_by_scope": item.supported_by_scope,
                    "evidence_classes": list(item.evidence_classes),
                    "status_policy": item.status_policy,
                    "expected_status": item.expected_status,
                    "gap_reason": item.gap_reason,
                }
                for item in self.case_questions
            ],
            "claim_boundaries": [
                {
                    "claim_area": item.claim_area,
                    "question_ids": list(item.question_ids),
                    "related_question_ids": list(item.related_question_ids),
                    "emit_when_all_statuses": list(item.emit_when_all_statuses),
                    "final_wording": item.final_wording,
                    "scope_boundary": item.scope_boundary,
                    "recommended_next_artifacts": list(item.recommended_next_artifacts),
                    "initial_investigative_pressure": item.initial_investigative_pressure,
                }
                for item in self.claim_boundaries
            ],
        }


def _required_string(data: dict[str, Any], name: str, *, label: str) -> str:
    value = data.get(name)
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label}.{name} must be a non-empty string")
    return value


def _optional_string(data: dict[str, Any], name: str, *, label: str) -> str | None:
    value = data.get(name)
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label}.{name} must be a non-empty string when provided")
    return value


def _reject_blocked_keys(value: Any, *, path: str) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError(f"{path} contains a non-string key")
            if key.casefold() in BLOCKED_EXECUTION_KEYS:
                raise ValueError(f"{path} contains blocked execution key: {key}")
            _reject_blocked_keys(item, path=f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _reject_blocked_keys(item, path=f"{path}[{index}]")
    elif not isinstance(value, (str, int, float, bool, type(None))):
        raise ValueError(f"{path} contains a non-JSON value")


def _load_json_object(path: Path, label: str) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"malformed {label} JSON: {exc.msg}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"{label} JSON must contain an object")
    return payload


def _validate_date(value: str, *, label: str) -> str:
    try:
        datetime.fromisoformat(value)
    except ValueError as exc:
        raise ValueError(f"{label} must be an ISO date or datetime") from exc
    return value


def _validate_datetime(value: str, *, label: str) -> str:
    text = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise ValueError(f"{label} must be an ISO datetime") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{label} must include an explicit UTC offset")
    return value


def _optional_string_list(
    data: dict[str, Any],
    name: str,
    *,
    label: str,
) -> tuple[str, ...]:
    value = data.get(name, [])
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise ValueError(f"{label}.{name} must be a list of non-empty strings")
    return tuple(value)


def _normalize_extension(value: str) -> str:
    normalized = value.casefold()
    return normalized if normalized.startswith(".") else f".{normalized}"


def _triage_profile(payload: dict[str, Any]) -> CasebookTriageProfile:
    profile = payload.get("triage_profile", {})
    if profile is None:
        profile = {}
    if not isinstance(profile, dict):
        raise ValueError("casebook.triage_profile must be an object when provided")
    return CasebookTriageProfile(
        keywords=_optional_string_list(profile, "keywords", label="casebook.triage_profile"),
        sensitive_paths=_optional_string_list(
            profile,
            "sensitive_paths",
            label="casebook.triage_profile",
        ),
        file_extensions=tuple(
            _normalize_extension(item)
            for item in _optional_string_list(
                profile,
                "file_extensions",
                label="casebook.triage_profile",
            )
        ),
    )


def _case_facts(payload: dict[str, Any]) -> tuple[CasebookFact, ...]:
    rows = payload.get("case_facts", [])
    if not isinstance(rows, list) or not all(isinstance(row, dict) for row in rows):
        raise ValueError("casebook.case_facts must be a list of objects")
    facts: list[CasebookFact] = []
    seen_ids: set[str] = set()
    for index, row in enumerate(rows):
        label = f"casebook.case_facts[{index}]"
        fact_id = _required_string(row, "id", label=label)
        if fact_id in seen_ids:
            raise ValueError(f"duplicate casebook fact id: {fact_id}")
        seen_ids.add(fact_id)
        facts.append(
            CasebookFact(
                id=fact_id,
                fact=_required_string(row, "fact", label=label),
            )
        )
    return tuple(facts)


def _key_dates(payload: dict[str, Any]) -> tuple[CasebookKeyDate, ...]:
    rows = payload.get("key_dates", [])
    if not isinstance(rows, list) or not all(isinstance(row, dict) for row in rows):
        raise ValueError("casebook.key_dates must be a list of objects")
    dates: list[CasebookKeyDate] = []
    for index, row in enumerate(rows):
        label = f"casebook.key_dates[{index}]"
        date = _required_string(row, "date", label=label)
        dates.append(
            CasebookKeyDate(
                id=_required_string(row, "id", label=label),
                date=_validate_date(date, label=f"{label}.date"),
                description=_required_string(row, "description", label=label),
            )
        )
    return tuple(dates)


def _analysis_windows(payload: dict[str, Any]) -> tuple[CasebookAnalysisWindow, ...]:
    rows = payload.get("analysis_windows", [])
    if not isinstance(rows, list) or not all(isinstance(row, dict) for row in rows):
        raise ValueError("casebook.analysis_windows must be a list of objects")
    windows: list[CasebookAnalysisWindow] = []
    for index, row in enumerate(rows):
        label = f"casebook.analysis_windows[{index}]"
        start = _required_string(row, "start", label=label)
        end = _required_string(row, "end", label=label)
        windows.append(
            CasebookAnalysisWindow(
                id=_required_string(row, "id", label=label),
                start=_validate_datetime(start, label=f"{label}.start"),
                end=_validate_datetime(end, label=f"{label}.end"),
                description=_required_string(row, "description", label=label),
            )
        )
    return tuple(windows)


def _questions(payload: dict[str, Any]) -> tuple[CasebookQuestion, ...]:
    rows = payload.get("case_questions", [])
    if not isinstance(rows, list) or not all(isinstance(row, dict) for row in rows):
        raise ValueError("casebook.case_questions must be a list of objects")
    questions: list[CasebookQuestion] = []
    seen_ids: set[str] = set()
    for index, row in enumerate(rows):
        label = f"casebook.case_questions[{index}]"
        question_id = _required_string(row, "id", label=label)
        if question_id in seen_ids:
            raise ValueError(f"duplicate casebook question id: {question_id}")
        seen_ids.add(question_id)
        supported = row.get("supported_by_scope")
        if not isinstance(supported, (bool, str)):
            raise ValueError(f"{label}.supported_by_scope must be a boolean or string")
        evidence_classes = row.get("evidence_classes", [])
        if not isinstance(evidence_classes, list) or not all(
            isinstance(item, str) and item for item in evidence_classes
        ):
            raise ValueError(f"{label}.evidence_classes must be a list of strings")
        questions.append(
            CasebookQuestion(
                id=question_id,
                question=_required_string(row, "question", label=label),
                supported_by_scope=supported,
                evidence_classes=tuple(evidence_classes),
                status_policy=_optional_string(row, "status_policy", label=label),
                expected_status=_optional_string(row, "expected_status", label=label),
                gap_reason=_optional_string(row, "gap_reason", label=label),
            )
        )
    return tuple(questions)


def _claim_boundaries(
    payload: dict[str, Any],
    *,
    question_ids: set[str],
) -> tuple[CasebookClaimBoundary, ...]:
    rows = payload.get("claim_boundaries", [])
    if not isinstance(rows, list) or not all(isinstance(row, dict) for row in rows):
        raise ValueError("casebook.claim_boundaries must be a list of objects")
    boundaries: list[CasebookClaimBoundary] = []
    seen_areas: set[str] = set()
    for index, row in enumerate(rows):
        label = f"casebook.claim_boundaries[{index}]"
        claim_area = _required_string(row, "claim_area", label=label)
        if claim_area in seen_areas:
            raise ValueError(f"duplicate casebook claim boundary area: {claim_area}")
        seen_areas.add(claim_area)
        boundary_question_ids = _optional_string_list(row, "question_ids", label=label)
        if not boundary_question_ids:
            raise ValueError(f"{label}.question_ids must contain at least one question id")
        related_question_ids = _optional_string_list(
            row,
            "related_question_ids",
            label=label,
        )
        unknown_ids = sorted(
            question_id
            for question_id in (*boundary_question_ids, *related_question_ids)
            if question_id not in question_ids
        )
        if unknown_ids:
            raise ValueError(
                f"{label} references unknown case question id(s): {', '.join(unknown_ids)}"
            )
        statuses = _optional_string_list(row, "emit_when_all_statuses", label=label)
        if not statuses:
            raise ValueError(f"{label}.emit_when_all_statuses must contain at least one status")
        invalid_statuses = sorted(
            status for status in statuses if status not in CASEBOOK_CLAIM_BOUNDARY_STATUSES
        )
        if invalid_statuses:
            allowed = ", ".join(sorted(CASEBOOK_CLAIM_BOUNDARY_STATUSES))
            raise ValueError(
                f"{label}.emit_when_all_statuses contains invalid status "
                f"{', '.join(invalid_statuses)}; allowed: {allowed}"
            )
        boundaries.append(
            CasebookClaimBoundary(
                claim_area=claim_area,
                question_ids=boundary_question_ids,
                related_question_ids=related_question_ids,
                emit_when_all_statuses=statuses,
                final_wording=_required_string(row, "final_wording", label=label),
                scope_boundary=_required_string(row, "scope_boundary", label=label),
                recommended_next_artifacts=_optional_string_list(
                    row,
                    "recommended_next_artifacts",
                    label=label,
                ),
                initial_investigative_pressure=_optional_string(
                    row,
                    "initial_investigative_pressure",
                    label=label,
                ),
            )
        )
    return tuple(boundaries)


def casebook_from_dict(payload: dict[str, Any], *, path: Path | None = None) -> Casebook:
    _reject_blocked_keys(payload, path="casebook")
    questions = _questions(payload)
    return Casebook(
        case_id=_required_string(payload, "case_id", label="casebook"),
        display_name=_required_string(payload, "display_name", label="casebook"),
        time_zone=_optional_string(payload, "time_zone", label="casebook"),
        triage_profile=_triage_profile(payload),
        case_facts=_case_facts(payload),
        key_dates=_key_dates(payload),
        analysis_windows=_analysis_windows(payload),
        case_questions=questions,
        claim_boundaries=_claim_boundaries(
            payload,
            question_ids={question.id for question in questions},
        ),
        path=path,
    )


def load_casebook(casebook_path: Path, *, case_id: str) -> Casebook:
    if casebook_path.suffix.casefold() in {".yaml", ".yml"}:
        raise ValueError(CASEBOOK_YAML_REJECTION)
    if casebook_path.suffix.casefold() != ".json":
        raise ValueError("casebooks must use .json")
    resolved = casebook_path.resolve()
    if not resolved.exists():
        raise ValueError(f"casebook does not exist: {casebook_path}")
    if resolved.is_dir():
        raise ValueError(f"casebook path is a directory: {casebook_path}")
    casebook = casebook_from_dict(_load_json_object(resolved, "casebook"), path=resolved)
    if casebook.case_id != case_id:
        raise ValueError(
            f"casebook case_id '{casebook.case_id}' does not match case_id '{case_id}'"
        )
    return casebook


def analysis_window_bounds(casebook: Casebook) -> tuple[tuple[datetime, datetime], ...]:
    bounds: list[tuple[datetime, datetime]] = []
    for window in casebook.analysis_windows:
        start_text = window.start[:-1] + "+00:00" if window.start.endswith("Z") else window.start
        end_text = window.end[:-1] + "+00:00" if window.end.endswith("Z") else window.end
        start = datetime.fromisoformat(start_text)
        end = datetime.fromisoformat(end_text)
        if start.tzinfo is None or start.utcoffset() is None:
            raise ValueError(f"casebook analysis window {window.id} start lacks offset")
        if end.tzinfo is None or end.utcoffset() is None:
            raise ValueError(f"casebook analysis window {window.id} end lacks offset")
        bounds.append((start.astimezone(timezone.utc), end.astimezone(timezone.utc)))
    return tuple(bounds)
