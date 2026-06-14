from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping

DEFAULT_EVENT_LIMIT = 20
SAFE_FALLBACK_CLAIM_BOUNDARY = (
    "No confirmed theft, exfiltration, compromise, memory, malware, or "
    "attribution conclusion is supported by the generated Elenchos outputs. "
    "Analyst review remains required."
)
REQUIRED_OUTPUTS = (
    "report.md",
    "findings.json",
    "case_questions.json",
    "gap_analysis.json",
    "validation_summary.json",
)


@dataclass(frozen=True, slots=True)
class ConsoleEvent:
    timestamp_utc: str | None
    kind: str
    message: str


@dataclass(frozen=True, slots=True)
class ConsoleState:
    output_dir: Path
    run_dir: Path | None
    prompt: str | None
    job_status: str | None
    returncode: int | None
    validation_status: str | None
    finding_counts: dict[str, int]
    case_question_counts: dict[str, int]
    normalized_events: int | None
    rationale_events: list[ConsoleEvent]
    policy_events: list[ConsoleEvent]
    progress_events: list[ConsoleEvent]
    final_summary: str | None
    claim_boundary: str | None
    openclaw_log_tail: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    required_outputs_present: dict[str, bool] = field(default_factory=dict)


def read_console_state(
    output_dir: Path,
    *,
    prompt: str | None = None,
    event_limit: int = DEFAULT_EVENT_LIMIT,
) -> ConsoleState:
    root = output_dir.expanduser().resolve()
    errors: list[str] = []
    candidates = _candidate_dirs(root)
    run_dir = _best_run_dir(candidates)

    rationale_events = _dedupe_events(
        _events_from_jsonl(
            candidates,
            "model_rationale.jsonl",
            kind="model-rationale",
            message_getter=_rationale_message,
            errors=errors,
        )
    )[-event_limit:]
    policy_events = _dedupe_events(
        _events_from_jsonl(
            candidates,
            "policy_decisions.jsonl",
            kind="policy",
            message_getter=_policy_message,
            errors=errors,
        )
    )[-event_limit:]
    progress_events = _dedupe_events(
        _events_from_jsonl(
            candidates,
            "progress.jsonl",
            kind="progress",
            message_getter=_progress_message,
            errors=errors,
        )
    )[-event_limit:]

    job = _first_json(candidates, "run_job.json", errors)
    validation = _first_json(candidates, "validation_summary.json", errors)
    findings = _first_json(candidates, "findings.json", errors)
    questions = _first_json(candidates, "case_questions.json", errors)
    normalized = _first_json(candidates, "normalized_events.json", errors)
    gap_analysis = _first_json(candidates, "gap_analysis.json", errors)
    self_correction = _first_json(candidates, "self_correction_events.json", errors)
    report = _first_text(candidates, "report.md", errors)
    openclaw_log_tail = _first_text_tail(candidates, "openclaw-console.log", errors)

    job_status, returncode = _job_status(job)
    validation_status = _string_value(validation, ("validation_status", "status"))
    finding_counts = _finding_status_counts(findings)
    case_question_counts = _case_question_status_counts(questions)
    normalized_events = _normalized_event_count(normalized)
    claim_boundary = _claim_boundary(
        self_correction=self_correction,
        gap_analysis=gap_analysis,
        case_questions=questions,
        validation=validation,
    )
    final_summary = _final_summary(
        report=report,
        validation_status=validation_status,
        finding_counts=finding_counts,
        case_question_counts=case_question_counts,
    )

    return ConsoleState(
        output_dir=root,
        run_dir=run_dir,
        prompt=prompt,
        job_status=job_status,
        returncode=returncode,
        validation_status=validation_status or "pending",
        finding_counts=finding_counts,
        case_question_counts=case_question_counts,
        normalized_events=normalized_events,
        rationale_events=rationale_events,
        policy_events=policy_events,
        progress_events=progress_events,
        final_summary=final_summary,
        claim_boundary=claim_boundary or SAFE_FALLBACK_CLAIM_BOUNDARY,
        openclaw_log_tail=openclaw_log_tail,
        errors=errors,
        required_outputs_present={
            name: any((candidate / name).is_file() for candidate in candidates)
            for name in REQUIRED_OUTPUTS
        },
    )


def _candidate_dirs(root: Path) -> list[Path]:
    raw = [
        root,
        root / "run",
        root / "agent-run",
    ]
    if root.name in {"run", "agent-run"}:
        raw.extend([root.parent, root.parent / "run", root.parent / "agent-run"])
    seen: set[str] = set()
    dirs: list[Path] = []
    for path in raw:
        resolved = path.resolve()
        key = resolved.as_posix()
        if key in seen:
            continue
        seen.add(key)
        dirs.append(resolved)
    return dirs


def _best_run_dir(candidates: Iterable[Path]) -> Path | None:
    marker_names = (
        "agent_run.json",
        "run_job.json",
        "report.md",
        "findings.json",
        "model_rationale.jsonl",
        "policy_decisions.jsonl",
    )
    for candidate in candidates:
        if any((candidate / name).exists() for name in marker_names):
            return candidate
    return None


def _safe_json(path: Path, errors: list[str]) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        errors.append(f"{path.name}: {exc}")
        return None
    if not isinstance(payload, dict):
        errors.append(f"{path.name}: JSON root is not an object")
        return None
    return payload


def _first_json(
    candidates: Iterable[Path],
    filename: str,
    errors: list[str],
) -> dict[str, Any] | None:
    for candidate in candidates:
        payload = _safe_json(candidate / filename, errors)
        if payload is not None:
            return payload
    return None


def _first_text(candidates: Iterable[Path], filename: str, errors: list[str]) -> str | None:
    for candidate in candidates:
        path = candidate / filename
        if not path.is_file():
            continue
        try:
            return path.read_text(encoding="utf-8", errors="ignore")
        except OSError as exc:
            errors.append(f"{path.name}: {exc}")
    return None


def _first_text_tail(
    candidates: Iterable[Path],
    filename: str,
    errors: list[str],
    *,
    limit: int = 12,
) -> list[str]:
    for candidate in candidates:
        path = candidate / filename
        if not path.is_file():
            continue
        try:
            rows = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError as exc:
            errors.append(f"{path.name}: {exc}")
            return []
        return [row for row in rows[-limit:] if row.strip()]
    return []


def _jsonl_rows(path: Path, errors: list[str]) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    rows: list[dict[str, Any]] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        errors.append(f"{path.name}: {exc}")
        return []
    for lineno, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped:
            continue
        try:
            payload = json.loads(stripped)
        except json.JSONDecodeError as exc:
            errors.append(f"{path.name}:{lineno}: {exc.msg}")
            continue
        if not isinstance(payload, dict):
            errors.append(f"{path.name}:{lineno}: JSONL row is not an object")
            continue
        rows.append(payload)
    return rows


def _events_from_jsonl(
    candidates: Iterable[Path],
    filename: str,
    *,
    kind: str,
    message_getter: Any,
    errors: list[str],
) -> list[ConsoleEvent]:
    events: list[ConsoleEvent] = []
    for candidate in candidates:
        for row in _jsonl_rows(candidate / filename, errors):
            message = message_getter(row)
            if not message:
                continue
            events.append(
                ConsoleEvent(
                    timestamp_utc=_event_timestamp(row),
                    kind=kind,
                    message=message,
                )
            )
    return sorted(events, key=lambda event: (event.timestamp_utc or "", event.kind, event.message))


def _event_timestamp(row: Mapping[str, Any]) -> str | None:
    for key in ("timestamp_utc", "timestamp"):
        value = row.get(key)
        if isinstance(value, str) and value:
            return value
    return None


def _rationale_message(row: Mapping[str, Any]) -> str | None:
    value = row.get("visible_message")
    return value if isinstance(value, str) and value else None


def _policy_message(row: Mapping[str, Any]) -> str | None:
    visible = row.get("visible_policy_message")
    if isinstance(visible, str) and visible:
        return visible
    action = row.get("proposed_action")
    decision = row.get("decision")
    reason = row.get("reason")
    if isinstance(action, str) and isinstance(decision, str):
        suffix = f": {reason}" if isinstance(reason, str) and reason else ""
        return f"[policy] proposed {action} -> {decision}{suffix}"
    return None


def _progress_message(row: Mapping[str, Any]) -> str | None:
    phase = row.get("phase")
    status = row.get("status")
    message = row.get("message")
    if isinstance(phase, str) and isinstance(status, str):
        if isinstance(message, str) and message:
            return f"{phase}: {status} - {message}"
        return f"{phase}: {status}"
    return None


def _dedupe_events(events: list[ConsoleEvent]) -> list[ConsoleEvent]:
    seen: set[tuple[str | None, str, str]] = set()
    deduped: list[ConsoleEvent] = []
    for event in events:
        key = (event.timestamp_utc, event.kind, event.message)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(event)
    return deduped


def _job_status(job: Mapping[str, Any] | None) -> tuple[str | None, int | None]:
    if job is None:
        return None, None
    status = job.get("status")
    returncode = job.get("returncode")
    return (
        status if isinstance(status, str) and status else None,
        returncode if isinstance(returncode, int) else None,
    )


def _string_value(payload: Mapping[str, Any] | None, keys: tuple[str, ...]) -> str | None:
    if payload is None:
        return None
    for key in keys:
        value = payload.get(key)
        if isinstance(value, str) and value:
            return value
    return None


def _rows(payload: Mapping[str, Any] | None, key: str) -> list[dict[str, Any]]:
    if payload is None:
        return []
    value = payload.get(key)
    if isinstance(value, list):
        return [row for row in value if isinstance(row, dict)]
    if isinstance(payload, list):
        return [row for row in payload if isinstance(row, dict)]
    return []


def _finding_status_counts(payload: Mapping[str, Any] | None) -> dict[str, int]:
    counts: Counter[str] = Counter()
    for row in _rows(payload, "findings"):
        status = row.get("status")
        if isinstance(status, str) and status:
            counts[status] += 1
    return dict(sorted(counts.items()))


def _case_question_status_counts(payload: Mapping[str, Any] | None) -> dict[str, int]:
    if payload is None:
        return {}
    status_counts = payload.get("status_counts")
    if isinstance(status_counts, dict):
        return {
            str(key): value
            for key, value in sorted(status_counts.items())
            if isinstance(value, int)
        }
    counts: Counter[str] = Counter()
    for row in _rows(payload, "questions"):
        status = row.get("status")
        if isinstance(status, str) and status:
            counts[status] += 1
    return dict(sorted(counts.items()))


def _normalized_event_count(payload: Mapping[str, Any] | None) -> int | None:
    if payload is None:
        return None
    for key in ("event_count", "normalized_event_count", "normalized_events_written"):
        value = payload.get(key)
        if isinstance(value, int):
            return value
    events = payload.get("events")
    if isinstance(events, list):
        return len(events)
    return None


def _claim_boundary(
    *,
    self_correction: Mapping[str, Any] | None,
    gap_analysis: Mapping[str, Any] | None,
    case_questions: Mapping[str, Any] | None,
    validation: Mapping[str, Any] | None,
) -> str | None:
    for payload, key in (
        (self_correction, "events"),
        (gap_analysis, "claim_boundaries"),
        (case_questions, "claim_boundaries"),
    ):
        for row in _rows(payload, key):
            final_wording = row.get("final_wording")
            if isinstance(final_wording, str) and final_wording:
                return final_wording
    if validation is not None:
        notes = validation.get("notes")
        if isinstance(notes, list):
            for note in notes:
                if isinstance(note, str) and "Elenchos" in note:
                    return note
    return None


def _final_summary(
    *,
    report: str | None,
    validation_status: str | None,
    finding_counts: Mapping[str, int],
    case_question_counts: Mapping[str, int],
) -> str | None:
    if report:
        lines = [line.strip() for line in report.splitlines() if line.strip()]
        selected = [
            line.lstrip("#").strip()
            for line in lines
            if not line.startswith("```")
        ][:5]
        if selected:
            return " ".join(selected)[:800]
    if validation_status or finding_counts or case_question_counts:
        return (
            f"Validation: {validation_status or 'pending'}. "
            f"Findings: {_format_counts(finding_counts) or 'none yet'}. "
            f"Case questions: {_format_counts(case_question_counts) or 'none yet'}."
        )
    return None


def _format_counts(counts: Mapping[str, int]) -> str:
    return ", ".join(f"{key}={value}" for key, value in sorted(counts.items()))


def render_text_snapshot(state: ConsoleState) -> str:
    lines = [
        "Elenchos Case Console",
        f"Output directory: {state.output_dir}",
        f"Run directory: {state.run_dir or 'pending'}",
        f"Job status: {state.job_status or 'pending'}",
        f"Return code: {state.returncode if state.returncode is not None else 'pending'}",
        f"Validation: {state.validation_status or 'pending'}",
        f"Findings: {_format_counts(state.finding_counts) or 'none'}",
        f"Case questions: {_format_counts(state.case_question_counts) or 'none'}",
        "Normalized events: "
        f"{state.normalized_events if state.normalized_events is not None else 'pending'}",
        "",
        "Live rationale",
    ]
    lines.extend(f"- {event.message}" for event in state.rationale_events[-8:])
    if not state.rationale_events:
        lines.append("- pending")
    lines.append("")
    lines.append("Policy gate")
    lines.extend(f"- {event.message}" for event in state.policy_events[-8:])
    if not state.policy_events:
        lines.append("- pending")
    lines.append("")
    lines.append("Run status")
    lines.extend(f"- {event.message}" for event in state.progress_events[-8:])
    if not state.progress_events:
        lines.append("- pending")
    lines.append("")
    lines.append("Final summary")
    lines.append(state.final_summary or "Pending generated Elenchos summary.")
    lines.append("")
    lines.append("Claim boundary")
    lines.append(state.claim_boundary or SAFE_FALLBACK_CLAIM_BOUNDARY)
    if state.errors:
        lines.append("")
        lines.append("Parser warnings")
        lines.extend(f"- {error}" for error in state.errors[-5:])
    if state.openclaw_log_tail:
        lines.append("")
        lines.append("OpenClaw log tail")
        lines.extend(f"- {line}" for line in state.openclaw_log_tail)
    return "\n".join(lines) + "\n"
