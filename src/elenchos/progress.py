from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from elenchos.audit.execution_ledger import utc_now

ALLOWED_PROGRESS_PHASES = {
    "prepare_case",
    "run_case",
    "normalize/select",
    "report",
    "summarize_run",
    "validate_run_outputs",
    "emit_claim_boundary",
}
ALLOWED_PROGRESS_STATUSES = {
    "started",
    "completed",
    "failed",
    "partial_success",
    "needs_review",
}
PROGRESS_FILENAME = "progress.jsonl"

_PRIVATE_HASH_PATTERN = re.compile(r"\b(?:sha256:)?[a-fA-F0-9]{64}\b")
_SECRET_PATTERN = re.compile(
    r"(?i)\b(?:api[_-]?key|authorization|bearer|password|secret|token)\b"
)
_RAW_ROW_PATTERN = re.compile(r"[{}]|\[[^\]]+\]|(?:[^,\n]+,){3,}[^,\n]+")


@dataclass(frozen=True, slots=True)
class ProgressEvent:
    timestamp: str
    case_id: str
    phase: str
    status: str
    message: str

    def to_dict(self) -> dict[str, str]:
        return {
            "timestamp": self.timestamp,
            "case_id": self.case_id,
            "phase": self.phase,
            "status": self.status,
            "message": self.message,
        }


def _require_string(name: str, value: object) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} must be a non-empty string")
    return value


def validate_progress_message(message: str) -> str:
    message = _require_string("message", message).strip()
    if len(message) > 240:
        raise ValueError("progress message must be 240 characters or fewer")
    if _PRIVATE_HASH_PATTERN.search(message):
        raise ValueError("progress message must not include private hashes")
    if _SECRET_PATTERN.search(message):
        raise ValueError("progress message must not include secrets")
    if _RAW_ROW_PATTERN.search(message):
        raise ValueError("progress message must not include raw parser rows")
    return message


def make_progress_event(
    *,
    case_id: str,
    phase: str,
    status: str,
    message: str,
    timestamp: str | None = None,
) -> ProgressEvent:
    case_id = _require_string("case_id", case_id)
    if phase not in ALLOWED_PROGRESS_PHASES:
        raise ValueError(f"invalid progress phase: {phase}")
    if status not in ALLOWED_PROGRESS_STATUSES:
        raise ValueError(f"invalid progress status: {status}")
    event_timestamp = timestamp or utc_now()
    if not event_timestamp.endswith("Z"):
        raise ValueError("timestamp must end with Z")
    return ProgressEvent(
        timestamp=event_timestamp,
        case_id=case_id,
        phase=phase,
        status=status,
        message=validate_progress_message(message),
    )


def append_progress_event(
    progress_path: Path,
    *,
    case_id: str,
    phase: str,
    status: str,
    message: str,
    timestamp: str | None = None,
) -> ProgressEvent:
    event = make_progress_event(
        case_id=case_id,
        phase=phase,
        status=status,
        message=message,
        timestamp=timestamp,
    )
    progress_path.parent.mkdir(parents=True, exist_ok=True)
    with progress_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event.to_dict(), sort_keys=True))
        handle.write("\n")
    return event


def progress_path_for_output_dir(output_dir: Path) -> Path:
    return output_dir / PROGRESS_FILENAME


def progress_display_rows(events: list[ProgressEvent]) -> list[dict[str, str]]:
    return [event.to_dict() for event in events]


def progress_event_from_mapping(payload: Mapping[str, Any]) -> ProgressEvent:
    expected = {"timestamp", "case_id", "phase", "status", "message"}
    if set(payload) != expected:
        raise ValueError("progress event must contain exactly required fields")
    return make_progress_event(
        timestamp=_require_string("timestamp", payload["timestamp"]),
        case_id=_require_string("case_id", payload["case_id"]),
        phase=_require_string("phase", payload["phase"]),
        status=_require_string("status", payload["status"]),
        message=_require_string("message", payload["message"]),
    )


def read_progress_events(progress_path: Path) -> list[ProgressEvent]:
    if not progress_path.exists():
        return []
    events: list[ProgressEvent] = []
    with progress_path.open("r", encoding="utf-8") as handle:
        for lineno, line in enumerate(handle, 1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                payload = json.loads(stripped)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"Malformed progress JSONL at line {lineno} in '{progress_path}': "
                    f"{exc.msg}"
                ) from exc
            if not isinstance(payload, dict):
                raise ValueError(
                    f"Malformed progress JSONL at line {lineno} in '{progress_path}': "
                    "not an object"
                )
            events.append(progress_event_from_mapping(payload))
    return events
