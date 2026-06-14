from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

JSON_ROW = dict[str, Any]
CASE_WINDOW = tuple[datetime, datetime]

EVENT_SELECTION_FIRST_N = "first-n"
EVENT_SELECTION_FORENSIC_TRIAGE = "forensic-triage"
SUPPORTED_EVENT_SELECTION_PROFILES = {
    EVENT_SELECTION_FIRST_N,
    EVENT_SELECTION_FORENSIC_TRIAGE,
}

SUSPICIOUS_PATH_MARKERS = (
    "temp",
    "downloads",
    "appdata",
    "programdata",
    "startup",
    "tasks",
    "system32",
    "syswow64",
    "users",
    "public",
)
SUSPICIOUS_EXTENSIONS = {
    ".exe",
    ".dll",
    ".ps1",
    ".bat",
    ".cmd",
    ".vbs",
    ".js",
    ".jse",
    ".scr",
    ".msi",
    ".lnk",
    ".zip",
    ".rar",
    ".7z",
}
ANCHOR_WINDOW = timedelta(hours=1)

SELECTION_REASON_ORDER = (
    "anchor_path_selected",
    "suspicious_path_selected",
    "anchor_window_selected",
    "case_window_selected",
    "deterministic_fill_selected",
)
EMPTY_SELECTION_COUNTS = {
    "non_mft_preserved": 0,
    "anchor_path_selected": 0,
    "suspicious_path_selected": 0,
    "anchor_window_selected": 0,
    "case_window_selected": 0,
    "deterministic_fill_selected": 0,
    "dropped_due_to_cap": 0,
}


@dataclass(slots=True)
class TriageAnchors:
    path_keys: set[str] = field(default_factory=set)
    basename_keys: set[str] = field(default_factory=set)
    timestamps: list[datetime] = field(default_factory=list)

    def add_row(self, row: JSON_ROW) -> None:
        path = path_from_event_row(row)
        if path is not None:
            self.path_keys.add(path_key(path))
            basename = basename_key(path)
            if basename is not None:
                self.basename_keys.add(basename)
        timestamp = timestamp_from_row(row)
        if timestamp is not None:
            self.timestamps.append(timestamp)

    def extend_rows(self, rows: list[JSON_ROW]) -> None:
        for row in rows:
            self.add_row(row)


@dataclass(slots=True)
class EventSelectionResult:
    rows: list[JSON_ROW]
    source_events_seen: int
    counts: dict[str, int]
    dropped_due_to_cap: int


def validate_event_selection_profile(value: str | None) -> str:
    profile = value or EVENT_SELECTION_FIRST_N
    if profile not in SUPPORTED_EVENT_SELECTION_PROFILES:
        supported = ", ".join(sorted(SUPPORTED_EVENT_SELECTION_PROFILES))
        raise ValueError(f"event_selection_profile must be one of: {supported}")
    return profile


def path_key(value: str) -> str:
    return value.replace("\\", "/").rstrip("/").casefold()


def basename_key(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = value.replace("\\", "/").rstrip("/")
    if not normalized:
        return None
    return normalized.rsplit("/", 1)[-1].casefold() or None


def path_from_event_row(row: JSON_ROW) -> str | None:
    path = row.get("path")
    if isinstance(path, str) and path:
        return path
    value_data = row.get("value_data")
    if isinstance(value_data, str) and value_data:
        return value_data
    subject = row.get("subject")
    if isinstance(subject, str) and ("/" in subject or "\\" in subject):
        return subject
    return None


def timestamp_from_value(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    text = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def timestamp_from_row(row: JSON_ROW) -> datetime | None:
    return timestamp_from_value(row.get("timestamp_utc") or row.get("timestamp"))


def is_suspicious_path(value: str | None) -> bool:
    if value is None:
        return False
    normalized = path_key(value)
    parts = {part for part in normalized.replace("\\", "/").split("/") if part}
    suffix = Path(normalized).suffix.casefold()
    return bool(parts & set(SUSPICIOUS_PATH_MARKERS)) or suffix in SUSPICIOUS_EXTENSIONS


def classify_selection_reason(
    *,
    path: str | None,
    timestamp: datetime | None,
    anchors: TriageAnchors,
    case_windows: tuple[CASE_WINDOW, ...] = (),
) -> str:
    if path is not None:
        key = path_key(path)
        basename = basename_key(path)
        if key in anchors.path_keys or (basename is not None and basename in anchors.basename_keys):
            return "anchor_path_selected"
    if is_suspicious_path(path):
        return "suspicious_path_selected"
    if timestamp is not None and any(
        abs(timestamp - anchor) <= ANCHOR_WINDOW for anchor in anchors.timestamps
    ):
        return "anchor_window_selected"
    if timestamp is not None and any(start <= timestamp <= end for start, end in case_windows):
        return "case_window_selected"
    return "deterministic_fill_selected"


def empty_selection_counts() -> dict[str, int]:
    return dict(EMPTY_SELECTION_COUNTS)


def select_event_rows_for_triage(
    rows: list[JSON_ROW],
    *,
    max_events: int | None,
    anchors: TriageAnchors,
    case_windows: tuple[CASE_WINDOW, ...] = (),
) -> EventSelectionResult:
    if max_events is None:
        return EventSelectionResult(
            rows=list(rows),
            source_events_seen=len(rows),
            counts={
                **empty_selection_counts(),
                "deterministic_fill_selected": len(rows),
            },
            dropped_due_to_cap=0,
        )

    buckets: dict[str, list[JSON_ROW]] = {reason: [] for reason in SELECTION_REASON_ORDER}
    for row in rows:
        reason = classify_selection_reason(
            path=path_from_event_row(row),
            timestamp=timestamp_from_row(row),
            anchors=anchors,
            case_windows=case_windows,
        )
        if len(buckets[reason]) < max_events:
            buckets[reason].append(row)

    selected: list[JSON_ROW] = []
    counts = empty_selection_counts()
    for reason in SELECTION_REASON_ORDER:
        available = max_events - len(selected)
        if available <= 0:
            break
        chunk = buckets[reason][:available]
        selected.extend(chunk)
        counts[reason] += len(chunk)

    dropped = max(len(rows) - len(selected), 0)
    counts["dropped_due_to_cap"] = dropped
    return EventSelectionResult(
        rows=selected,
        source_events_seen=len(rows),
        counts=counts,
        dropped_due_to_cap=dropped,
    )
