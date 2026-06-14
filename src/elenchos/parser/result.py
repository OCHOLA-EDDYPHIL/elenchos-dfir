from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from elenchos.correlation.event_schema import JSON_SCALAR, ParserEvent

VALID_PARSER_RESULT_STATUSES = {"success", "partial_success", "skipped", "failed"}


def _utc_timestamp(value: datetime | str | None) -> str | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timestamp datetime must be timezone-aware")
        return (
            value.astimezone(timezone.utc)
            .isoformat(timespec="seconds")
            .replace("+00:00", "Z")
        )
    if not isinstance(value, str):
        raise TypeError("timestamp must be a datetime, string, or None")
    if not value:
        raise ValueError("timestamp must not be empty when provided")
    if value.endswith("+00:00"):
        return value[:-6] + "Z"
    if not value.endswith("Z"):
        raise ValueError("timestamp string must use explicit UTC with trailing Z")
    return value


def _validate_string_list(name: str, values: list[str]) -> list[str]:
    if not isinstance(values, list):
        raise TypeError(f"{name} must be a list of strings")
    if not all(isinstance(item, str) and item for item in values):
        raise ValueError(f"{name} must contain only non-empty strings")
    return values


def _validate_metadata(metadata: dict[str, JSON_SCALAR]) -> dict[str, JSON_SCALAR]:
    if not isinstance(metadata, dict):
        raise TypeError("metadata must be a dictionary")
    for key, value in metadata.items():
        if not isinstance(key, str) or not key:
            raise ValueError("metadata keys must be non-empty strings")
        if not isinstance(value, (str, int, float, bool, type(None))):
            raise TypeError("metadata values must be JSON scalar values")
    return metadata


def _validate_coverage_gaps(
    coverage_gaps: list[dict[str, JSON_SCALAR]],
) -> list[dict[str, JSON_SCALAR]]:
    if not isinstance(coverage_gaps, list):
        raise TypeError("coverage_gaps must be a list of dictionaries")
    checked: list[dict[str, JSON_SCALAR]] = []
    for gap in coverage_gaps:
        if not isinstance(gap, dict):
            raise TypeError("coverage_gaps must contain only dictionaries")
        checked_gap: dict[str, JSON_SCALAR] = {}
        for key, value in gap.items():
            if not isinstance(key, str) or not key:
                raise ValueError("coverage_gaps keys must be non-empty strings")
            if not isinstance(value, (str, int, float, bool, type(None))):
                raise TypeError("coverage_gaps values must be JSON scalar values")
            checked_gap[key] = value
        checked.append(checked_gap)
    return checked


def _normalize_command(command: Sequence[str] | None) -> tuple[str, ...] | None:
    if command is None:
        return None
    if isinstance(command, str):
        raise TypeError("command must be an argv sequence, not a shell string")
    if not isinstance(command, Sequence):
        raise TypeError("command must be a sequence of strings")
    if not all(isinstance(item, str) and item for item in command):
        raise ValueError("command must contain only non-empty strings")
    return tuple(command)


@dataclass(slots=True)
class ParserResult:
    case_id: str
    artifact_id: str
    artifact_type: str
    parser_name: str
    source_tool: str
    status: str
    command: Sequence[str] | None = None
    output_dir: str | None = None
    output_files: list[str] = field(default_factory=list)
    output_hashes: dict[str, str] = field(default_factory=dict)
    audit_event_ids: list[str] = field(default_factory=list)
    events: list[ParserEvent] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    coverage_gaps: list[dict[str, JSON_SCALAR]] = field(default_factory=list)
    started_at_utc: datetime | str | None = None
    ended_at_utc: datetime | str | None = None
    duration_ms: int | None = None
    tool_version: str | None = None
    metadata: dict[str, JSON_SCALAR] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for field_name in (
            "case_id",
            "artifact_id",
            "artifact_type",
            "parser_name",
            "source_tool",
            "status",
        ):
            value = getattr(self, field_name)
            if not isinstance(value, str) or not value:
                raise ValueError(f"{field_name} must be a non-empty string")

        if self.status not in VALID_PARSER_RESULT_STATUSES:
            raise ValueError(f"invalid parser result status: {self.status}")

        self.command = _normalize_command(self.command)
        self.output_files = _validate_string_list("output_files", self.output_files)
        self.audit_event_ids = _validate_string_list("audit_event_ids", self.audit_event_ids)
        self.warnings = _validate_string_list("warnings", self.warnings)
        self.errors = _validate_string_list("errors", self.errors)
        self.coverage_gaps = _validate_coverage_gaps(self.coverage_gaps)
        if not all(isinstance(event, ParserEvent) for event in self.events):
            raise TypeError("events must contain only ParserEvent instances")
        if not isinstance(self.output_hashes, dict):
            raise TypeError("output_hashes must be a dictionary")
        for key, value in self.output_hashes.items():
            if not isinstance(key, str) or not key:
                raise ValueError("output_hashes keys must be non-empty strings")
            if not isinstance(value, str) or not value:
                raise ValueError("output_hashes values must be non-empty strings")

        self.started_at_utc = _utc_timestamp(self.started_at_utc)
        self.ended_at_utc = _utc_timestamp(self.ended_at_utc)
        if self.duration_ms is not None and self.duration_ms < 0:
            raise ValueError("duration_ms must not be negative")
        self.metadata = _validate_metadata(self.metadata)

    @property
    def source_artifact_id(self) -> str:
        return self.artifact_id

    @property
    def output_paths(self) -> list[str]:
        return list(self.output_files)

    @property
    def normalized_events(self) -> list[ParserEvent]:
        return list(self.events)

    @classmethod
    def missing_command(
        cls,
        *,
        case_id: str,
        artifact_id: str,
        artifact_type: str,
        parser_name: str,
        source_tool: str,
        reason: str,
        coverage_gaps: list[dict[str, JSON_SCALAR]] | None = None,
    ) -> ParserResult:
        return cls(
            case_id=case_id,
            artifact_id=artifact_id,
            artifact_type=artifact_type,
            parser_name=parser_name,
            source_tool=source_tool,
            status="skipped",
            command=None,
            errors=[reason],
            coverage_gaps=list(coverage_gaps or []),
        )

    def to_dict(self) -> dict[str, Any]:
        event_dicts = [event.to_dict() for event in self.events]
        return {
            "case_id": self.case_id,
            "artifact_id": self.artifact_id,
            "source_artifact_id": self.source_artifact_id,
            "artifact_type": self.artifact_type,
            "parser_name": self.parser_name,
            "source_tool": self.source_tool,
            "status": self.status,
            "command": list(self.command) if self.command is not None else None,
            "output_dir": self.output_dir,
            "output_files": list(self.output_files),
            "output_paths": self.output_paths,
            "output_hashes": dict(self.output_hashes),
            "audit_event_ids": list(self.audit_event_ids),
            "events": event_dicts,
            "normalized_events": event_dicts,
            "warnings": list(self.warnings),
            "errors": list(self.errors),
            "coverage_gaps": [dict(gap) for gap in self.coverage_gaps],
            "started_at_utc": self.started_at_utc,
            "ended_at_utc": self.ended_at_utc,
            "duration_ms": self.duration_ms,
            "tool_version": self.tool_version,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ParserResult:
        event_rows = data.get("events", data.get("normalized_events", []))
        artifact_id = data.get("artifact_id", data.get("source_artifact_id"))
        if not isinstance(artifact_id, str):
            raise ValueError("artifact_id or source_artifact_id must be present")
        raw_coverage_gaps = data.get("coverage_gaps", [])
        if not isinstance(raw_coverage_gaps, list):
            raw_coverage_gaps = []
        return cls(
            case_id=data["case_id"],
            artifact_id=artifact_id,
            artifact_type=data["artifact_type"],
            parser_name=data["parser_name"],
            source_tool=data["source_tool"],
            status=data["status"],
            command=data.get("command"),
            output_dir=data.get("output_dir"),
            output_files=list(data.get("output_files", data.get("output_paths", []))),
            output_hashes=dict(data.get("output_hashes", {})),
            audit_event_ids=list(data.get("audit_event_ids", [])),
            events=[ParserEvent.from_dict(row) for row in event_rows],
            warnings=list(data.get("warnings", [])),
            errors=list(data.get("errors", [])),
            coverage_gaps=[
                dict(gap)
                for gap in raw_coverage_gaps
                if isinstance(gap, dict)
            ],
            started_at_utc=data.get("started_at_utc"),
            ended_at_utc=data.get("ended_at_utc"),
            duration_ms=data.get("duration_ms"),
            tool_version=data.get("tool_version"),
            metadata=dict(data.get("metadata", {})),
        )
