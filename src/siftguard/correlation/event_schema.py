from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

JSON_SCALAR = str | int | float | bool | None

VALID_PARSER_EVENT_TYPES = {
    "file_created",
    "file_modified",
    "file_accessed",
    "file_record",
    "registry_run_key",
    "registry_userassist_program_use",
    "registry_recent_document_candidate",
    "registry_opensave_file_candidate",
    "registry_lastvisited_program_candidate",
    "registry_typed_path_candidate",
    "amcache_execution",
    "unknown",
}

VALID_ARTIFACT_TYPES = {
    "mft",
    "registry",
    "amcache",
    "userassist",
    "recentdocs",
    "opensavepidlmru",
    "lastvisitedpidlmru",
    "typedpaths",
    "unknown",
}
VALID_PARSER_NAMES = {"mftecmd", "recmd", "amcacheparser", "unknown"}
VALID_PARSER_EVENT_STATUSES = {"observed", "normalized", "malformed", "skipped"}
VALID_PARSER_EVENT_CONFIDENCE = {
    "tool_reported",
    "normalized",
    "inferred_from_parser_output",
    "unknown",
}


@dataclass(slots=True)
class TimelineEvent:
    timestamp_utc: str
    event_type: str
    description: str
    artifact_id: str | None = None


def _utc_timestamp(value: datetime | str | None) -> str | None:
    if value is None:
        return None

    if isinstance(value, datetime):
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timestamp_utc datetime must be timezone-aware")
        return (
            value.astimezone(timezone.utc)
            .isoformat(timespec="seconds")
            .replace("+00:00", "Z")
        )

    if not isinstance(value, str):
        raise TypeError("timestamp_utc must be a datetime, string, or None")
    if not value:
        raise ValueError("timestamp_utc must not be empty when provided")
    if value.endswith("+00:00"):
        return value[:-6] + "Z"
    if not value.endswith("Z"):
        raise ValueError("timestamp_utc string must use explicit UTC with trailing Z")
    return value


def _validate_string_list(name: str, values: list[str]) -> list[str]:
    if not isinstance(values, list):
        raise TypeError(f"{name} must be a list of strings")
    if not values:
        raise ValueError(f"{name} must not be empty")
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


@dataclass(slots=True)
class RawRecordRef:
    source_path: str | None = None
    row_number: int | None = None
    record_id: str | None = None
    byte_offset: int | None = None
    notes: str | None = None

    def __post_init__(self) -> None:
        if self.row_number is not None and self.row_number <= 0:
            raise ValueError("row_number must be positive when provided")
        if self.byte_offset is not None and self.byte_offset < 0:
            raise ValueError("byte_offset must not be negative when provided")

    def to_dict(self) -> dict[str, int | str | None]:
        return {
            "source_path": self.source_path,
            "row_number": self.row_number,
            "record_id": self.record_id,
            "byte_offset": self.byte_offset,
            "notes": self.notes,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RawRecordRef:
        return cls(
            source_path=data.get("source_path"),
            row_number=data.get("row_number"),
            record_id=data.get("record_id"),
            byte_offset=data.get("byte_offset"),
            notes=data.get("notes"),
        )


@dataclass(slots=True)
class ParserEvent:
    case_id: str
    artifact_id: str
    artifact_type: str
    parser_name: str
    source_tool: str
    event_type: str
    evidence_refs: list[str]
    event_id: str = ""
    timestamp_utc: datetime | str | None = None
    timestamp_description: str | None = None
    subject: str | None = None
    path: str | None = None
    key_path: str | None = None
    value_name: str | None = None
    value_data: str | None = None
    sha256: str | None = None
    raw_record_ref: RawRecordRef | dict[str, Any] | None = None
    status: str = "observed"
    confidence: str = "tool_reported"
    metadata: dict[str, JSON_SCALAR] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for field_name in (
            "case_id",
            "artifact_id",
            "artifact_type",
            "parser_name",
            "source_tool",
            "event_type",
            "status",
            "confidence",
        ):
            value = getattr(self, field_name)
            if not isinstance(value, str) or not value:
                raise ValueError(f"{field_name} must be a non-empty string")

        if self.artifact_type not in VALID_ARTIFACT_TYPES:
            raise ValueError(f"invalid artifact_type: {self.artifact_type}")
        if self.parser_name not in VALID_PARSER_NAMES:
            raise ValueError(f"invalid parser_name: {self.parser_name}")
        if self.event_type not in VALID_PARSER_EVENT_TYPES:
            raise ValueError(f"invalid event_type: {self.event_type}")
        if self.status not in VALID_PARSER_EVENT_STATUSES:
            raise ValueError(f"invalid status: {self.status}")
        if self.confidence not in VALID_PARSER_EVENT_CONFIDENCE:
            raise ValueError(f"invalid confidence: {self.confidence}")

        self.evidence_refs = _validate_string_list("evidence_refs", self.evidence_refs)
        self.timestamp_utc = _utc_timestamp(self.timestamp_utc)

        if isinstance(self.raw_record_ref, dict):
            self.raw_record_ref = RawRecordRef.from_dict(self.raw_record_ref)
        elif self.raw_record_ref is not None and not isinstance(self.raw_record_ref, RawRecordRef):
            raise TypeError("raw_record_ref must be RawRecordRef, dict, or None")

        self.metadata = _validate_metadata(self.metadata)
        if not self.event_id:
            self.event_id = deterministic_parser_event_id(self)

    def to_dict(self) -> dict[str, Any]:
        raw_record_ref = (
            self.raw_record_ref.to_dict()
            if isinstance(self.raw_record_ref, RawRecordRef)
            else self.raw_record_ref
        )
        payload: dict[str, Any] = {
            "event_id": self.event_id,
            "case_id": self.case_id,
            "artifact_id": self.artifact_id,
            "artifact_type": self.artifact_type,
            "parser_name": self.parser_name,
            "source_tool": self.source_tool,
            "event_type": self.event_type,
            "timestamp_utc": self.timestamp_utc,
            "timestamp_description": self.timestamp_description,
            "subject": self.subject,
            "path": self.path,
            "key_path": self.key_path,
            "value_name": self.value_name,
            "value_data": self.value_data,
            "sha256": self.sha256,
            "evidence_refs": list(self.evidence_refs),
            "raw_record_ref": raw_record_ref,
            "status": self.status,
            "confidence": self.confidence,
            "metadata": dict(self.metadata),
        }
        for key in (
            "artifact_family",
            "source_artifact_id",
            "source_id",
            "source_role",
            "registry_hive_path",
            "registry_key_path",
            "decoded_value",
            "target",
            "timestamp_kind",
            "user_sid",
            "user_hint",
            "evidence_ref",
            "parser_status",
            "confidence_basis",
            "interpretation_note",
        ):
            if key in self.metadata:
                payload[key] = self.metadata[key]
        return payload

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ParserEvent:
        payload = dict(data)
        return cls(
            case_id=payload["case_id"],
            artifact_id=payload["artifact_id"],
            artifact_type=payload["artifact_type"],
            parser_name=payload["parser_name"],
            source_tool=payload["source_tool"],
            event_type=payload["event_type"],
            evidence_refs=list(payload["evidence_refs"]),
            event_id=payload.get("event_id", ""),
            timestamp_utc=payload.get("timestamp_utc"),
            timestamp_description=payload.get("timestamp_description"),
            subject=payload.get("subject"),
            path=payload.get("path"),
            key_path=payload.get("key_path"),
            value_name=payload.get("value_name"),
            value_data=payload.get("value_data"),
            sha256=payload.get("sha256"),
            raw_record_ref=payload.get("raw_record_ref"),
            status=payload.get("status", "observed"),
            confidence=payload.get("confidence", "tool_reported"),
            metadata=payload.get("metadata", {}),
        )


def deterministic_parser_event_id(event: ParserEvent) -> str:
    if isinstance(event.raw_record_ref, RawRecordRef):
        raw_record_ref = event.raw_record_ref.to_dict()
    elif isinstance(event.raw_record_ref, dict):
        raw_record_ref = event.raw_record_ref
    else:
        raw_record_ref = None
    payload = {
        "case_id": event.case_id,
        "artifact_id": event.artifact_id,
        "artifact_type": event.artifact_type,
        "parser_name": event.parser_name,
        "source_tool": event.source_tool,
        "event_type": event.event_type,
        "timestamp_utc": event.timestamp_utc,
        "timestamp_description": event.timestamp_description,
        "subject": event.subject,
        "path": event.path,
        "key_path": event.key_path,
        "value_name": event.value_name,
        "value_data": event.value_data,
        "sha256": event.sha256,
        "raw_record_ref": raw_record_ref,
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    digest = hashlib.sha256(encoded).hexdigest()[:24]
    return f"parser_event_{digest}"
