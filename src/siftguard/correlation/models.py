from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from siftguard.validation.models import EvidenceRef

JSON_SCALAR = str | int | float | bool | None


class TimelineEventType(str, Enum):
    DROP = "drop"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    OBSERVATION = "observation"


def _coerce_event_type(value: TimelineEventType | str) -> TimelineEventType:
    try:
        return TimelineEventType(value)
    except ValueError as exc:
        raise ValueError(f"invalid event_type: {value}") from exc


def _validate_optional_string(name: str, value: str | None) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} must be a non-empty string when provided")
    return value


def _validate_required_string(name: str, value: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} must be a non-empty string")
    return value


def _validate_details(details: dict[str, JSON_SCALAR]) -> dict[str, JSON_SCALAR]:
    if not isinstance(details, dict):
        raise TypeError("details must be a dictionary")
    for key, value in details.items():
        if not isinstance(key, str) or not key:
            raise ValueError("details keys must be non-empty strings")
        if not isinstance(value, (str, int, float, bool, type(None))):
            raise TypeError("details values must be JSON scalar values")
    return details


def _validate_evidence_refs(evidence_refs: list[EvidenceRef]) -> list[EvidenceRef]:
    if not isinstance(evidence_refs, list):
        raise TypeError("evidence_refs must be a list of EvidenceRef instances")
    if not all(isinstance(item, EvidenceRef) for item in evidence_refs):
        raise TypeError("evidence_refs must contain only EvidenceRef instances")
    return evidence_refs


@dataclass(slots=True)
class TimelineEvent:
    event_type: TimelineEventType
    timestamp: str | None
    subject: str | None
    source: str
    details: dict[str, JSON_SCALAR] = field(default_factory=dict)
    evidence_refs: list[EvidenceRef] = field(default_factory=list)
    path: str | None = None
    basename: str | None = None
    ambiguous: bool = False
    ambiguity_reason: str | None = None

    def __post_init__(self) -> None:
        self.event_type = _coerce_event_type(self.event_type)
        self.timestamp = _validate_optional_string("timestamp", self.timestamp)
        self.subject = _validate_optional_string("subject", self.subject)
        self.source = _validate_required_string("source", self.source)
        self.details = _validate_details(self.details)
        self.evidence_refs = _validate_evidence_refs(self.evidence_refs)
        self.path = _validate_optional_string("path", self.path)
        self.basename = _validate_optional_string("basename", self.basename)
        if not isinstance(self.ambiguous, bool):
            raise TypeError("ambiguous must be a boolean")
        self.ambiguity_reason = _validate_optional_string(
            "ambiguity_reason", self.ambiguity_reason
        )

    def sort_key(self) -> tuple[bool, str, str, str, str, str, str, str]:
        details_key = json.dumps(self.details, sort_keys=True, separators=(",", ":"))
        evidence_key = json.dumps(
            [ref.to_dict() for ref in self.evidence_refs],
            sort_keys=True,
            separators=(",", ":"),
        )
        return (
            self.timestamp is None,
            self.timestamp or "",
            self.event_type.value,
            self.source,
            details_key,
            self.subject or "",
            self.path or self.basename or "",
            evidence_key,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_type": self.event_type.value,
            "timestamp": self.timestamp,
            "subject": self.subject,
            "source": self.source,
            "details": dict(self.details),
            "evidence_refs": [ref.to_dict() for ref in self.evidence_refs],
            "path": self.path,
            "basename": self.basename,
            "ambiguous": self.ambiguous,
            "ambiguity_reason": self.ambiguity_reason,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TimelineEvent:
        return cls(
            event_type=data["event_type"],
            timestamp=data.get("timestamp"),
            subject=data.get("subject"),
            source=data["source"],
            details=dict(data.get("details", {})),
            evidence_refs=[
                EvidenceRef.from_dict(ref) for ref in data.get("evidence_refs", [])
            ],
            path=data.get("path"),
            basename=data.get("basename"),
            ambiguous=bool(data.get("ambiguous", False)),
            ambiguity_reason=data.get("ambiguity_reason"),
        )


@dataclass(slots=True)
class SubjectTimeline:
    subject: str
    events: list[TimelineEvent] = field(default_factory=list)
    ambiguous: bool = False
    ambiguity_reason: str | None = None

    def __post_init__(self) -> None:
        self.subject = _validate_required_string("subject", self.subject)
        if not isinstance(self.events, list):
            raise TypeError("events must be a list of TimelineEvent instances")
        if not all(isinstance(event, TimelineEvent) for event in self.events):
            raise TypeError("events must contain only TimelineEvent instances")
        self.events = sorted(self.events, key=lambda event: event.sort_key())
        if not isinstance(self.ambiguous, bool):
            raise TypeError("ambiguous must be a boolean")
        self.ambiguity_reason = _validate_optional_string(
            "ambiguity_reason", self.ambiguity_reason
        )

    def collect_evidence_refs(self) -> list[EvidenceRef]:
        refs: list[EvidenceRef] = []
        seen: set[str] = set()
        for event in self.events:
            for ref in event.evidence_refs:
                key = json.dumps(ref.to_dict(), sort_keys=True, separators=(",", ":"))
                if key in seen:
                    continue
                seen.add(key)
                refs.append(ref)
        return refs

    def to_dict(self) -> dict[str, Any]:
        return {
            "subject": self.subject,
            "ambiguous": self.ambiguous,
            "ambiguity_reason": self.ambiguity_reason,
            "evidence_refs": [ref.to_dict() for ref in self.collect_evidence_refs()],
            "events": [event.to_dict() for event in self.events],
        }
