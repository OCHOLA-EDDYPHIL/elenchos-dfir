from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True)
class TimelineEvent:
    timestamp_utc: str
    event_type: str
    description: str
    artifact_id: str | None = None
