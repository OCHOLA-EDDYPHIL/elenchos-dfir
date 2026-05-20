from __future__ import annotations

from dataclasses import dataclass, field

VALID_STATUSES = {"confirmed", "inferred", "rejected", "needs_review"}
VALID_CONFIDENCE = {"high", "medium", "low"}


@dataclass(slots=True)
class EvidenceRef:
    artifact_id: str
    parser: str | None = None
    source_path: str | None = None


@dataclass(slots=True)
class Finding:
    finding_id: str
    case_id: str
    type: str
    status: str
    confidence: str
    summary: str
    evidence_refs: list[EvidenceRef] = field(default_factory=list)
    inference: bool = False

    def __post_init__(self) -> None:
        if self.status not in VALID_STATUSES:
            raise ValueError(f"invalid status: {self.status}")
        if self.confidence not in VALID_CONFIDENCE:
            raise ValueError(f"invalid confidence: {self.confidence}")
