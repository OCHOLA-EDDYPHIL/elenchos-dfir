from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ClaimStatus(str, Enum):
    CONFIRMED = "confirmed"
    INFERRED = "inferred"
    REJECTED = "rejected"
    NEEDS_REVIEW = "needs_review"


class Confidence(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class FindingKind(str, Enum):
    OBSERVATION = "observation"
    CONCLUSION = "conclusion"


def _coerce_claim_status(value: ClaimStatus | str) -> ClaimStatus:
    try:
        return ClaimStatus(value)
    except ValueError as exc:
        raise ValueError(f"invalid status: {value}") from exc


def _coerce_confidence(value: Confidence | str) -> Confidence:
    try:
        return Confidence(value)
    except ValueError as exc:
        raise ValueError(f"invalid confidence: {value}") from exc


def _coerce_finding_kind(value: FindingKind | str) -> FindingKind:
    try:
        return FindingKind(value)
    except ValueError as exc:
        raise ValueError(f"invalid kind: {value}") from exc


def _validate_required_string(name: str, value: str | None) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} must be a non-empty string")
    return value


def _validate_optional_string(name: str, value: str | None) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} must be a non-empty string when provided")
    return value


def _validate_string_list(name: str, values: list[str]) -> list[str]:
    if not isinstance(values, list):
        raise TypeError(f"{name} must be a list of strings")
    if not all(isinstance(item, str) and item for item in values):
        raise ValueError(f"{name} must contain only non-empty strings")
    return values


def _limitations_document_missing_hashes(limitations: list[str]) -> bool:
    return any("hash" in limitation.lower() for limitation in limitations)


@dataclass(slots=True)
class EvidenceRef:
    parser: str
    source: str
    evidence_id: str | None = None
    artifact_id: str | None = None
    raw_record_ref: str | None = None
    timestamp_field: str | None = None
    description: str | None = None

    def __post_init__(self) -> None:
        self.parser = _validate_required_string("parser", self.parser)
        self.source = _validate_required_string("source", self.source)
        self.evidence_id = _validate_optional_string("evidence_id", self.evidence_id)
        self.artifact_id = _validate_optional_string("artifact_id", self.artifact_id)
        self.raw_record_ref = _validate_optional_string("raw_record_ref", self.raw_record_ref)
        self.timestamp_field = _validate_optional_string("timestamp_field", self.timestamp_field)
        self.description = _validate_optional_string("description", self.description)

        if self.evidence_id is None and self.artifact_id is None:
            raise ValueError("evidence_id or artifact_id must be provided")

    def to_dict(self) -> dict[str, str | None]:
        return {
            "evidence_id": self.evidence_id,
            "artifact_id": self.artifact_id,
            "parser": self.parser,
            "source": self.source,
            "raw_record_ref": self.raw_record_ref,
            "timestamp_field": self.timestamp_field,
            "description": self.description,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EvidenceRef:
        return cls(
            evidence_id=data.get("evidence_id"),
            artifact_id=data.get("artifact_id"),
            parser=data["parser"],
            source=data["source"],
            raw_record_ref=data.get("raw_record_ref"),
            timestamp_field=data.get("timestamp_field"),
            description=data.get("description"),
        )


@dataclass(slots=True)
class Finding:
    finding_id: str
    claim: str
    status: ClaimStatus
    confidence: Confidence
    kind: FindingKind
    evidence_refs: list[EvidenceRef] = field(default_factory=list)
    audit_event_refs: list[str] = field(default_factory=list)
    artifact_hashes: list[str] = field(default_factory=list)
    raw_record_refs: list[str] = field(default_factory=list)
    rationale: str = ""
    limitations: list[str] = field(default_factory=list)
    supports_final_report: bool = field(init=False)

    def __post_init__(self) -> None:
        self.finding_id = _validate_required_string("finding_id", self.finding_id)
        self.claim = _validate_required_string("claim", self.claim)
        self.status = _coerce_claim_status(self.status)
        self.confidence = _coerce_confidence(self.confidence)
        self.kind = _coerce_finding_kind(self.kind)
        self.evidence_refs = self._validate_evidence_refs(self.evidence_refs)
        self.audit_event_refs = _validate_string_list("audit_event_refs", self.audit_event_refs)
        self.artifact_hashes = _validate_string_list("artifact_hashes", self.artifact_hashes)
        self.raw_record_refs = _validate_string_list("raw_record_refs", self.raw_record_refs)
        self.rationale = self._validate_rationale()
        self.limitations = _validate_string_list("limitations", self.limitations)

        self._validate_claim_support()
        self.supports_final_report = self._supports_final_report()

    @staticmethod
    def _validate_evidence_refs(values: list[EvidenceRef]) -> list[EvidenceRef]:
        if not isinstance(values, list):
            raise TypeError("evidence_refs must be a list of EvidenceRef instances")
        if not all(isinstance(item, EvidenceRef) for item in values):
            raise TypeError("evidence_refs must contain only EvidenceRef instances")
        return values

    def _validate_rationale(self) -> str:
        if not isinstance(self.rationale, str):
            raise TypeError("rationale must be a string")
        if self.status in {
            ClaimStatus.CONFIRMED,
            ClaimStatus.INFERRED,
            ClaimStatus.REJECTED,
        } and not self.rationale:
            raise ValueError(f"{self.status.value} finding requires non-empty rationale")
        return self.rationale

    def _has_raw_record_support(self) -> bool:
        return bool(self.raw_record_refs) or any(ref.raw_record_ref for ref in self.evidence_refs)

    def _has_artifact_hash_support(self) -> bool:
        return bool(self.artifact_hashes) or _limitations_document_missing_hashes(self.limitations)

    def _validate_claim_support(self) -> None:
        if self.status is ClaimStatus.CONFIRMED:
            if not self.evidence_refs:
                raise ValueError("confirmed finding requires at least one evidence reference")
            if not self._has_raw_record_support():
                raise ValueError("confirmed finding requires at least one raw record reference")
            if not self._has_artifact_hash_support():
                raise ValueError(
                    "confirmed finding requires artifact hashes or a hash limitation"
                )

        if self.status is ClaimStatus.INFERRED and not self.evidence_refs:
            raise ValueError("inferred finding requires at least one evidence reference")

    def _supports_final_report(self) -> bool:
        if self.status is ClaimStatus.CONFIRMED:
            return bool(
                self.evidence_refs
                and self.rationale
                and self._has_raw_record_support()
                and self._has_artifact_hash_support()
            )
        if self.status is ClaimStatus.INFERRED:
            return bool(self.evidence_refs and self.rationale)
        return False

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "claim": self.claim,
            "status": self.status.value,
            "confidence": self.confidence.value,
            "kind": self.kind.value,
            "evidence_refs": [ref.to_dict() for ref in self.evidence_refs],
            "audit_event_refs": list(self.audit_event_refs),
            "artifact_hashes": list(self.artifact_hashes),
            "raw_record_refs": list(self.raw_record_refs),
            "rationale": self.rationale,
            "limitations": list(self.limitations),
            "supports_final_report": self.supports_final_report,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Finding:
        return cls(
            finding_id=data["finding_id"],
            claim=data["claim"],
            status=data["status"],
            confidence=data["confidence"],
            kind=data["kind"],
            evidence_refs=[
                EvidenceRef.from_dict(ref) for ref in data.get("evidence_refs", [])
            ],
            audit_event_refs=list(data.get("audit_event_refs", [])),
            artifact_hashes=list(data.get("artifact_hashes", [])),
            raw_record_refs=list(data.get("raw_record_refs", [])),
            rationale=data.get("rationale", ""),
            limitations=list(data.get("limitations", [])),
        )
