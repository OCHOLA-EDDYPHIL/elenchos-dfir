from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

from siftguard.correlation.models import SubjectTimeline, TimelineEventType
from siftguard.validation.models import (
    ClaimStatus,
    Confidence,
    EvidenceRef,
    Finding,
    FindingKind,
)


def _coerce_status(value: ClaimStatus | str) -> ClaimStatus:
    try:
        return ClaimStatus(value)
    except ValueError as exc:
        raise ValueError(f"invalid status: {value}") from exc


def _coerce_confidence(value: Confidence | str) -> Confidence:
    try:
        return Confidence(value)
    except ValueError as exc:
        raise ValueError(f"invalid confidence: {value}") from exc


def _coerce_kind(value: FindingKind | str) -> FindingKind:
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


def _validate_evidence_refs(name: str, refs: list[EvidenceRef]) -> list[EvidenceRef]:
    if not isinstance(refs, list):
        raise TypeError(f"{name} must be a list of EvidenceRef instances")
    if not all(isinstance(ref, EvidenceRef) for ref in refs):
        raise TypeError(f"{name} must contain only EvidenceRef instances")
    return refs


def _has_raw_record_support(evidence_refs: list[EvidenceRef], raw_record_refs: list[str]) -> bool:
    return bool(raw_record_refs) or any(ref.raw_record_ref for ref in evidence_refs)


def _has_hash_support(artifact_hashes: list[str], limitations: list[str]) -> bool:
    return bool(artifact_hashes) or any("hash" in limitation.lower() for limitation in limitations)


def _dedupe_evidence_refs(refs: Sequence[EvidenceRef]) -> list[EvidenceRef]:
    deduped: list[EvidenceRef] = []
    seen: set[str] = set()
    for ref in refs:
        key = json.dumps(ref.to_dict(), sort_keys=True, separators=(",", ":"))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(ref)
    return deduped


def _raw_record_refs_from_evidence(evidence_refs: Sequence[EvidenceRef]) -> list[str]:
    refs: list[str] = []
    seen: set[str] = set()
    for evidence_ref in evidence_refs:
        raw_ref = evidence_ref.raw_record_ref
        if raw_ref is None or raw_ref in seen:
            continue
        seen.add(raw_ref)
        refs.append(raw_ref)
    return refs


def _append_unique(values: list[str], value: str | None) -> list[str]:
    if value and value not in values:
        values.append(value)
    return values


@dataclass(slots=True)
class ClaimCandidate:
    finding_id: str
    claim: str
    requested_status: ClaimStatus
    confidence: Confidence
    kind: FindingKind
    evidence_refs: list[EvidenceRef] = field(default_factory=list)
    audit_event_refs: list[str] = field(default_factory=list)
    artifact_hashes: list[str] = field(default_factory=list)
    raw_record_refs: list[str] = field(default_factory=list)
    rationale: str = ""
    limitations: list[str] = field(default_factory=list)
    inference_rule: str | None = None
    contradiction_evidence_refs: list[EvidenceRef] = field(default_factory=list)
    source_timeline_subject: str | None = None
    ambiguous: bool = False
    ambiguity_reason: str | None = None

    def __post_init__(self) -> None:
        self.finding_id = _validate_required_string("finding_id", self.finding_id)
        self.claim = _validate_required_string("claim", self.claim)
        self.requested_status = _coerce_status(self.requested_status)
        self.confidence = _coerce_confidence(self.confidence)
        self.kind = _coerce_kind(self.kind)
        self.evidence_refs = _validate_evidence_refs("evidence_refs", self.evidence_refs)
        self.audit_event_refs = _validate_string_list("audit_event_refs", self.audit_event_refs)
        self.artifact_hashes = _validate_string_list("artifact_hashes", self.artifact_hashes)
        self.raw_record_refs = _validate_string_list("raw_record_refs", self.raw_record_refs)
        if not isinstance(self.rationale, str):
            raise TypeError("rationale must be a string")
        self.limitations = _validate_string_list("limitations", self.limitations)
        self.inference_rule = _validate_optional_string("inference_rule", self.inference_rule)
        self.contradiction_evidence_refs = _validate_evidence_refs(
            "contradiction_evidence_refs",
            self.contradiction_evidence_refs,
        )
        self.source_timeline_subject = _validate_optional_string(
            "source_timeline_subject",
            self.source_timeline_subject,
        )
        if not isinstance(self.ambiguous, bool):
            raise TypeError("ambiguous must be a boolean")
        self.ambiguity_reason = _validate_optional_string(
            "ambiguity_reason",
            self.ambiguity_reason,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "claim": self.claim,
            "requested_status": self.requested_status.value,
            "confidence": self.confidence.value,
            "kind": self.kind.value,
            "evidence_refs": [ref.to_dict() for ref in self.evidence_refs],
            "audit_event_refs": list(self.audit_event_refs),
            "artifact_hashes": list(self.artifact_hashes),
            "raw_record_refs": list(self.raw_record_refs),
            "rationale": self.rationale,
            "limitations": list(self.limitations),
            "inference_rule": self.inference_rule,
            "contradiction_evidence_refs": [
                ref.to_dict() for ref in self.contradiction_evidence_refs
            ],
            "source_timeline_subject": self.source_timeline_subject,
            "ambiguous": self.ambiguous,
            "ambiguity_reason": self.ambiguity_reason,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ClaimCandidate:
        return cls(
            finding_id=data["finding_id"],
            claim=data["claim"],
            requested_status=data["requested_status"],
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
            inference_rule=data.get("inference_rule"),
            contradiction_evidence_refs=[
                EvidenceRef.from_dict(ref)
                for ref in data.get("contradiction_evidence_refs", [])
            ],
            source_timeline_subject=data.get("source_timeline_subject"),
            ambiguous=bool(data.get("ambiguous", False)),
            ambiguity_reason=data.get("ambiguity_reason"),
        )


@dataclass(slots=True)
class ClaimValidationResult:
    finding: Finding
    original_requested_status: ClaimStatus
    final_status: ClaimStatus
    validation_notes: list[str] = field(default_factory=list)
    downgrade_reason: str | None = None
    rule_name: str | None = None
    contradiction_evidence_refs: list[EvidenceRef] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not isinstance(self.finding, Finding):
            raise TypeError("finding must be a Finding")
        self.original_requested_status = _coerce_status(self.original_requested_status)
        self.final_status = _coerce_status(self.final_status)
        self.validation_notes = _validate_string_list(
            "validation_notes",
            self.validation_notes,
        )
        self.downgrade_reason = _validate_optional_string(
            "downgrade_reason",
            self.downgrade_reason,
        )
        self.rule_name = _validate_optional_string("rule_name", self.rule_name)
        self.contradiction_evidence_refs = _validate_evidence_refs(
            "contradiction_evidence_refs",
            self.contradiction_evidence_refs,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding": self.finding.to_dict(),
            "original_requested_status": self.original_requested_status.value,
            "final_status": self.final_status.value,
            "validation_notes": list(self.validation_notes),
            "downgrade_reason": self.downgrade_reason,
            "rule_name": self.rule_name,
            "contradiction_evidence_refs": [
                ref.to_dict() for ref in self.contradiction_evidence_refs
            ],
        }


def _confirmed_downgrade_reason(candidate: ClaimCandidate) -> str | None:
    missing: list[str] = []
    if not candidate.evidence_refs:
        missing.append("direct evidence references")
    if not _has_raw_record_support(candidate.evidence_refs, candidate.raw_record_refs):
        missing.append("raw record support")
    if not _has_hash_support(candidate.artifact_hashes, candidate.limitations):
        missing.append("artifact hash support")
    if not candidate.rationale:
        missing.append("rationale")
    if missing:
        return "confirmed claim lacks " + ", ".join(missing)
    return None


def _inferred_downgrade_reason(candidate: ClaimCandidate) -> str | None:
    missing: list[str] = []
    if not candidate.evidence_refs:
        missing.append("supporting evidence references")
    if not candidate.rationale:
        missing.append("rationale")
    if not candidate.inference_rule:
        missing.append("inference rule")
    if missing:
        return "inferred claim lacks " + ", ".join(missing)
    return None


def _needs_review_rationale(candidate: ClaimCandidate, downgrade_reason: str | None) -> str:
    if candidate.rationale:
        return candidate.rationale
    if candidate.ambiguous:
        return "Claim requires analyst review because the source evidence is ambiguous."
    if downgrade_reason:
        return f"Claim requires analyst review because {downgrade_reason}."
    return "Claim requires analyst review because supporting evidence is incomplete."


def _decide_status(candidate: ClaimCandidate) -> tuple[ClaimStatus, str | None, str | None]:
    if candidate.ambiguous and candidate.requested_status is not ClaimStatus.REJECTED:
        ambiguity_reason = candidate.ambiguity_reason or "source evidence is ambiguous"
        return ClaimStatus.NEEDS_REVIEW, ambiguity_reason, "ambiguity_review"

    if candidate.requested_status is ClaimStatus.CONFIRMED:
        confirmed_reason = _confirmed_downgrade_reason(candidate)
        if confirmed_reason is not None:
            return ClaimStatus.NEEDS_REVIEW, confirmed_reason, "confirmed_support"
        return ClaimStatus.CONFIRMED, None, "direct_support"

    if candidate.requested_status is ClaimStatus.INFERRED:
        inferred_reason = _inferred_downgrade_reason(candidate)
        if inferred_reason is not None:
            return ClaimStatus.NEEDS_REVIEW, inferred_reason, candidate.inference_rule
        return ClaimStatus.INFERRED, None, candidate.inference_rule

    if candidate.requested_status is ClaimStatus.REJECTED:
        if not candidate.rationale:
            return ClaimStatus.NEEDS_REVIEW, "rejected claim lacks rejection rationale", "rejection"
        return ClaimStatus.REJECTED, None, "rejection"

    return ClaimStatus.NEEDS_REVIEW, None, "needs_review"


def validate_claim_candidate(candidate: ClaimCandidate) -> ClaimValidationResult:
    final_status, downgrade_reason, rule_name = _decide_status(candidate)
    evidence_refs = list(candidate.evidence_refs)
    if candidate.requested_status is ClaimStatus.REJECTED or final_status is ClaimStatus.REJECTED:
        evidence_refs = _dedupe_evidence_refs(
            [*candidate.evidence_refs, *candidate.contradiction_evidence_refs]
        )

    rationale = candidate.rationale
    limitations = list(candidate.limitations)
    validation_notes = [f"requested_status={candidate.requested_status.value}"]

    if final_status is ClaimStatus.NEEDS_REVIEW:
        rationale = _needs_review_rationale(candidate, downgrade_reason)
        _append_unique(limitations, downgrade_reason)
        _append_unique(limitations, candidate.ambiguity_reason)

    if downgrade_reason is not None:
        validation_notes.append(
            f"downgraded from {candidate.requested_status.value} to {final_status.value}: "
            f"{downgrade_reason}"
        )
    else:
        validation_notes.append(f"status retained as {final_status.value}")

    if rule_name is not None:
        validation_notes.append(f"rule={rule_name}")

    finding = Finding(
        finding_id=candidate.finding_id,
        claim=candidate.claim,
        status=final_status,
        confidence=candidate.confidence,
        kind=candidate.kind,
        evidence_refs=evidence_refs,
        audit_event_refs=list(candidate.audit_event_refs),
        artifact_hashes=list(candidate.artifact_hashes),
        raw_record_refs=list(candidate.raw_record_refs),
        rationale=rationale,
        limitations=limitations,
    )

    return ClaimValidationResult(
        finding=finding,
        original_requested_status=candidate.requested_status,
        final_status=final_status,
        validation_notes=validation_notes,
        downgrade_reason=downgrade_reason,
        rule_name=rule_name,
        contradiction_evidence_refs=list(candidate.contradiction_evidence_refs),
    )


def validate_claim_candidates(candidates: Sequence[ClaimCandidate]) -> list[ClaimValidationResult]:
    candidate_list = list(candidates)
    if not all(isinstance(candidate, ClaimCandidate) for candidate in candidate_list):
        raise TypeError("candidates must contain only ClaimCandidate instances")
    return [validate_claim_candidate(candidate) for candidate in candidate_list]


def _timeline_candidate_id(timeline: SubjectTimeline) -> str:
    encoded = json.dumps(timeline.to_dict(), sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )
    return f"F-TL-{hashlib.sha256(encoded).hexdigest()[:16]}"


def candidate_from_subject_timeline(timeline: SubjectTimeline) -> ClaimCandidate:
    if not isinstance(timeline, SubjectTimeline):
        raise TypeError("timeline must be a SubjectTimeline")

    evidence_refs = timeline.collect_evidence_refs()
    raw_record_refs = _raw_record_refs_from_evidence(evidence_refs)
    event_types = {event.event_type for event in timeline.events}
    finding_id = _timeline_candidate_id(timeline)

    if timeline.ambiguous:
        return ClaimCandidate(
            finding_id=finding_id,
            claim=f"Timeline for {timeline.subject} requires analyst review due to ambiguity.",
            requested_status=ClaimStatus.NEEDS_REVIEW,
            confidence=Confidence.LOW,
            kind=FindingKind.CONCLUSION,
            evidence_refs=evidence_refs,
            raw_record_refs=raw_record_refs,
            rationale="Claim requires analyst review because the source timeline is ambiguous.",
            limitations=[timeline.ambiguity_reason or "Source timeline is ambiguous."],
            source_timeline_subject=timeline.subject,
            ambiguous=True,
            ambiguity_reason=timeline.ambiguity_reason,
        )

    if {
        TimelineEventType.DROP,
        TimelineEventType.EXECUTION,
        TimelineEventType.PERSISTENCE,
    } <= event_types:
        return ClaimCandidate(
            finding_id=finding_id,
            claim=(
                f"Timeline for {timeline.subject} contains drop, execution, "
                "and persistence observations."
            ),
            requested_status=ClaimStatus.INFERRED,
            confidence=Confidence.MEDIUM,
            kind=FindingKind.CONCLUSION,
            evidence_refs=evidence_refs,
            raw_record_refs=raw_record_refs,
            rationale=(
                "Drop, execution, and persistence observations are present for the same "
                "non-ambiguous subject timeline."
            ),
            inference_rule="drop_execution_persistence_timeline",
            source_timeline_subject=timeline.subject,
        )

    return ClaimCandidate(
        finding_id=finding_id,
        claim=f"Timeline for {timeline.subject} has incomplete correlation coverage.",
        requested_status=ClaimStatus.NEEDS_REVIEW,
        confidence=Confidence.LOW,
        kind=FindingKind.CONCLUSION,
        evidence_refs=evidence_refs,
        raw_record_refs=raw_record_refs,
        rationale=(
            "Claim requires analyst review because the timeline does not contain enough "
            "event categories for validation."
        ),
        limitations=["Timeline has incomplete event category coverage."],
        source_timeline_subject=timeline.subject,
    )
