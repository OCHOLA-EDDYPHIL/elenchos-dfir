from __future__ import annotations

import json

from siftguard.correlation.models import SubjectTimeline, TimelineEvent, TimelineEventType
from siftguard.validation.claims import (
    ClaimCandidate,
    candidate_from_subject_timeline,
    candidates_from_subject_timelines,
    should_emit_finding_for_timeline,
    validate_claim_candidate,
    validate_claim_candidates,
)
from siftguard.validation.models import ClaimStatus, Confidence, EvidenceRef, FindingKind

SYNTHETIC_HASH = "sha256:" + ("a" * 64)
SYNTHETIC_PATH = "C:/Users/Alice/AppData/Local/Temp/example-a.exe"


def evidence_ref(
    evidence_id: str = "EV-SYN-MFT-001",
    parser: str = "mftecmd",
    source: str = "$MFT",
    raw_record_ref: str = "csv:mft.csv:1842",
) -> EvidenceRef:
    return EvidenceRef(
        evidence_id=evidence_id,
        parser=parser,
        source=source,
        raw_record_ref=raw_record_ref,
        description="Synthetic claim validation evidence reference.",
    )


def candidate(
    *,
    finding_id: str = "F-SYN-CLAIM-001",
    requested_status: ClaimStatus = ClaimStatus.CONFIRMED,
    evidence_refs: list[EvidenceRef] | None = None,
    artifact_hashes: list[str] | None = None,
    raw_record_refs: list[str] | None = None,
    rationale: str = "Synthetic evidence directly supports the claim.",
    inference_rule: str | None = None,
    contradiction_evidence_refs: list[EvidenceRef] | None = None,
    limitations: list[str] | None = None,
    ambiguous: bool = False,
    ambiguity_reason: str | None = None,
) -> ClaimCandidate:
    return ClaimCandidate(
        finding_id=finding_id,
        claim=f"Synthetic claim for {SYNTHETIC_PATH}.",
        requested_status=requested_status,
        confidence=Confidence.HIGH,
        kind=FindingKind.CONCLUSION,
        evidence_refs=list(evidence_refs if evidence_refs is not None else [evidence_ref()]),
        audit_event_refs=["TR-SYN-001"],
        artifact_hashes=list(artifact_hashes if artifact_hashes is not None else [SYNTHETIC_HASH]),
        raw_record_refs=list(raw_record_refs if raw_record_refs is not None else []),
        rationale=rationale,
        limitations=list(limitations if limitations is not None else []),
        inference_rule=inference_rule,
        contradiction_evidence_refs=list(contradiction_evidence_refs or []),
        source_timeline_subject=SYNTHETIC_PATH,
        ambiguous=ambiguous,
        ambiguity_reason=ambiguity_reason,
    )


def timeline_event(event_type: TimelineEventType, evidence_id: str) -> TimelineEvent:
    return TimelineEvent(
        event_type=event_type,
        timestamp="2026-01-01T00:00:00Z",
        subject=SYNTHETIC_PATH,
        source="synthetic",
        details={"detail": event_type.value},
        evidence_refs=[evidence_ref(evidence_id=evidence_id)],
        path=SYNTHETIC_PATH,
    )


def test_confirmed_candidate_with_direct_support_stays_confirmed():
    result = validate_claim_candidate(candidate())

    assert result.original_requested_status is ClaimStatus.CONFIRMED
    assert result.final_status is ClaimStatus.CONFIRMED
    assert result.finding.status is ClaimStatus.CONFIRMED
    assert result.finding.supports_final_report is True
    assert result.rule_name == "direct_support"


def test_confirmed_candidate_without_evidence_is_downgraded():
    result = validate_claim_candidate(
        candidate(evidence_refs=[], raw_record_refs=["csv:mft.csv:1842"])
    )

    assert result.final_status is ClaimStatus.NEEDS_REVIEW
    assert result.finding.supports_final_report is False
    assert "direct evidence references" in (result.downgrade_reason or "")
    assert any("downgraded" in note for note in result.validation_notes)


def test_confirmed_candidate_without_raw_record_support_is_downgraded():
    result = validate_claim_candidate(
        candidate(evidence_refs=[evidence_ref(raw_record_ref=None)], raw_record_refs=[])
    )

    assert result.final_status is ClaimStatus.NEEDS_REVIEW
    assert "raw record support" in (result.downgrade_reason or "")
    assert result.finding.supports_final_report is False


def test_confirmed_candidate_without_artifact_hash_or_limitation_is_downgraded():
    result = validate_claim_candidate(candidate(artifact_hashes=[]))

    assert result.final_status is ClaimStatus.NEEDS_REVIEW
    assert "artifact hash support" in (result.downgrade_reason or "")


def test_confirmed_candidate_with_hash_limitation_can_stay_confirmed():
    result = validate_claim_candidate(
        candidate(
            artifact_hashes=[],
            limitations=["Artifact hash is unavailable in this synthetic input."],
        )
    )

    assert result.final_status is ClaimStatus.CONFIRMED
    assert result.finding.supports_final_report is True


def test_inferred_candidate_with_evidence_rationale_and_rule_stays_inferred():
    result = validate_claim_candidate(
        candidate(
            requested_status=ClaimStatus.INFERRED,
            artifact_hashes=[],
            inference_rule="synthetic_sequence_rule",
            rationale="Synthetic timeline sequence supports an inference.",
        )
    )

    assert result.final_status is ClaimStatus.INFERRED
    assert result.finding.status is ClaimStatus.INFERRED
    assert result.rule_name == "synthetic_sequence_rule"
    assert result.finding.supports_final_report is True


def test_inferred_candidate_without_inference_rule_is_downgraded():
    result = validate_claim_candidate(
        candidate(
            requested_status=ClaimStatus.INFERRED,
            artifact_hashes=[],
            inference_rule=None,
            rationale="Synthetic rationale exists.",
        )
    )

    assert result.final_status is ClaimStatus.NEEDS_REVIEW
    assert "inference rule" in (result.downgrade_reason or "")


def test_inferred_candidate_without_evidence_is_downgraded():
    result = validate_claim_candidate(
        candidate(
            requested_status=ClaimStatus.INFERRED,
            evidence_refs=[],
            artifact_hashes=[],
            raw_record_refs=[],
            inference_rule="synthetic_sequence_rule",
            rationale="Synthetic rationale exists.",
        )
    )

    assert result.final_status is ClaimStatus.NEEDS_REVIEW
    assert "supporting evidence references" in (result.downgrade_reason or "")


def test_rejected_candidate_preserves_rejection_rationale():
    result = validate_claim_candidate(
        candidate(
            requested_status=ClaimStatus.REJECTED,
            evidence_refs=[],
            artifact_hashes=[],
            raw_record_refs=[],
            rationale="Synthetic contradictory records reject the claim.",
        )
    )

    assert result.final_status is ClaimStatus.REJECTED
    assert result.finding.rationale == "Synthetic contradictory records reject the claim."
    assert result.finding.supports_final_report is False


def test_rejected_candidate_preserves_contradicting_evidence_refs():
    contradiction = evidence_ref(
        evidence_id="EV-SYN-REG-001",
        parser="recmd",
        source="NTUSER.DAT",
        raw_record_ref="json:runkeys.json:/entries/12",
    )
    result = validate_claim_candidate(
        candidate(
            requested_status=ClaimStatus.REJECTED,
            evidence_refs=[],
            artifact_hashes=[],
            raw_record_refs=[],
            rationale="Synthetic registry evidence contradicts the claim.",
            contradiction_evidence_refs=[contradiction],
        )
    )

    assert result.final_status is ClaimStatus.REJECTED
    assert result.contradiction_evidence_refs == [contradiction]
    assert result.finding.evidence_refs == [contradiction]


def test_needs_review_candidate_can_represent_incomplete_or_ambiguous_evidence():
    result = validate_claim_candidate(
        candidate(
            requested_status=ClaimStatus.NEEDS_REVIEW,
            evidence_refs=[],
            artifact_hashes=[],
            raw_record_refs=[],
            rationale="",
            ambiguous=True,
            ambiguity_reason="Synthetic basename maps to multiple subjects.",
        )
    )

    assert result.final_status is ClaimStatus.NEEDS_REVIEW
    assert result.finding.status is ClaimStatus.NEEDS_REVIEW
    assert result.finding.supports_final_report is False
    assert "analyst review" in result.finding.rationale


def test_evidence_free_claim_is_never_upgraded_to_confirmed():
    result = validate_claim_candidate(
        candidate(
            requested_status=ClaimStatus.CONFIRMED,
            evidence_refs=[],
            artifact_hashes=[],
            raw_record_refs=[],
            rationale="Synthetic unsupported claim.",
        )
    )

    assert result.final_status is not ClaimStatus.CONFIRMED
    assert result.finding.supports_final_report is False


def test_validation_results_are_deterministic_for_same_input():
    candidates = [
        candidate(finding_id="F-SYN-DET-001"),
        candidate(
            finding_id="F-SYN-DET-002",
            requested_status=ClaimStatus.INFERRED,
            artifact_hashes=[],
            inference_rule="synthetic_sequence_rule",
            rationale="Synthetic sequence supports inference.",
        ),
    ]

    first = [result.to_dict() for result in validate_claim_candidates(candidates)]
    second = [result.to_dict() for result in validate_claim_candidates(candidates)]

    assert first == second
    assert json.loads(json.dumps(first, sort_keys=True)) == first


def test_unit_coverage_reaches_all_final_statuses():
    results = [
        validate_claim_candidate(candidate()),
        validate_claim_candidate(
            candidate(
                requested_status=ClaimStatus.INFERRED,
                artifact_hashes=[],
                inference_rule="synthetic_sequence_rule",
                rationale="Synthetic sequence supports inference.",
            )
        ),
        validate_claim_candidate(
            candidate(
                requested_status=ClaimStatus.REJECTED,
                evidence_refs=[],
                artifact_hashes=[],
                raw_record_refs=[],
                rationale="Synthetic evidence rejects the claim.",
            )
        ),
        validate_claim_candidate(
            candidate(
                requested_status=ClaimStatus.CONFIRMED,
                evidence_refs=[],
                artifact_hashes=[],
                raw_record_refs=[],
            )
        ),
    ]

    assert {result.final_status for result in results} == {
        ClaimStatus.CONFIRMED,
        ClaimStatus.INFERRED,
        ClaimStatus.REJECTED,
        ClaimStatus.NEEDS_REVIEW,
    }


def test_ambiguous_timeline_candidate_becomes_needs_review():
    timeline = SubjectTimeline(
        subject="example-a.exe",
        events=[timeline_event(TimelineEventType.OBSERVATION, "EV-SYN-MFT-001")],
        ambiguous=True,
        ambiguity_reason="Synthetic basename maps to multiple full paths.",
    )

    result = validate_claim_candidate(candidate_from_subject_timeline(timeline))

    assert result.final_status is ClaimStatus.NEEDS_REVIEW
    assert result.finding.supports_final_report is False
    assert result.finding.limitations == ["Synthetic basename maps to multiple full paths."]


def test_non_ambiguous_complete_timeline_candidate_is_inferred():
    timeline = SubjectTimeline(
        subject=SYNTHETIC_PATH,
        events=[
            timeline_event(TimelineEventType.DROP, "EV-SYN-MFT-001"),
            timeline_event(TimelineEventType.EXECUTION, "EV-SYN-AMCACHE-001"),
            timeline_event(TimelineEventType.PERSISTENCE, "EV-SYN-REG-001"),
        ],
    )

    result = validate_claim_candidate(candidate_from_subject_timeline(timeline))

    assert result.final_status is ClaimStatus.INFERRED
    assert result.rule_name == "drop_execution_persistence_timeline"


def test_ordinary_mft_only_timeline_is_not_reportable_finding():
    timeline = SubjectTimeline(
        subject="C:/Data/ordinary.txt",
        events=[
            TimelineEvent(
                event_type=TimelineEventType.DROP,
                timestamp="2026-01-01T00:00:00Z",
                subject="C:/Data/ordinary.txt",
                source="mftecmd",
                details={"detail": "ordinary MFT create"},
                evidence_refs=[evidence_ref()],
                path="C:/Data/ordinary.txt",
            )
        ],
    )

    assert should_emit_finding_for_timeline(timeline) is False
    assert candidates_from_subject_timelines([timeline]) == []


def test_correlated_same_path_events_produce_one_grouped_candidate():
    timeline = SubjectTimeline(
        subject=SYNTHETIC_PATH,
        events=[
            timeline_event(TimelineEventType.DROP, "EV-SYN-MFT-001"),
            timeline_event(TimelineEventType.EXECUTION, "EV-SYN-AMCACHE-001"),
            timeline_event(TimelineEventType.PERSISTENCE, "EV-SYN-REG-001"),
        ],
    )

    candidates = candidates_from_subject_timelines([timeline])

    assert len(candidates) == 1
    assert candidates[0].source_timeline_subject == SYNTHETIC_PATH


def test_synthetic_claim_validation_examples_contain_no_real_evidence_or_private_paths():
    payload = validate_claim_candidate(candidate()).to_dict()
    encoded = json.dumps(payload)

    assert "example-a.exe" in encoded
    for forbidden in ("/mnt/evidence", "/home/", "runs/", ".local/"):
        assert forbidden not in encoded
    assert ("payload" + ".dll") not in encoded
