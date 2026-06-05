from __future__ import annotations

from siftguard.agent.casebook import CasebookClaimBoundary, casebook_from_dict
from siftguard.agent.claim_boundaries import (
    build_claim_boundary_records,
    build_self_correction_events,
)

FINAL_WORDING = "SIFTGuard kept the configured claim not_assessed."
SCOPE_BOUNDARY = "The submitted artifact scope does not support this configured claim."
RECOMMENDED_ARTIFACTS = ("network telemetry", "browser history")


def _casebook(*, claim_boundaries: list[dict[str, object]] | None = None):
    return casebook_from_dict(
        {
            "analysis_windows": [],
            "case_id": "case-claim-boundary",
            "case_questions": [
                {
                    "evidence_classes": [],
                    "id": "q_claim_subject",
                    "question": "What claim subject is supported?",
                    "supported_by_scope": False,
                },
                {
                    "evidence_classes": [],
                    "id": "q_claim_transfer",
                    "question": "What transfer path is supported?",
                    "supported_by_scope": False,
                },
                {
                    "evidence_classes": [],
                    "id": "q_context",
                    "question": "What additional context is available?",
                    "supported_by_scope": False,
                },
            ],
            "claim_boundaries": claim_boundaries or [],
            "display_name": "Synthetic Claim Boundary Case",
            "key_dates": [],
            "time_zone": None,
        }
    )


def _boundary() -> dict[str, object]:
    return {
        "claim_area": "configured claim",
        "emit_when_all_statuses": ["not_assessed"],
        "final_wording": FINAL_WORDING,
        "initial_investigative_pressure": "The case asks whether a claim can be supported.",
        "question_ids": ["q_claim_subject", "q_claim_transfer"],
        "recommended_next_artifacts": list(RECOMMENDED_ARTIFACTS),
        "related_question_ids": ["q_context"],
        "scope_boundary": SCOPE_BOUNDARY,
    }


def _case_questions(*, transfer_status: str = "not_assessed") -> dict[str, object]:
    return {
        "questions": [
            {"question_id": "q_claim_subject", "status": "not_assessed"},
            {"question_id": "q_claim_transfer", "status": transfer_status},
            {"question_id": "q_context", "status": "not_assessed"},
        ]
    }


def test_casebook_claim_boundary_metadata_round_trips():
    casebook = _casebook(claim_boundaries=[_boundary()])

    assert casebook.claim_boundaries == (
        CasebookClaimBoundary(
            claim_area="configured claim",
            question_ids=("q_claim_subject", "q_claim_transfer"),
            related_question_ids=("q_context",),
            emit_when_all_statuses=("not_assessed",),
            final_wording=FINAL_WORDING,
            scope_boundary=SCOPE_BOUNDARY,
            recommended_next_artifacts=RECOMMENDED_ARTIFACTS,
            initial_investigative_pressure=(
                "The case asks whether a claim can be supported."
            ),
        ),
    )
    assert casebook.to_dict()["claim_boundaries"][0]["scope_boundary"] == SCOPE_BOUNDARY


def test_claim_boundary_events_emit_from_casebook_metadata():
    payload = build_self_correction_events(
        case_id="case-claim-boundary",
        created_at="2026-01-01T00:00:00Z",
        casebook=_casebook(claim_boundaries=[_boundary()]),
        case_questions=_case_questions(),
    )

    assert payload["mode"] == "claim_boundary_self_correction"
    assert payload["event_count"] == 1
    event = payload["events"][0]
    assert event["event_id"] == "claim-boundary-001"
    assert event["claim_area"] == "configured claim"
    assert event["final_wording"] == FINAL_WORDING
    assert event["scope_boundary"] == SCOPE_BOUNDARY
    assert event["recommended_next_artifacts"] == list(RECOMMENDED_ARTIFACTS)
    assert event["source_question_ids"] == [
        "q_claim_subject",
        "q_claim_transfer",
        "q_context",
    ]
    assert event["human_intervention"] is False
    assert event["model_output_used_as_evidence"] is False
    assert event["raw_evidence_sent_to_model"] is False


def test_claim_boundary_events_do_not_emit_without_metadata():
    payload = build_self_correction_events(
        case_id="case-claim-boundary",
        created_at="2026-01-01T00:00:00Z",
        casebook=_casebook(),
        case_questions=_case_questions(),
    )

    assert payload["event_count"] == 0
    assert payload["events"] == []


def test_claim_boundary_records_do_not_emit_when_any_primary_question_is_not_matched():
    casebook = _casebook(claim_boundaries=[_boundary()])

    for status in ("needs_review", "inferred", "confirmed", "rejected"):
        records = build_claim_boundary_records(
            casebook=casebook,
            case_questions=_case_questions(transfer_status=status),
        )
        assert records == []


def test_related_question_is_included_only_when_status_matches_boundary():
    casebook = _casebook(claim_boundaries=[_boundary()])
    records = build_claim_boundary_records(
        casebook=casebook,
        case_questions={
            "questions": [
                {"question_id": "q_claim_subject", "status": "not_assessed"},
                {"question_id": "q_claim_transfer", "status": "not_assessed"},
                {"question_id": "q_context", "status": "needs_review"},
            ]
        },
    )

    assert records[0]["source_question_ids"] == [
        "q_claim_subject",
        "q_claim_transfer",
    ]
