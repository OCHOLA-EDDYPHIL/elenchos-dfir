from __future__ import annotations

from siftguard.agent.self_correction_events import (
    THEFT_EXFILTRATION_SCOPE_BOUNDARY,
    THEFT_EXFILTRATION_STRICT_WORDING,
    build_self_correction_events,
)


def test_build_self_correction_events_records_real_theft_exfiltration_gap():
    payload = build_self_correction_events(
        case_id="rocba-standard",
        created_at="2026-01-01T00:00:00Z",
        case_questions={
            "questions": [
                {"question_id": "q_what_was_stolen", "status": "not_assessed"},
                {"question_id": "q_where_transferred", "status": "not_assessed"},
                {"question_id": "q_how_stolen", "status": "not_assessed"},
                {"question_id": "q_memory", "status": "not_assessed"},
                {"question_id": "q_when_activity", "status": "needs_review"},
            ]
        },
    )

    assert payload["mode"] == "real_gap_self_correction"
    assert payload["event_count"] == 1
    event = payload["events"][0]
    assert event["event_id"] == "real-gap-001"
    assert event["phase"] == "claim_validation"
    assert event["final_wording"] == THEFT_EXFILTRATION_STRICT_WORDING
    assert event["claim_boundary"] == THEFT_EXFILTRATION_SCOPE_BOUNDARY
    assert event["human_intervention"] is False
    assert event["model_output_used_as_evidence"] is False
    assert event["raw_evidence_sent_to_model"] is False
    assert event["source_question_ids"] == [
        "q_what_was_stolen",
        "q_where_transferred",
        "q_how_stolen",
        "q_memory",
    ]


def test_build_self_correction_events_does_not_emit_without_real_gap():
    payload = build_self_correction_events(
        case_id="case-with-supported-output",
        created_at="2026-01-01T00:00:00Z",
        case_questions={
            "questions": [
                {"question_id": "q_what_was_stolen", "status": "not_assessed"},
                {"question_id": "q_where_transferred", "status": "needs_review"},
                {"question_id": "q_how_stolen", "status": "not_assessed"},
            ]
        },
    )

    assert payload["event_count"] == 0
    assert payload["events"] == []
