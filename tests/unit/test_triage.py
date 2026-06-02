from __future__ import annotations

from datetime import datetime, timezone

from siftguard.triage import TriageAnchors, classify_selection_reason, select_event_rows_for_triage


def test_case_window_events_are_selected_before_deterministic_fill():
    case_window = (
        datetime(2020, 11, 13, 0, 0, tzinfo=timezone.utc),
        datetime(2020, 11, 13, 23, 59, tzinfo=timezone.utc),
    )
    rows = [
        {
            "event_id": "outside",
            "path": "C:/Data/readme.txt",
            "timestamp_utc": "2020-11-15T00:00:00Z",
        },
        {
            "event_id": "inside",
            "path": "C:/Data/project-notes.txt",
            "timestamp_utc": "2020-11-13T15:00:00Z",
        },
    ]

    result = select_event_rows_for_triage(
        rows,
        max_events=1,
        anchors=TriageAnchors(),
        case_windows=(case_window,),
    )

    assert [row["event_id"] for row in result.rows] == ["inside"]
    assert result.counts["case_window_selected"] == 1
    assert result.counts["dropped_due_to_cap"] == 1


def test_case_window_classification_requires_timestamp_in_window():
    case_window = (
        datetime(2020, 11, 13, 0, 0, tzinfo=timezone.utc),
        datetime(2020, 11, 13, 23, 59, tzinfo=timezone.utc),
    )

    reason = classify_selection_reason(
        path="C:/Data/readme.txt",
        timestamp=datetime(2020, 11, 13, 12, 0, tzinfo=timezone.utc),
        anchors=TriageAnchors(),
        case_windows=(case_window,),
    )

    assert reason == "case_window_selected"
