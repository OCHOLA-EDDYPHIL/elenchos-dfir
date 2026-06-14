from __future__ import annotations

import json
from pathlib import Path

from elenchos.correlation.event_schema import ParserEvent, RawRecordRef
from elenchos.parser.mft import normalize_mftecmd_csv

FIXTURE_DIR = Path("tests/fixtures/parser_outputs/mft")


def test_valid_mftecmd_fixture_normalizes_without_errors():
    events, warnings, errors = normalize_mftecmd_csv(
        csv_path=FIXTURE_DIR / "mftecmd_valid.csv",
        case_id="case-001",
        artifact_id="EV-MFT-0001",
    )

    assert warnings == []
    assert errors == []
    assert [event.event_type for event in events] == [
        "file_record",
        "file_created",
        "file_modified",
        "file_accessed",
    ]


def test_valid_mftecmd_fixture_preserves_path_refs_and_utc_timestamps():
    events, _, _ = normalize_mftecmd_csv(
        csv_path=FIXTURE_DIR / "mftecmd_valid.csv",
        case_id="case-001",
        artifact_id="EV-MFT-0001",
    )

    for event in events:
        assert event.path == r"C:\Temp\payload.dll"
        assert event.evidence_refs == ["EV-MFT-0001"]
        assert isinstance(event.raw_record_ref, RawRecordRef)
        assert event.raw_record_ref.source_path.endswith("mftecmd_valid.csv")
        assert event.raw_record_ref.row_number == 2

    timestamp_events = [event for event in events if event.timestamp_utc is not None]
    assert timestamp_events
    assert all(event.timestamp_utc.endswith("Z") for event in timestamp_events)
    assert {event.timestamp_description for event in timestamp_events} == {
        "Created0x10",
        "Modified0x10",
        "Accessed0x10",
    }


def test_mftecmd_event_ids_are_deterministic():
    first, _, _ = normalize_mftecmd_csv(
        csv_path=FIXTURE_DIR / "mftecmd_valid.csv",
        case_id="case-001",
        artifact_id="EV-MFT-0001",
    )
    second, _, _ = normalize_mftecmd_csv(
        csv_path=FIXTURE_DIR / "mftecmd_valid.csv",
        case_id="case-001",
        artifact_id="EV-MFT-0001",
    )

    assert [event.event_id for event in first] == [event.event_id for event in second]


def test_mftecmd_normalization_respects_max_events():
    events, warnings, errors = normalize_mftecmd_csv(
        csv_path=FIXTURE_DIR / "mftecmd_valid.csv",
        case_id="case-001",
        artifact_id="EV-MFT-0001",
        max_events=2,
    )

    assert errors == []
    assert len(events) == 2
    assert [event.event_type for event in events] == ["file_record", "file_created"]
    assert any("max_events=2 reached" in warning for warning in warnings)


def test_mftecmd_event_id_changes_when_stable_field_changes():
    events, _, _ = normalize_mftecmd_csv(
        csv_path=FIXTURE_DIR / "mftecmd_valid.csv",
        case_id="case-001",
        artifact_id="EV-MFT-0001",
    )
    payload = events[0].to_dict()
    payload["event_id"] = ""
    payload["path"] = r"C:\Temp\other.dll"

    changed = ParserEvent.from_dict(payload)

    assert changed.event_id != events[0].event_id


def test_malformed_mftecmd_fixture_does_not_crash_and_warns():
    events, warnings, errors = normalize_mftecmd_csv(
        csv_path=FIXTURE_DIR / "mftecmd_malformed.csv",
        case_id="case-001",
        artifact_id="EV-MFT-0001",
    )

    assert errors == []
    assert warnings
    assert any("invalid integer" in warning for warning in warnings)
    assert any("invalid timestamp" in warning for warning in warnings)
    assert [event.event_type for event in events] == ["file_record"]
    assert events[0].status == "malformed"
    assert events[0].path == r"C:\Temp\payload.dll"


def test_empty_mftecmd_csv_returns_error(tmp_path):
    csv_path = tmp_path / "empty.csv"
    csv_path.write_text("", encoding="utf-8")

    events, warnings, errors = normalize_mftecmd_csv(
        csv_path=csv_path,
        case_id="case-001",
        artifact_id="EV-MFT-0001",
    )

    assert events == []
    assert warnings == []
    assert errors


def test_mftecmd_row_without_path_context_returns_error(tmp_path):
    csv_path = tmp_path / "missing-path.csv"
    csv_path.write_text(
        "EntryNumber,Created0x10\n42,2026-01-01 00:00:00.0000000\n",
        encoding="utf-8",
    )

    events, warnings, errors = normalize_mftecmd_csv(
        csv_path=csv_path,
        case_id="case-001",
        artifact_id="EV-MFT-0001",
    )

    assert events == []
    assert warnings == []
    assert errors == ["row 2: missing file path or file name"]


def test_mftecmd_events_do_not_contain_conclusion_terms():
    events, _, _ = normalize_mftecmd_csv(
        csv_path=FIXTURE_DIR / "mftecmd_valid.csv",
        case_id="case-001",
        artifact_id="EV-MFT-0001",
    )
    payload = json.dumps([event.to_dict() for event in events]).lower()

    terms = (
        "attack" + "er",
        "comprom" + "ised",
        "exfil" + "tration",
        "persistence " + "confirmed",
    )
    for term in terms:
        assert term not in payload
