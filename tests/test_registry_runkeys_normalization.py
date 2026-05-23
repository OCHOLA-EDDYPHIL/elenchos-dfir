from __future__ import annotations

import json
from pathlib import Path

from siftguard.correlation.event_schema import ParserEvent, RawRecordRef
from siftguard.parser.registry_runkeys import normalize_recmd_runkeys_csv

FIXTURE_DIR = Path("tests/fixtures/parser_outputs/registry")


def test_valid_recmd_runkeys_fixture_normalizes_without_errors():
    events, warnings, errors = normalize_recmd_runkeys_csv(
        csv_path=FIXTURE_DIR / "recmd_runkeys_valid.csv",
        case_id="case-001",
        artifact_id="EV-REG-0001",
    )

    assert warnings == []
    assert errors == []
    assert len(events) == 2
    assert {event.event_type for event in events} == {"registry_run_key"}
    assert {event.parser_name for event in events} == {"recmd"}
    assert {event.artifact_type for event in events} == {"registry"}


def test_valid_recmd_runkeys_fixture_preserves_registry_values_and_timestamps():
    events, _, _ = normalize_recmd_runkeys_csv(
        csv_path=FIXTURE_DIR / "recmd_runkeys_valid.csv",
        case_id="case-001",
        artifact_id="EV-REG-0001",
    )

    first, second = events
    assert first.key_path == r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
    assert first.value_name == "Updater"
    assert first.value_data == r"C:\Users\alice\AppData\Local\Temp\evil.exe"
    assert second.key_path == r"HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce"
    assert second.value_name == "Payload"
    assert second.value_data == r"C:\Temp\payload.dll"

    for event in events:
        assert event.timestamp_utc is not None
        assert event.timestamp_utc.endswith("Z")
        assert event.timestamp_description == "LastWriteTime"
        assert event.evidence_refs == ["EV-REG-0001"]
        assert isinstance(event.raw_record_ref, RawRecordRef)
        assert event.raw_record_ref.source_path.endswith("recmd_runkeys_valid.csv")
        assert event.raw_record_ref.row_number is not None
        assert event.raw_record_ref.row_number > 0


def test_recmd_runkeys_event_ids_are_deterministic():
    first, _, _ = normalize_recmd_runkeys_csv(
        csv_path=FIXTURE_DIR / "recmd_runkeys_valid.csv",
        case_id="case-001",
        artifact_id="EV-REG-0001",
    )
    second, _, _ = normalize_recmd_runkeys_csv(
        csv_path=FIXTURE_DIR / "recmd_runkeys_valid.csv",
        case_id="case-001",
        artifact_id="EV-REG-0001",
    )

    assert [event.event_id for event in first] == [event.event_id for event in second]


def test_recmd_runkeys_event_id_changes_when_stable_field_changes():
    events, _, _ = normalize_recmd_runkeys_csv(
        csv_path=FIXTURE_DIR / "recmd_runkeys_valid.csv",
        case_id="case-001",
        artifact_id="EV-REG-0001",
    )
    payload = events[0].to_dict()
    payload["event_id"] = ""
    payload["value_name"] = "DifferentValue"

    changed = ParserEvent.from_dict(payload)

    assert changed.event_id != events[0].event_id


def test_malformed_recmd_runkeys_fixture_does_not_crash_and_warns():
    events, warnings, errors = normalize_recmd_runkeys_csv(
        csv_path=FIXTURE_DIR / "recmd_runkeys_malformed.csv",
        case_id="case-001",
        artifact_id="EV-REG-0001",
    )

    assert errors == []
    assert warnings
    assert any("missing KeyPath" in warning for warning in warnings)
    assert any("invalid timestamp" in warning for warning in warnings)
    assert len(events) == 1
    assert events[0].event_type == "registry_run_key"
    assert events[0].status == "malformed"
    assert events[0].timestamp_utc is None
    assert events[0].key_path is None
    assert events[0].value_name == "Updater"


def test_empty_recmd_runkeys_csv_returns_error(tmp_path):
    csv_path = tmp_path / "empty.csv"
    csv_path.write_text("", encoding="utf-8")

    events, warnings, errors = normalize_recmd_runkeys_csv(
        csv_path=csv_path,
        case_id="case-001",
        artifact_id="EV-REG-0001",
    )

    assert events == []
    assert warnings == []
    assert errors


def test_recmd_runkeys_row_without_context_returns_error(tmp_path):
    csv_path = tmp_path / "missing-context.csv"
    csv_path.write_text(
        "Hive,KeyPath,ValueName,ValueData,LastWriteTime\nNTUSER.DAT,,,,\n",
        encoding="utf-8",
    )

    events, warnings, errors = normalize_recmd_runkeys_csv(
        csv_path=csv_path,
        case_id="case-001",
        artifact_id="EV-REG-0001",
    )

    assert events == []
    assert warnings == []
    assert errors == ["row 2: missing registry key and value context"]


def test_header_only_recmd_runkeys_csv_returns_error(tmp_path):
    csv_path = tmp_path / "header-only.csv"
    csv_path.write_text(
        "Hive,KeyPath,ValueName,ValueData,LastWriteTime\n",
        encoding="utf-8",
    )

    events, warnings, errors = normalize_recmd_runkeys_csv(
        csv_path=csv_path,
        case_id="case-001",
        artifact_id="EV-REG-0001",
    )

    assert events == []
    assert warnings == []
    assert errors


def test_recmd_runkeys_events_do_not_contain_conclusion_terms():
    events, _, _ = normalize_recmd_runkeys_csv(
        csv_path=FIXTURE_DIR / "recmd_runkeys_valid.csv",
        case_id="case-001",
        artifact_id="EV-REG-0001",
    )
    payload = json.dumps([event.to_dict() for event in events]).lower()

    terms = (
        "mal" + "ware",
        "attack" + "er",
        "comprom" + "ised",
        "exfil" + "tration",
        "persistence " + "confirmed",
        "drop " + "confirmed",
        "executed " + "confirmed",
        "sus" + "picious",
    )
    for term in terms:
        assert term not in payload
