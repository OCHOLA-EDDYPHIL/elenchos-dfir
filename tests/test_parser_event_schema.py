from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from elenchos.correlation.event_schema import ParserEvent, RawRecordRef


def make_event(**overrides):
    data = {
        "case_id": "case-001",
        "artifact_id": "EV-MFT-0001",
        "artifact_type": "mft",
        "parser_name": "mftecmd",
        "source_tool": "MFTECmd",
        "event_type": "file_record",
        "timestamp_utc": "2026-01-01T00:00:00Z",
        "timestamp_description": "MFT Created0x10",
        "path": r"C:\Temp\payload.dll",
        "evidence_refs": ["EV-MFT-0001"],
        "raw_record_ref": RawRecordRef(source_path="mftecmd_valid.csv", row_number=2),
        "metadata": {"entry_number": 42},
    }
    data.update(overrides)
    return ParserEvent(**data)


def test_parser_event_serializes_to_json_compatible_data():
    event = make_event()
    payload = event.to_dict()

    encoded = json.dumps(payload, sort_keys=True)
    decoded = json.loads(encoded)
    restored = ParserEvent.from_dict(decoded)

    assert restored.to_dict() == payload
    assert payload["raw_record_ref"]["row_number"] == 2


def test_parser_event_id_is_stable_for_same_inputs():
    first = make_event()
    second = make_event()

    assert first.event_id == second.event_id


def test_parser_event_id_changes_when_stable_field_changes():
    first = make_event()
    second = make_event(path=r"C:\Temp\other.dll")

    assert first.event_id != second.event_id


def test_parser_event_rejects_invalid_event_type():
    with pytest.raises(ValueError, match="invalid event_type"):
        make_event(event_type="persistence_confirmed")


def test_parser_event_requires_evidence_refs():
    with pytest.raises(ValueError, match="evidence_refs"):
        make_event(evidence_refs=[])


def test_parser_event_is_observation_not_finding():
    event = make_event(event_type="registry_run_key", artifact_type="registry", parser_name="recmd")

    assert not hasattr(event, "finding_id")
    assert not hasattr(event, "finding_status")
    assert not hasattr(event, "persistence_confirmed")
    assert event.status == "observed"


def test_raw_record_ref_validates_positive_row_number():
    with pytest.raises(ValueError, match="row_number"):
        RawRecordRef(source_path="mft.csv", row_number=0)


def test_raw_record_ref_supports_stable_record_id_examples():
    ref = RawRecordRef(record_id="csv:mft.csv:1842")

    assert ref.to_dict()["record_id"] == "csv:mft.csv:1842"


def test_parser_event_normalizes_timezone_aware_datetime_to_z():
    event = make_event(timestamp_utc=datetime(2026, 1, 1, tzinfo=timezone.utc))

    assert event.timestamp_utc == "2026-01-01T00:00:00Z"


def test_parser_event_rejects_unsupported_status_and_confidence():
    with pytest.raises(ValueError, match="invalid status"):
        make_event(status="confirmed")

    with pytest.raises(ValueError, match="invalid confidence"):
        make_event(confidence="high")
