from __future__ import annotations

import json
from pathlib import Path

from elenchos.correlation.event_schema import ParserEvent, RawRecordRef
from elenchos.parser.amcache import normalize_amcache_csv

FIXTURE_DIR = Path("tests/fixtures/parser_outputs/amcache")


def test_valid_amcache_fixture_normalizes_without_errors():
    events, warnings, errors = normalize_amcache_csv(
        csv_path=FIXTURE_DIR / "amcacheparser_valid.csv",
        case_id="case-001",
        artifact_id="EV-AMCACHE-0001",
    )

    assert warnings == []
    assert errors == []
    assert len(events) == 1
    assert events[0].parser_name == "amcacheparser"
    assert events[0].artifact_type == "amcache"
    assert events[0].metadata["artifact_family"] == "amcache"
    assert events[0].to_dict()["artifact_family"] == "amcache"
    assert events[0].event_type == "amcache_execution"


def test_valid_amcache_fixture_preserves_path_refs_timestamp_and_hash():
    events, _, _ = normalize_amcache_csv(
        csv_path=FIXTURE_DIR / "amcacheparser_valid.csv",
        case_id="case-001",
        artifact_id="EV-AMCACHE-0001",
    )
    event = events[0]

    assert event.subject == "Synthetic Program"
    assert event.path == r"C:\Users\alice\AppData\Local\Temp\evil.exe"
    assert event.timestamp_utc is not None
    assert event.timestamp_utc.endswith("Z")
    assert event.timestamp_description == "LastModifiedTimeUtc"
    assert event.sha256 == "a" * 64
    assert event.evidence_refs == ["EV-AMCACHE-0001"]
    assert isinstance(event.raw_record_ref, RawRecordRef)
    assert event.raw_record_ref.source_path.endswith("amcacheparser_valid.csv")
    assert event.raw_record_ref.row_number == 2


def test_amcache_event_ids_are_deterministic():
    first, _, _ = normalize_amcache_csv(
        csv_path=FIXTURE_DIR / "amcacheparser_valid.csv",
        case_id="case-001",
        artifact_id="EV-AMCACHE-0001",
    )
    second, _, _ = normalize_amcache_csv(
        csv_path=FIXTURE_DIR / "amcacheparser_valid.csv",
        case_id="case-001",
        artifact_id="EV-AMCACHE-0001",
    )

    assert [event.event_id for event in first] == [event.event_id for event in second]


def test_amcache_event_id_changes_when_stable_field_changes():
    events, _, _ = normalize_amcache_csv(
        csv_path=FIXTURE_DIR / "amcacheparser_valid.csv",
        case_id="case-001",
        artifact_id="EV-AMCACHE-0001",
    )
    payload = events[0].to_dict()
    payload["event_id"] = ""
    payload["path"] = r"C:\Temp\other.exe"

    changed = ParserEvent.from_dict(payload)

    assert changed.event_id != events[0].event_id


def test_malformed_amcache_fixture_does_not_crash_and_warns():
    events, warnings, errors = normalize_amcache_csv(
        csv_path=FIXTURE_DIR / "amcacheparser_malformed.csv",
        case_id="case-001",
        artifact_id="EV-AMCACHE-0001",
    )

    assert errors == []
    assert warnings
    assert any("invalid hash" in warning for warning in warnings)
    assert any("invalid timestamp" in warning for warning in warnings)
    assert any("missing FilePath" in warning for warning in warnings)
    assert len(events) == 1
    assert events[0].event_type == "amcache_execution"
    assert events[0].status == "malformed"
    assert events[0].subject == "Synthetic Program"
    assert events[0].path is None
    assert events[0].timestamp_utc is None
    assert events[0].sha256 is None


def test_empty_amcache_csv_returns_error(tmp_path):
    csv_path = tmp_path / "empty.csv"
    csv_path.write_text("", encoding="utf-8")

    events, warnings, errors = normalize_amcache_csv(
        csv_path=csv_path,
        case_id="case-001",
        artifact_id="EV-AMCACHE-0001",
    )

    assert events == []
    assert warnings == []
    assert errors


def test_amcache_row_without_context_returns_error(tmp_path):
    csv_path = tmp_path / "missing-context.csv"
    csv_path.write_text(
        "ProgramName,FilePath,SHA1,LastModifiedTimeUtc\n,,,\n",
        encoding="utf-8",
    )

    events, warnings, errors = normalize_amcache_csv(
        csv_path=csv_path,
        case_id="case-001",
        artifact_id="EV-AMCACHE-0001",
    )

    assert events == []
    assert warnings == []
    assert errors == ["row 2: missing Amcache row subject or path"]


def test_header_only_amcache_csv_returns_error(tmp_path):
    csv_path = tmp_path / "header-only.csv"
    csv_path.write_text(
        "ProgramName,FilePath,SHA1,LastModifiedTimeUtc\n",
        encoding="utf-8",
    )

    events, warnings, errors = normalize_amcache_csv(
        csv_path=csv_path,
        case_id="case-001",
        artifact_id="EV-AMCACHE-0001",
    )

    assert events == []
    assert warnings == []
    assert errors


def test_amcache_events_do_not_contain_conclusion_terms():
    events, _, _ = normalize_amcache_csv(
        csv_path=FIXTURE_DIR / "amcacheparser_valid.csv",
        case_id="case-001",
        artifact_id="EV-AMCACHE-0001",
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
