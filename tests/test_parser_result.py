from __future__ import annotations

import json

import pytest

from siftguard.correlation.event_schema import ParserEvent, RawRecordRef
from siftguard.parser.result import ParserResult


def make_event() -> ParserEvent:
    return ParserEvent(
        case_id="case-001",
        artifact_id="EV-REG-0001",
        artifact_type="registry",
        parser_name="recmd",
        source_tool="RECmd",
        event_type="registry_run_key",
        key_path=r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
        value_name="Updater",
        value_data=r"C:\Users\alice\AppData\Local\Temp\evil.exe",
        evidence_refs=["EV-REG-0001"],
        raw_record_ref=RawRecordRef(source_path="recmd_runkeys_valid.csv", row_number=2),
    )


def test_parser_result_success_with_events_serializes():
    event = make_event()
    result = ParserResult(
        case_id="case-001",
        artifact_id="EV-REG-0001",
        artifact_type="registry",
        parser_name="recmd",
        source_tool="RECmd",
        status="success",
        command=("RECmd", "-f", "SOFTWARE"),
        output_dir="runs/case-001/parser_outputs/EV-REG-0001/recmd",
        output_files=["recmd_runkeys_valid.csv"],
        output_hashes={"recmd_runkeys_valid.csv": "a" * 64},
        audit_event_ids=["audit_000001"],
        events=[event],
        started_at_utc="2026-01-01T00:00:00Z",
        ended_at_utc="2026-01-01T00:00:01Z",
        duration_ms=1000,
        tool_version="2.1.0",
    )

    payload = result.to_dict()
    encoded = json.dumps(payload, sort_keys=True)
    restored = ParserResult.from_dict(json.loads(encoded))

    assert restored.status == "success"
    assert restored.command == ("RECmd", "-f", "SOFTWARE")
    assert restored.source_artifact_id == "EV-REG-0001"
    assert restored.output_paths == ["recmd_runkeys_valid.csv"]
    assert len(restored.normalized_events) == 1


def test_parser_result_failed_with_errors_and_zero_events():
    result = ParserResult(
        case_id="case-001",
        artifact_id="EV-MFT-0001",
        artifact_type="mft",
        parser_name="mftecmd",
        source_tool="MFTECmd",
        status="failed",
        command=("MFTECmd", "-f", "$MFT"),
        errors=["parser reported unknown file type"],
    )

    assert result.events == []
    assert result.errors == ["parser reported unknown file type"]


def test_parser_result_skipped_missing_parser_command_is_visible():
    result = ParserResult.missing_command(
        case_id="case-001",
        artifact_id="EV-AMCACHE-0001",
        artifact_type="amcache",
        parser_name="amcacheparser",
        source_tool="AmcacheParser",
        reason="AmcacheParser command not configured",
    )

    assert result.status == "skipped"
    assert result.command is None
    assert result.errors == ["AmcacheParser command not configured"]


def test_parser_result_supports_partial_success():
    result = ParserResult(
        case_id="case-001",
        artifact_id="EV-MFT-0001",
        artifact_type="mft",
        parser_name="mftecmd",
        source_tool="MFTECmd",
        status="partial_success",
        warnings=["one malformed row skipped"],
        events=[make_event()],
    )

    assert result.status == "partial_success"
    assert result.warnings == ["one malformed row skipped"]


def test_parser_result_rejects_shell_string_command():
    with pytest.raises(TypeError, match="shell string"):
        ParserResult(
            case_id="case-001",
            artifact_id="EV-MFT-0001",
            artifact_type="mft",
            parser_name="mftecmd",
            source_tool="MFTECmd",
            status="failed",
            command="MFTECmd -f $MFT --csv out",
        )
