from __future__ import annotations

from pathlib import Path

import pytest

from siftguard.parser.config import ParserCommandConfig
from siftguard.parser.registry_user_activity import (
    normalize_recmd_user_activity_csv,
    parse_registry_user_activity,
)

FIXTURE_DIR = Path("tests/fixtures/parser_outputs/registry")


def test_userassist_rows_normalize_to_program_use_event():
    events, warnings, errors, gaps = normalize_recmd_user_activity_csv(
        csv_path=FIXTURE_DIR / "recmd_userassist.csv",
        case_id="case-001",
        artifact_id="prep_ntuser",
        artifact_type="userassist",
        source_id="src_disk",
        source_role="disk_image",
    )

    assert not errors
    assert not gaps
    assert {event.event_type for event in events} == {"registry_userassist_program_use"}
    assert events[0].artifact_type == "userassist"
    assert events[0].metadata["artifact_family"] == "registry_user_activity"
    assert events[0].metadata["source_id"] == "src_disk"
    assert events[0].path == r"C:\Users\analyst\AppData\Local\Temp\tool.exe"
    assert warnings == []


def test_recentdocs_rows_normalize_to_recent_document_event():
    events, _warnings, errors, _gaps = normalize_recmd_user_activity_csv(
        csv_path=FIXTURE_DIR / "recmd_recentdocs.csv",
        case_id="case-001",
        artifact_id="prep_ntuser",
        artifact_type="recentdocs",
    )

    assert not errors
    assert events[0].event_type == "registry_recent_document_candidate"
    assert events[0].artifact_type == "recentdocs"
    assert events[0].path.endswith(r"ProjectAlpha\design.docx")


def test_opensave_rows_normalize_to_opensave_event():
    events, _warnings, errors, _gaps = normalize_recmd_user_activity_csv(
        csv_path=FIXTURE_DIR / "recmd_opensavepidlmru.csv",
        case_id="case-001",
        artifact_id="prep_ntuser",
        artifact_type="opensavepidlmru",
    )

    assert not errors
    assert events[0].event_type == "registry_opensave_file_candidate"
    assert events[0].artifact_type == "opensavepidlmru"


def test_lastvisited_rows_normalize_to_lastvisited_event():
    events, _warnings, errors, _gaps = normalize_recmd_user_activity_csv(
        csv_path=FIXTURE_DIR / "recmd_lastvisitedpidlmru.csv",
        case_id="case-001",
        artifact_id="prep_ntuser",
        artifact_type="lastvisitedpidlmru",
    )

    assert not errors
    assert events[0].event_type == "registry_lastvisited_program_candidate"
    assert events[0].artifact_type == "lastvisitedpidlmru"


def test_typedpaths_rows_normalize_to_typed_path_event():
    events, _warnings, errors, _gaps = normalize_recmd_user_activity_csv(
        csv_path=FIXTURE_DIR / "recmd_typedpaths.csv",
        case_id="case-001",
        artifact_id="prep_ntuser",
        artifact_type="typedpaths",
    )

    assert not errors
    assert events[0].event_type == "registry_typed_path_candidate"
    assert events[0].artifact_type == "typedpaths"
    assert events[0].path == r"C:\Users\analyst\OneDrive\Research"


@pytest.mark.parametrize("artifact_type", ["userassist", "recentdocs"])
def test_missing_user_activity_rows_produce_coverage_gap(artifact_type: str):
    events, warnings, errors, gaps = normalize_recmd_user_activity_csv(
        csv_path=FIXTURE_DIR / "recmd_user_activity_empty.csv",
        case_id="case-001",
        artifact_id="prep_ntuser",
        artifact_type=artifact_type,
    )

    assert events == []
    assert warnings == []
    assert errors == []
    assert gaps[0]["artifact_family"] == "registry_user_activity"
    assert gaps[0]["artifact_type"] == artifact_type
    assert gaps[0]["reason"] == "no_rows"


def test_parser_unavailable_produces_gaps_not_shell_command(tmp_path: Path):
    hive = tmp_path / "NTUSER.DAT"
    hive.write_bytes(b"synthetic hive")

    result = parse_registry_user_activity(
        case_id="case-001",
        artifact_id="prep_ntuser",
        hive_path=hive,
        runs_root=tmp_path / "runs",
        command_config=ParserCommandConfig({}),
    )

    assert result.status == "skipped"
    assert result.command is None
    assert {gap["reason"] for gap in result.coverage_gaps} == {"parser_unavailable"}
    assert {gap["artifact_type"] for gap in result.coverage_gaps} >= {
        "userassist",
        "recentdocs",
        "opensavepidlmru",
        "lastvisitedpidlmru",
        "typedpaths",
    }
