from __future__ import annotations

import json
from pathlib import Path

import pytest

from siftguard.mcp_server import schemas, server

CASE_ID = "CASE-SYN-001"
SYNTHETIC_PATH = "C:/Users/Alice/AppData/Local/Temp/example-a.exe"


def walk_schema_keys(value: object) -> set[str]:
    keys: set[str] = set()
    if isinstance(value, dict):
        for key, child in value.items():
            keys.add(str(key))
            keys.update(walk_schema_keys(child))
    elif isinstance(value, list):
        for item in value:
            keys.update(walk_schema_keys(item))
    return keys


def correlation_descriptor() -> schemas.ToolDescriptor:
    return schemas.get_tool_descriptor("correlate_timeline")


def write_input(path: Path) -> None:
    path.write_text(
        json.dumps(
            {
                "case_id": CASE_ID,
                "events": [
                    {
                        "event_type": "observation",
                        "timestamp": "2026-01-01T00:00:01Z",
                        "subject": SYNTHETIC_PATH,
                        "source": "normalized-events",
                        "path": SYNTHETIC_PATH,
                        "details": {"detail": "synthetic observation"},
                        "evidence_refs": [
                            {
                                "evidence_id": "EV-SYN-MFT-001",
                                "parser": "mftecmd",
                                "source": "$MFT",
                                "raw_record_ref": "csv:mft.csv:1842",
                            }
                        ],
                    }
                ],
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )


def test_correlation_request_schema_exposes_safe_path_fields():
    descriptor = correlation_descriptor()
    required = descriptor.input_schema["required"]
    properties = descriptor.input_schema["properties"]

    assert required == ["case_id", "normalized_events_path", "output_dir"]
    assert "case_id" in properties
    assert "normalized_events_path" in properties
    assert "output_dir" in properties
    assert "include_report" in properties


def test_correlation_response_schema_exposes_outputs_and_counts():
    output_schema = correlation_descriptor().output_schema
    assert output_schema is not None
    properties = output_schema["properties"]

    for key in (
        "case_id",
        "event_count",
        "timeline_count",
        "finding_count",
        "report_path",
        "timelines_path",
        "findings_path",
        "audit_path",
    ):
        assert key in properties


def test_correlation_schema_does_not_expose_raw_evidence_upload_or_execution_fields():
    descriptor = correlation_descriptor()
    keys = walk_schema_keys(descriptor.input_schema) | walk_schema_keys(descriptor.output_schema)
    forbidden = {
        "raw_evidence",
        "raw_evidence_bytes",
        "evidence_bytes",
        "upload",
        "command",
        "cmd",
        "argv",
        "shell",
        "executable",
    }

    assert not (keys & forbidden)


def test_correlation_tool_descriptor_is_in_planned_tools():
    assert "correlate_timeline" in server.get_planned_tools()
    assert schemas.get_correlation_tool_descriptors()[0].name == "correlate_timeline"


def test_server_helper_calls_workflow_with_typed_paths(tmp_path: Path):
    input_path = tmp_path / "normalized-events.json"
    output_dir = tmp_path / "runs" / CASE_ID
    write_input(input_path)

    result = server.run_correlation_workflow_tool(
        {
            "case_id": CASE_ID,
            "normalized_events_path": str(input_path),
            "output_dir": str(output_dir),
        }
    )

    assert result["case_id"] == CASE_ID
    assert result["event_count"] == 1
    assert result["timeline_count"] == 1
    assert Path(str(result["timelines_path"])).is_file()
    assert Path(str(result["findings_path"])).is_file()
    assert Path(str(result["report_path"])).is_file()
    assert Path(str(result["audit_path"])).is_file()


def test_server_helper_rejects_invalid_request_paths(tmp_path: Path):
    with pytest.raises(ValueError, match="normalized input JSON does not exist"):
        server.run_correlation_workflow_tool(
            {
                "case_id": CASE_ID,
                "normalized_events_path": str(tmp_path / "missing.json"),
                "output_dir": str(tmp_path / "runs" / CASE_ID),
            }
        )
