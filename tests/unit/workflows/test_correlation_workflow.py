from __future__ import annotations

import json
from pathlib import Path

import pytest

from elenchos.audit.execution_ledger import read_events
from elenchos.workflows.correlation import (
    load_normalized_timeline_events,
    run_correlation_workflow,
)

CASE_ID = "CASE-SYN-001"
SYNTHETIC_PATH = "C:/Users/Alice/AppData/Local/Temp/example-a.exe"
SYNTHETIC_HASH = "sha256:" + ("a" * 64)
FIXED_TIME = "2026-01-01T00:00:00Z"


def fixed_clock() -> str:
    return FIXED_TIME


def parser_event(
    *,
    artifact_id: str,
    artifact_type: str,
    parser_name: str,
    source_tool: str,
    event_type: str,
    timestamp_utc: str,
    path: str | None = SYNTHETIC_PATH,
    value_data: str | None = None,
    raw_source: str = "normalized.csv",
    row_number: int = 2,
) -> dict[str, object]:
    return {
        "case_id": CASE_ID,
        "artifact_id": artifact_id,
        "artifact_type": artifact_type,
        "parser_name": parser_name,
        "source_tool": source_tool,
        "event_type": event_type,
        "timestamp_utc": timestamp_utc,
        "timestamp_description": "SyntheticTimestamp",
        "subject": SYNTHETIC_PATH,
        "path": path,
        "value_data": value_data,
        "sha256": SYNTHETIC_HASH if artifact_type in {"mft", "amcache"} else None,
        "evidence_refs": [artifact_id],
        "raw_record_ref": {
            "source_path": raw_source,
            "row_number": row_number,
            "record_id": artifact_id,
        },
        "status": "normalized",
        "confidence": "tool_reported",
        "metadata": {"synthetic": True},
    }


def normalized_payload(events: list[dict[str, object]] | None = None) -> dict[str, object]:
    return {
        "case_id": CASE_ID,
        "events": events
        if events is not None
        else [
            parser_event(
                artifact_id="EV-SYN-MFT-001",
                artifact_type="mft",
                parser_name="mftecmd",
                source_tool="MFTECmd",
                event_type="file_created",
                timestamp_utc="2026-01-01T00:00:01Z",
                raw_source="mft.csv",
                row_number=1842,
            ),
            parser_event(
                artifact_id="EV-SYN-AMCACHE-001",
                artifact_type="amcache",
                parser_name="amcacheparser",
                source_tool="AmcacheParser",
                event_type="amcache_execution",
                timestamp_utc="2026-01-01T00:00:02Z",
                raw_source="amcache.csv",
                row_number=4,
            ),
            parser_event(
                artifact_id="EV-SYN-REG-001",
                artifact_type="registry",
                parser_name="recmd",
                source_tool="RECmd",
                event_type="registry_run_key",
                timestamp_utc="2026-01-01T00:00:03Z",
                path=None,
                value_data=SYNTHETIC_PATH,
                raw_source="runkeys.json",
                row_number=12,
            ),
        ],
    }


def write_input(tmp_path: Path, payload: dict[str, object] | None = None) -> Path:
    input_path = tmp_path / "normalized-events.json"
    input_path.write_text(
        json.dumps(payload if payload is not None else normalized_payload(), sort_keys=True),
        encoding="utf-8",
    )
    return input_path


def output_dir(tmp_path: Path) -> Path:
    return tmp_path / "runs" / CASE_ID


def test_workflow_reads_normalized_events_and_writes_expected_outputs(tmp_path: Path):
    result = run_correlation_workflow(
        case_id=CASE_ID,
        input_path=write_input(tmp_path),
        output_dir=output_dir(tmp_path),
        clock=fixed_clock,
    )

    assert result.event_count == 3
    assert result.timeline_count == 1
    assert result.finding_count == 1
    for path in (
        result.timelines_path,
        result.findings_path,
        result.report_path,
        result.audit_path,
    ):
        assert path is not None
        assert path.is_file()
        assert path.resolve().is_relative_to(output_dir(tmp_path).resolve())


def test_workflow_outputs_include_timelines_findings_report_and_audit(tmp_path: Path):
    result = run_correlation_workflow(
        case_id=CASE_ID,
        input_path=write_input(tmp_path),
        output_dir=output_dir(tmp_path),
        clock=fixed_clock,
    )

    timelines = json.loads(result.timelines_path.read_text(encoding="utf-8"))
    findings = json.loads(result.findings_path.read_text(encoding="utf-8"))
    report = result.report_path.read_text(encoding="utf-8") if result.report_path else ""
    audit_actions = [event["action"] for event in read_events(result.audit_path)]

    assert timelines["timeline_count"] == 1
    assert timelines["timelines"][0]["subject"] == SYNTHETIC_PATH
    assert findings["finding_count"] == 1
    assert findings["validation_results"][0]["final_status"] == "inferred"
    assert "## Subject Timeline" in report
    assert "## Inferred Findings" in report
    assert audit_actions == [
        "workflow_started",
        "input_loaded",
        "timelines_built",
        "claims_validated",
        "report_rendered",
        "workflow_completed",
    ]


def test_workflow_output_is_deterministic_for_same_input_and_clock(tmp_path: Path):
    input_path = write_input(tmp_path)
    out_dir = output_dir(tmp_path)

    first = run_correlation_workflow(
        case_id=CASE_ID,
        input_path=input_path,
        output_dir=out_dir,
        clock=fixed_clock,
    )
    first_payloads = {
        path.name: path.read_text(encoding="utf-8")
        for path in (
            first.timelines_path,
            first.findings_path,
            first.report_path,
            first.audit_path,
        )
        if path is not None
    }

    second = run_correlation_workflow(
        case_id=CASE_ID,
        input_path=input_path,
        output_dir=out_dir,
        clock=fixed_clock,
    )
    second_payloads = {
        path.name: path.read_text(encoding="utf-8")
        for path in (
            second.timelines_path,
            second.findings_path,
            second.report_path,
            second.audit_path,
        )
        if path is not None
    }

    assert first_payloads == second_payloads


def test_workflow_handles_empty_events_without_crashing(tmp_path: Path):
    result = run_correlation_workflow(
        case_id=CASE_ID,
        input_path=write_input(tmp_path, normalized_payload(events=[])),
        output_dir=output_dir(tmp_path),
        clock=fixed_clock,
    )

    timelines = json.loads(result.timelines_path.read_text(encoding="utf-8"))
    findings = json.loads(result.findings_path.read_text(encoding="utf-8"))
    assert result.event_count == 0
    assert result.timeline_count == 0
    assert result.finding_count == 0
    assert timelines["timelines"] == []
    assert findings["findings"] == []


def test_workflow_rejects_malformed_input_with_clear_error(tmp_path: Path):
    input_path = tmp_path / "normalized-events.json"
    input_path.write_text("{not-json", encoding="utf-8")

    with pytest.raises(ValueError, match="malformed normalized input JSON"):
        run_correlation_workflow(
            case_id=CASE_ID,
            input_path=input_path,
            output_dir=output_dir(tmp_path),
            clock=fixed_clock,
        )


def test_workflow_rejects_invalid_event_record_with_clear_error(tmp_path: Path):
    payload = {"case_id": CASE_ID, "events": [{"event_type": "drop"}]}

    with pytest.raises(ValueError, match="invalid normalized event at index 0"):
        run_correlation_workflow(
            case_id=CASE_ID,
            input_path=write_input(tmp_path, payload),
            output_dir=output_dir(tmp_path),
            clock=fixed_clock,
        )


def test_workflow_accepts_native_timeline_event_input(tmp_path: Path):
    input_path = write_input(
        tmp_path,
        {
            "case_id": CASE_ID,
            "events": [
                {
                    "event_type": "observation",
                    "timestamp": None,
                    "subject": "example-a.exe",
                    "source": "normalized-events",
                    "details": {"detail": "synthetic observation"},
                    "evidence_refs": [
                        {
                            "evidence_id": "EV-SYN-MFT-001",
                            "artifact_id": None,
                            "parser": "mftecmd",
                            "source": "$MFT",
                            "raw_record_ref": "csv:mft.csv:1842",
                            "timestamp_field": None,
                            "description": "Synthetic row.",
                        }
                    ],
                    "path": None,
                    "basename": "example-a.exe",
                    "ambiguous": False,
                    "ambiguity_reason": None,
                }
            ],
        },
    )

    events = load_normalized_timeline_events(case_id=CASE_ID, input_path=input_path)

    assert len(events) == 1
    assert events[0].event_type.value == "observation"


def test_workflow_rejects_non_generated_output_directory(tmp_path: Path):
    with pytest.raises(ValueError, match="ignored generated output path"):
        run_correlation_workflow(
            case_id=CASE_ID,
            input_path=write_input(tmp_path),
            output_dir=tmp_path / "case-output",
            clock=fixed_clock,
        )


def test_workflow_does_not_create_repo_root_runs_for_synthetic_case(tmp_path: Path):
    case_id = "CASE-SYN-NO-ROOT-RUNS-54"
    payload = normalized_payload(events=[])
    payload["case_id"] = case_id
    input_path = tmp_path / "normalized-events.json"
    input_path.write_text(json.dumps(payload), encoding="utf-8")

    run_correlation_workflow(
        case_id=case_id,
        input_path=input_path,
        output_dir=tmp_path / "runs" / case_id,
        clock=fixed_clock,
    )

    assert not (Path.cwd() / "runs" / case_id).exists()


def test_synthetic_outputs_contain_no_forbidden_paths_or_legal_overclaims(tmp_path: Path):
    result = run_correlation_workflow(
        case_id=CASE_ID,
        input_path=write_input(tmp_path),
        output_dir=output_dir(tmp_path),
        clock=fixed_clock,
    )
    combined = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (
            result.timelines_path,
            result.findings_path,
            result.report_path,
            result.audit_path,
        )
        if path is not None
    )
    lower_combined = combined.lower()

    for forbidden in ("/mnt/evidence", "/home/", ".local/"):
        assert forbidden not in combined
    for overclaim in (
        "proves " "compromise",
        "irrefutable",
        "guaranteed",
    ):
        assert overclaim not in lower_combined
