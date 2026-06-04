from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

import pytest

from siftguard.integrations import mcp_server
from siftguard.integrations.safe_paths import (
    resolve_user_path,
    validate_integration_output_dir,
)
from siftguard.integrations.tool_adapter import (
    dispatch_tool,
    get_tool_definitions,
    prepare_case,
    run_case,
    summarize_run,
    validate_run_outputs,
)
from siftguard.integrations.tool_adapter import (
    main as tool_adapter_main,
)

CASE_ID = "case-openclaw-test"


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_case_prep(path: Path, *, source_root: Path | None = None) -> None:
    source_root = source_root or path.parent.parent.parent / "evidence"
    _write_json(
        path,
        {
            "case_id": CASE_ID,
            "coverage_gaps": [],
            "created_at": "2026-01-01T00:00:00Z",
            "output_dir": "runs/case-openclaw-test/case-prep",
            "prepared_artifacts": [],
            "schema_version": 1,
            "source_set_id": "srcset_test",
            "sources": [
                {
                    "analysis_scope": "primary",
                    "display_name": "source.E01",
                    "hash_status": "not_requested",
                    "kind": "ewf_e01",
                    "local_path": str(source_root / "source.E01"),
                    "role": "disk_image",
                    "sanitized_path": "source.E01",
                    "sha256": None,
                    "size_bytes": 1,
                    "source_id": "src_test",
                    "source_ref": "source.E01",
                    "status": "available",
                }
            ],
            "status": "completed",
            "warnings": [],
        },
    )


def write_good_run(output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    _write_json(
        output_dir / "agent_run.json",
        {"case_id": CASE_ID, "status": "completed", "output_refs": {}},
    )
    (output_dir / "audit.jsonl").write_text(
        json.dumps({"case_id": CASE_ID, "event_type": "run_case_completed"}) + "\n",
        encoding="utf-8",
    )
    _write_json(
        output_dir / "decision_trace.json",
        {"case_id": CASE_ID, "decisions": [{"decision_id": "test"}]},
    )
    _write_json(output_dir / "gap_analysis.json", {"case_id": CASE_ID})
    _write_json(
        output_dir / "performance_summary.json",
        {"case_id": CASE_ID, "run_status": "completed"},
    )
    _write_json(
        output_dir / "findings.json",
        {
            "case_id": CASE_ID,
            "finding_count": 2,
            "findings": [
                {"finding_id": "f1", "status": "needs_review"},
                {"finding_id": "f2", "status": "inferred"},
            ],
            "validation_results": [],
        },
    )
    questions = [
        {
            "linked_evidence_refs": [],
            "question": "What was stolen?",
            "question_id": "q_what_was_stolen",
            "reason": "unsupported",
            "status": "not_assessed",
        },
        {
            "linked_evidence_refs": [],
            "question": "Where was it transferred?",
            "question_id": "q_where_transferred",
            "reason": "unsupported",
            "status": "not_assessed",
        },
        {
            "linked_evidence_refs": [],
            "question": "How was it stolen?",
            "question_id": "q_how_stolen",
            "reason": "unsupported",
            "status": "not_assessed",
        },
        {
            "linked_evidence_refs": [],
            "question": "What did memory show?",
            "question_id": "q_memory",
            "reason": "unsupported",
            "status": "not_assessed",
        },
        {
            "linked_evidence_refs": [{"event_id": "evt1"}],
            "question": "When did activity occur?",
            "question_id": "q_when_activity",
            "reason": "synthetic",
            "status": "needs_review",
        },
    ]
    _write_json(
        output_dir / "case_questions.json",
        {
            "case_id": CASE_ID,
            "questions": questions,
            "status_counts": {"needs_review": 1, "not_assessed": 4},
        },
    )
    _write_json(
        output_dir / "normalized_events.json",
        {
            "case_id": CASE_ID,
            "event_count": 3,
            "events": [
                {
                    "artifact_family": "amcache",
                    "artifact_type": "amcache",
                    "event_type": "amcache_execution",
                    "parser_name": "amcacheparser",
                },
                {
                    "artifact_family": "registry_user_activity",
                    "artifact_type": "recentdocs",
                    "event_type": "registry_recent_document_candidate",
                    "parser_name": "recmd",
                },
                {
                    "artifact_type": "mft",
                    "event_type": "file_created",
                    "parser_name": "mftecmd",
                },
            ],
        },
    )
    _write_json(
        output_dir / "coverage_summary.json",
        {
            "case_id": CASE_ID,
            "limitations": ["synthetic generated output"],
            "normalized_events_written": 3,
            "per_artifact": [
                {"artifact_type": "amcache", "parser_status": "success"},
                {"artifact_type": "mft", "parser_status": "partial_success"},
            ],
        },
    )
    (output_dir / "report.md").write_text(
        "# Report\n\nGenerated report with bounded language.\n",
        encoding="utf-8",
    )


def test_safe_path_validation_rejects_output_under_mnt_evidence():
    with pytest.raises(ValueError, match="evidence root"):
        validate_integration_output_dir("/mnt/evidence/runs/case/agent-run")


def test_safe_path_validation_rejects_path_traversal():
    with pytest.raises(ValueError, match="path traversal"):
        resolve_user_path("../outside", "output_dir")


def test_tool_adapter_rejects_unknown_operation():
    with pytest.raises(ValueError, match="unknown SIFTGuard integration operation"):
        dispatch_tool("shell", {})


def test_prepare_case_uses_argv_style_command_construction(tmp_path: Path):
    seen: list[list[str]] = []

    def runner(argv: list[str], timeout_seconds: int) -> subprocess.CompletedProcess[str]:
        assert isinstance(argv, list)
        assert all(isinstance(item, str) for item in argv)
        assert timeout_seconds == 60
        seen.append(argv)
        return subprocess.CompletedProcess(
            argv,
            0,
            "\n".join(
                [
                    f"case_id={CASE_ID}",
                    "status=completed",
                    "prepared_artifacts=2",
                    "coverage_gaps=1",
                    f"case_prep={tmp_path / 'runs' / CASE_ID / 'case-prep' / 'case_prep.json'}",
                ]
            ),
            "",
        )

    result = prepare_case(
        {
            "case_id": CASE_ID,
            "source_root": str(tmp_path / "evidence"),
            "output_dir": str(tmp_path / "runs" / CASE_ID / "case-prep"),
            "timeout_seconds": 60,
        },
        command_runner=runner,
    )

    assert result["status"] == "completed"
    assert result["prepared_artifact_count"] == 2
    assert result["coverage_gap_count"] == 1
    assert seen[0][:4] == [seen[0][0], "-m", "siftguard", "case"]
    assert "shell" not in seen[0]


def test_prepare_case_returns_structured_failure_from_mocked_subprocess(tmp_path: Path):
    def runner(argv: list[str], timeout_seconds: int) -> subprocess.CompletedProcess[str]:
        del timeout_seconds
        return subprocess.CompletedProcess(argv, 1, "", "error=source missing\n")

    result = prepare_case(
        {
            "case_id": CASE_ID,
            "source_root": str(tmp_path / "evidence"),
            "output_dir": str(tmp_path / "runs" / CASE_ID / "case-prep"),
        },
        command_runner=runner,
    )

    assert result["status"] == "failed"
    assert result["command_name"] == "siftguard case prepare"
    assert result["error"] == "error=source missing"
    assert str(result["trace_stdout"]).endswith("prepare_case.stdout")
    assert str(result["trace_stderr"]).endswith("prepare_case.stderr")


def test_prepare_case_sanitizes_private_paths_from_structured_failure(tmp_path: Path):
    private_path = "/tmp/PRIVATE-RAW-EVIDENCE-PATH-DO-NOT-LEAK/source.E01"

    def runner(argv: list[str], timeout_seconds: int) -> subprocess.CompletedProcess[str]:
        del timeout_seconds
        return subprocess.CompletedProcess(
            argv,
            1,
            "",
            f"error=source missing: {private_path}\n",
        )

    result = prepare_case(
        {
            "case_id": CASE_ID,
            "source_root": str(tmp_path / "evidence"),
            "output_dir": str(tmp_path / "runs" / CASE_ID / "case-prep"),
        },
        command_runner=runner,
    )

    serialized = json.dumps(result, sort_keys=True)
    assert result["status"] == "failed"
    assert result["error"] == "error=source missing: <redacted_path>"
    assert "PRIVATE-RAW-EVIDENCE-PATH-DO-NOT-LEAK" not in serialized


def test_prepare_case_rejects_shell_like_case_id_before_runner():
    called = False

    def runner(argv: list[str], timeout_seconds: int) -> subprocess.CompletedProcess[str]:
        nonlocal called
        called = True
        return subprocess.CompletedProcess(argv, 0, "", "")

    with pytest.raises(ValueError, match="forbidden character"):
        prepare_case(
            {
                "case_id": "case;rm -rf",
                "source_root": "runs/synthetic-source",
                "output_dir": "runs/shell-like/case-prep",
            },
            command_runner=runner,
        )

    assert called is False


def test_run_case_returns_structured_result_from_mocked_subprocess(tmp_path: Path):
    case_prep = tmp_path / "runs" / CASE_ID / "case-prep" / "case_prep.json"
    output_dir = tmp_path / "runs" / CASE_ID / "agent-run"
    write_case_prep(case_prep)

    def runner(argv: list[str], timeout_seconds: int) -> subprocess.CompletedProcess[str]:
        assert isinstance(argv, list)
        assert "run-case" in argv
        assert timeout_seconds == 60
        write_good_run(output_dir)
        return subprocess.CompletedProcess(
            argv,
            0,
            "\n".join(
                [
                    f"case_id={CASE_ID}",
                    "status=completed",
                    "steps=6",
                    f"audit={output_dir / 'audit.jsonl'}",
                    f"case_questions={output_dir / 'case_questions.json'}",
                    f"decision_trace={output_dir / 'decision_trace.json'}",
                    f"gap_analysis={output_dir / 'gap_analysis.json'}",
                    f"performance_summary={output_dir / 'performance_summary.json'}",
                ]
            ),
            "",
        )

    result = run_case(
        {
            "artifact_manifest": str(case_prep),
            "case_id": CASE_ID,
            "output_dir": str(output_dir),
            "timeout_seconds": 60,
        },
        command_runner=runner,
    )

    assert result["status"] == "completed"
    assert result["command_name"] == "siftguard agent run-case"
    assert result["finding_status_counts"] == {"inferred": 1, "needs_review": 1}
    assert result["case_question_status_counts"] == {"needs_review": 1, "not_assessed": 4}
    assert "parser_status_summary" in result


def test_run_case_sanitizes_private_paths_from_structured_failure(tmp_path: Path):
    case_prep = tmp_path / "runs" / CASE_ID / "case-prep" / "case_prep.json"
    output_dir = tmp_path / "runs" / CASE_ID / "agent-run"
    write_case_prep(case_prep)

    def runner(argv: list[str], timeout_seconds: int) -> subprocess.CompletedProcess[str]:
        del timeout_seconds
        return subprocess.CompletedProcess(
            argv,
            1,
            "",
            "error=casebook missing: /mnt/evidence/private/casebook.json\n",
        )

    result = run_case(
        {
            "artifact_manifest": str(case_prep),
            "case_id": CASE_ID,
            "output_dir": str(output_dir),
        },
        command_runner=runner,
    )

    assert result["status"] == "failed"
    assert result["error"] == "error=casebook missing: <redacted_path>"
    assert "/mnt/evidence/private" not in json.dumps(result, sort_keys=True)


def test_summarize_run_parses_counts_and_traceability(tmp_path: Path):
    output_dir = tmp_path / "runs" / CASE_ID / "agent-run"
    write_good_run(output_dir)
    trace_dir = output_dir / "openclaw-trace"
    trace_dir.mkdir()
    (trace_dir / "run_case.stdout").write_text("ok\n", encoding="utf-8")
    (trace_dir / "run_case.stderr").write_text("", encoding="utf-8")

    summary = summarize_run({"output_dir": str(output_dir)})

    assert summary["finding_status_counts"] == {"inferred": 1, "needs_review": 1}
    assert summary["case_question_status_counts"] == {"needs_review": 1, "not_assessed": 4}
    assert summary["amcache_event_count"] == 1
    assert summary["registry_user_activity_family_counts"] == {"recentdocs": 1}
    trace_files = summary["required_trace_files"]
    assert isinstance(trace_files, dict)
    assert trace_files["audit"].endswith("audit.jsonl")
    assert trace_files["decision_trace"].endswith("decision_trace.json")
    assert trace_files["trace_run_case_stdout"].endswith("run_case.stdout")
    assert trace_files["trace_run_case_stderr"].endswith("run_case.stderr")


def test_validate_run_outputs_passes_for_safe_generated_outputs(tmp_path: Path):
    output_dir = tmp_path / "runs" / CASE_ID / "agent-run"
    write_good_run(output_dir)

    validation = validate_run_outputs({"output_dir": str(output_dir)})

    assert validation["validation_status"] == "pass"
    assert validation["missing_files"] == []
    assert validation["forbidden_wording_hits"] == []
    assert validation["unsupported_question_violations"] == []


def test_validate_run_outputs_fails_on_forbidden_wording(tmp_path: Path):
    output_dir = tmp_path / "runs" / CASE_ID / "agent-run"
    write_good_run(output_dir)
    (output_dir / "report.md").write_text("This proved compromise.\n", encoding="utf-8")

    validation = validate_run_outputs({"output_dir": str(output_dir)})

    assert validation["validation_status"] == "fail"
    assert validation["forbidden_wording_hits"] == [{"line": 1, "phrase": "proved compromise"}]


def test_validate_run_outputs_detects_missing_required_files(tmp_path: Path):
    output_dir = tmp_path / "runs" / CASE_ID / "agent-run"
    write_good_run(output_dir)
    (output_dir / "decision_trace.json").unlink()

    validation = validate_run_outputs({"output_dir": str(output_dir)})

    assert validation["validation_status"] == "fail"
    assert validation["missing_files"] == ["decision_trace.json"]


def test_validate_run_outputs_detects_unsupported_question_evidence_refs(
    tmp_path: Path,
):
    output_dir = tmp_path / "runs" / CASE_ID / "agent-run"
    write_good_run(output_dir)
    payload = json.loads((output_dir / "case_questions.json").read_text(encoding="utf-8"))
    payload["questions"][0]["linked_evidence_refs"] = [{"event_id": "raw_evt"}]
    _write_json(output_dir / "case_questions.json", payload)

    validation = validate_run_outputs({"output_dir": str(output_dir)})

    assert validation["validation_status"] == "fail"
    violations = validation["unsupported_question_violations"]
    assert isinstance(violations, list)
    assert violations[0]["question_id"] == "q_what_was_stolen"


def test_summarize_and_validate_do_not_read_raw_evidence_paths(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    output_dir = tmp_path / "runs" / CASE_ID / "agent-run"
    raw_evidence = tmp_path / "evidence" / "raw-secret.txt"
    raw_evidence.parent.mkdir()
    raw_evidence.write_text("raw evidence content must not be read", encoding="utf-8")
    write_good_run(output_dir)
    gap_payload = {"case_id": CASE_ID, "raw_path_for_test": str(raw_evidence)}
    _write_json(output_dir / "gap_analysis.json", gap_payload)

    original_read_text = Path.read_text

    def guarded_read_text(self: Path, *args: Any, **kwargs: Any) -> str:
        if self.resolve() == raw_evidence.resolve():
            raise AssertionError("raw evidence file was read")
        return original_read_text(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", guarded_read_text)

    summarize_run({"output_dir": str(output_dir)})
    validate_run_outputs({"output_dir": str(output_dir)})


def test_mcp_server_exposes_tools_and_calls_summary(tmp_path: Path):
    output_dir = tmp_path / "runs" / CASE_ID / "agent-run"
    write_good_run(output_dir)

    init_response = mcp_server.handle_message(
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
    )
    tools_response = mcp_server.handle_message(
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
    )
    call_response = mcp_server.handle_message(
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "summarize_run",
                "arguments": {"output_dir": str(output_dir)},
            },
        }
    )

    assert init_response is not None
    assert init_response["result"]["serverInfo"]["name"] == "siftguard-openclaw-adapter"
    assert tools_response is not None
    tools = tools_response["result"]["tools"]
    assert {tool["name"] for tool in tools} == {
        "prepare_case",
        "run_case",
        "summarize_run",
        "validate_run_outputs",
    }
    assert call_response is not None
    structured = call_response["result"]["structuredContent"]
    assert structured["case_question_status_counts"] == {"needs_review": 1, "not_assessed": 4}


def test_mcp_server_sanitizes_exception_paths_in_tool_errors():
    response = mcp_server.handle_message(
        {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "prepare_case",
                "arguments": {
                    "case_id": CASE_ID,
                    "source_root": "/tmp/PRIVATE-MCP-PATH",
                    "source_manifest_out": "/tmp/PRIVATE-MCP-PATH/source.json",
                    "output_dir": "runs/mcp-error-probe/case-prep",
                },
            },
        }
    )

    assert response is not None
    result = response["result"]
    assert result["isError"] is True
    structured = result["structuredContent"]
    assert (
        structured["error"]
        == "source_manifest_out must not be under evidence root '<redacted_path>'"
    )
    assert "PRIVATE-MCP-PATH" not in json.dumps(result, sort_keys=True)


def test_cli_dispatcher_sanitizes_exception_paths(capsys: pytest.CaptureFixture[str]):
    return_code = tool_adapter_main(
        ["summarize-run", "--json-input", "@/tmp/PRIVATE-CLI-PATH/input.json"]
    )

    output = capsys.readouterr().out
    payload = json.loads(output)
    assert return_code == 1
    assert payload["status"] == "failed"
    assert "<redacted_path>" in payload["error"]
    assert "PRIVATE-CLI-PATH" not in output


def test_tool_manifest_has_no_arbitrary_execution_fields():
    manifest = json.dumps(get_tool_definitions(), sort_keys=True)
    for forbidden in ("shell", "cmd", "executable", "raw_evidence_bytes"):
        assert forbidden not in manifest
