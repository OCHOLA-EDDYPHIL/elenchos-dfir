from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

import pytest

from elenchos.integrations import mcp_server
from elenchos.integrations.safe_paths import (
    resolve_user_path,
    validate_integration_output_dir,
)
from elenchos.integrations.tool_adapter import (
    dispatch_tool,
    get_tool_definitions,
    prepare_case,
    run_case,
    summarize_run,
    validate_run_outputs,
)
from elenchos.integrations.tool_adapter import (
    main as tool_adapter_main,
)
from elenchos.validation.integrity import write_integrity_manifest

CASE_ID = "case-openclaw-test"
FINAL_WORDING = "Elenchos kept the configured claim not_assessed."
SCOPE_BOUNDARY = "The submitted artifact scope does not support this configured claim."


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
        output_dir / "self_correction_events.json",
        {
            "case_id": CASE_ID,
            "created_at": "2026-01-01T00:00:00Z",
            "event_count": 1,
            "events": [
                {
                    "event_id": "claim-boundary-001",
                    "final_wording": FINAL_WORDING,
                    "human_intervention": False,
                    "phase": "claim_validation",
                    "scope_boundary": SCOPE_BOUNDARY,
                    "source_question_ids": [
                        "q_claim_subject",
                        "q_claim_transfer",
                        "q_claim_method",
                        "q_claim_context",
                    ],
                }
            ],
            "mode": "claim_boundary_self_correction",
        },
    )
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
            "question": "What claim subject is supported?",
            "question_id": "q_claim_subject",
            "reason": "unsupported",
            "supported_by_current_scope": False,
            "status": "not_assessed",
        },
        {
            "linked_evidence_refs": [],
            "question": "What transfer path is supported?",
            "question_id": "q_claim_transfer",
            "reason": "unsupported",
            "supported_by_current_scope": False,
            "status": "not_assessed",
        },
        {
            "linked_evidence_refs": [],
            "question": "What method is supported?",
            "question_id": "q_claim_method",
            "reason": "unsupported",
            "supported_by_current_scope": False,
            "status": "not_assessed",
        },
        {
            "linked_evidence_refs": [],
            "question": "What additional context is supported?",
            "question_id": "q_claim_context",
            "reason": "unsupported",
            "supported_by_current_scope": False,
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
    write_integrity_manifest(output_dir)


def test_safe_path_validation_rejects_output_under_mnt_evidence():
    with pytest.raises(ValueError, match="evidence root"):
        validate_integration_output_dir("/mnt/evidence/runs/case/agent-run")


def test_safe_path_validation_rejects_path_traversal():
    with pytest.raises(ValueError, match="path traversal"):
        resolve_user_path("../outside", "output_dir")


def test_tool_adapter_rejects_unknown_operation():
    with pytest.raises(ValueError, match="unknown Elenchos integration operation"):
        dispatch_tool("shell", {})


def test_dispatch_self_gates_tool_calls_with_policy(tmp_path: Path):
    output_dir = tmp_path / "runs" / CASE_ID / "agent-run"
    write_good_run(output_dir)

    result = dispatch_tool("inspect_run_state", {"output_dir": str(output_dir)})

    assert result["status"] == "completed"
    assert str(result["visible_policy_message"]).startswith(
        "[policy] proposed inspect_run_state -> allowed"
    )
    policy_path = output_dir / "policy_decisions.jsonl"
    assert policy_path.is_file()
    assert "[policy]" in policy_path.read_text(encoding="utf-8")


def test_dispatch_rejects_policy_blocked_start_before_launch(tmp_path: Path):
    output_dir = tmp_path / "runs" / CASE_ID / "agent-run"
    bad_manifest = output_dir / "run_integrity_manifest.json"
    bad_manifest.parent.mkdir(parents=True)
    bad_manifest.write_text("{}\n", encoding="utf-8")

    with pytest.raises(ValueError, match="start_case_run rejected by policy"):
        dispatch_tool(
            "start_case_run",
            {
                "output_dir": str(output_dir),
                "prepared_manifest_path": str(bad_manifest),
            },
        )

    policy_text = (output_dir / "policy_decisions.jsonl").read_text(encoding="utf-8")
    assert "[policy] proposed start_case_run -> rejected" in policy_text


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
    assert str(result["prepared_manifest_path"]).endswith("case_prep.json")
    assert seen[0][:4] == [seen[0][0], "-m", "elenchos", "case"]
    assert "shell" not in seen[0]


def test_prepare_case_default_timeout_is_unbounded_and_progress_is_written(tmp_path: Path):
    output_dir = tmp_path / "runs" / CASE_ID / "case-prep"
    seen_timeout: list[int | None] = []

    def runner(
        argv: list[str],
        timeout_seconds: int | None,
    ) -> subprocess.CompletedProcess[str]:
        seen_timeout.append(timeout_seconds)
        return subprocess.CompletedProcess(
            argv,
            0,
            "\n".join(
                [
                    f"case_id={CASE_ID}",
                    "status=completed",
                    "prepared_artifacts=1",
                    "coverage_gaps=0",
                    f"case_prep={output_dir / 'case_prep.json'}",
                ]
            ),
            "",
        )

    result = prepare_case(
        {
            "case_id": CASE_ID,
            "source_root": str(tmp_path / "evidence"),
            "output_dir": str(output_dir),
        },
        command_runner=runner,
    )

    assert result["status"] == "completed"
    assert seen_timeout == [None]
    progress_rows = [
        json.loads(line)
        for line in (output_dir / "progress.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    assert [row["status"] for row in progress_rows] == ["started", "completed"]
    assert {row["phase"] for row in progress_rows} == {"prepare_case"}


def test_prepare_case_uses_env_timeout_override(tmp_path: Path, monkeypatch):
    output_dir = tmp_path / "runs" / CASE_ID / "case-prep"
    seen_timeout: list[int | None] = []

    def runner(
        argv: list[str],
        timeout_seconds: int | None,
    ) -> subprocess.CompletedProcess[str]:
        seen_timeout.append(timeout_seconds)
        return subprocess.CompletedProcess(
            argv,
            0,
            f"case_id={CASE_ID}\nstatus=completed\ncase_prep={output_dir / 'case_prep.json'}",
            "",
        )

    monkeypatch.setenv("ELENCHOS_PREPARE_TIMEOUT_SECONDS", "123")

    prepare_case(
        {
            "case_id": CASE_ID,
            "source_root": str(tmp_path / "evidence"),
            "output_dir": str(output_dir),
        },
        command_runner=runner,
    )

    assert seen_timeout == [123]


def test_prepare_case_explicit_timeout_wins_over_env(tmp_path: Path, monkeypatch):
    output_dir = tmp_path / "runs" / CASE_ID / "case-prep"
    seen_timeout: list[int | None] = []

    def runner(
        argv: list[str],
        timeout_seconds: int | None,
    ) -> subprocess.CompletedProcess[str]:
        seen_timeout.append(timeout_seconds)
        return subprocess.CompletedProcess(
            argv,
            0,
            f"case_id={CASE_ID}\nstatus=completed\ncase_prep={output_dir / 'case_prep.json'}",
            "",
        )

    monkeypatch.setenv("ELENCHOS_PREPARE_TIMEOUT_SECONDS", "123")

    prepare_case(
        {
            "case_id": CASE_ID,
            "source_root": str(tmp_path / "evidence"),
            "output_dir": str(output_dir),
            "timeout_seconds": 60,
        },
        command_runner=runner,
    )

    assert seen_timeout == [60]


def test_prepare_case_invalid_env_timeout_fails_before_launch(
    tmp_path: Path,
    monkeypatch,
):
    called = False

    def runner(argv: list[str], timeout_seconds: int | None) -> subprocess.CompletedProcess[str]:
        nonlocal called
        called = True
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setenv("ELENCHOS_PREPARE_TIMEOUT_SECONDS", "soon")

    with pytest.raises(ValueError, match="ELENCHOS_PREPARE_TIMEOUT_SECONDS"):
        prepare_case(
            {
                "case_id": CASE_ID,
                "source_root": str(tmp_path / "evidence"),
                "output_dir": str(tmp_path / "runs" / CASE_ID / "case-prep"),
            },
            command_runner=runner,
        )

    assert called is False


def test_prepare_case_generates_human_readable_case_id_when_omitted(tmp_path: Path):
    seen: list[list[str]] = []

    def runner(argv: list[str], timeout_seconds: int) -> subprocess.CompletedProcess[str]:
        del timeout_seconds
        seen.append(argv)
        case_id = argv[argv.index("--case-id") + 1]
        return subprocess.CompletedProcess(
            argv,
            0,
            "\n".join(
                [
                    f"case_id={case_id}",
                    "status=completed",
                    "prepared_artifacts=0",
                    "coverage_gaps=0",
                ]
            ),
            "",
        )

    result = prepare_case(
        {
            "source_root": str(tmp_path / "ROCBA Evidence"),
            "output_dir": str(tmp_path / "runs" / "auto" / "case-prep"),
        },
        command_runner=runner,
    )

    generated_case_id = seen[0][seen[0].index("--case-id") + 1]
    assert generated_case_id.startswith("rocba-evidence-20")
    assert result["case_id"] == generated_case_id


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
    assert result["command_name"] == "elenchos case prepare"
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
                    f"self_correction_events={output_dir / 'self_correction_events.json'}",
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
    assert result["command_name"] == "elenchos agent run-case"
    assert result["finding_status_counts"] == {"inferred": 1, "needs_review": 1}
    assert result["case_question_status_counts"] == {"needs_review": 1, "not_assessed": 4}
    assert str(result["self_correction_events"]).endswith("self_correction_events.json")
    assert str(result["integrity_manifest"]).endswith("run_integrity_manifest.json")
    assert "parser_status_summary" in result


def test_run_case_defaults_case_id_from_case_prep(tmp_path: Path):
    case_prep = tmp_path / "runs" / CASE_ID / "case-prep" / "case_prep.json"
    output_dir = tmp_path / "runs" / CASE_ID / "agent-run"
    write_case_prep(case_prep)
    seen: list[list[str]] = []

    def runner(argv: list[str], timeout_seconds: int) -> subprocess.CompletedProcess[str]:
        del timeout_seconds
        seen.append(argv)
        write_good_run(output_dir)
        return subprocess.CompletedProcess(argv, 0, f"case_id={CASE_ID}\nstatus=completed\n", "")

    result = run_case(
        {
            "artifact_manifest": str(case_prep),
            "output_dir": str(output_dir),
        },
        command_runner=runner,
    )

    assert result["case_id"] == CASE_ID
    assert seen[0][seen[0].index("--case-id") + 1] == CASE_ID


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
    assert summary["real_gap_self_correction_events"][0]["final_wording"] == FINAL_WORDING
    assert summary["amcache_event_count"] == 1
    assert summary["registry_user_activity_family_counts"] == {"recentdocs": 1}
    assert summary["progress_trace"].endswith("progress.jsonl")
    assert summary["progress_event_count"] == 1
    trace_files = summary["required_trace_files"]
    assert isinstance(trace_files, dict)
    assert trace_files["audit"].endswith("audit.jsonl")
    assert trace_files["decision_trace"].endswith("decision_trace.json")
    assert trace_files["self_correction_events"].endswith("self_correction_events.json")
    assert trace_files["progress"].endswith("progress.jsonl")
    assert trace_files["trace_run_case_stdout"].endswith("run_case.stdout")
    assert trace_files["trace_run_case_stderr"].endswith("run_case.stderr")


def test_validate_run_outputs_passes_for_safe_generated_outputs(tmp_path: Path):
    output_dir = tmp_path / "runs" / CASE_ID / "agent-run"
    write_good_run(output_dir)

    validation = validate_run_outputs({"output_dir": str(output_dir)})

    assert validation["validation_status"] == "pass"
    assert validation["missing_files"] == []
    assert "progress.jsonl" not in validation["missing_files"]
    assert validation["forbidden_wording_hits"] == []
    assert validation["unsupported_question_violations"] == []
    assert validation["self_correction_event_count"] == 1
    assert validation["integrity_violations"] == []
    assert "run integrity manifest hashes verified" in validation["notes"]
    assert FINAL_WORDING in validation["notes"]


def test_validate_run_outputs_accepts_optional_progress_trace(tmp_path: Path):
    output_dir = tmp_path / "runs" / CASE_ID / "agent-run"
    write_good_run(output_dir)
    (output_dir / "progress.jsonl").write_text(
        json.dumps(
            {
                "timestamp": "2026-01-01T00:00:00Z",
                "case_id": CASE_ID,
                "phase": "run_case",
                "status": "completed",
                "message": "run_case completed",
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    validation = validate_run_outputs({"output_dir": str(output_dir)})

    assert validation["validation_status"] == "pass"
    assert validation["progress_trace"].endswith("progress.jsonl")
    assert validation["progress_event_count"] == 2


def test_validate_run_outputs_fails_on_forbidden_wording(tmp_path: Path):
    output_dir = tmp_path / "runs" / CASE_ID / "agent-run"
    write_good_run(output_dir)
    (output_dir / "report.md").write_text("This proved compromise.\n", encoding="utf-8")

    validation = validate_run_outputs({"output_dir": str(output_dir)})

    assert validation["validation_status"] == "fail"
    assert validation["forbidden_wording_hits"] == [{"line": 1, "phrase": "proved compromise"}]
    assert validation["integrity_violations"]


def test_validate_run_outputs_fails_when_integrity_manifest_is_missing(tmp_path: Path):
    output_dir = tmp_path / "runs" / CASE_ID / "agent-run"
    write_good_run(output_dir)
    (output_dir / "run_integrity_manifest.json").unlink()

    validation = validate_run_outputs({"output_dir": str(output_dir)})

    assert validation["validation_status"] == "fail"
    assert "run_integrity_manifest.json" in validation["missing_files"]
    assert validation["integrity_violations"] == [
        {
            "path": "run_integrity_manifest.json",
            "reason": "missing_integrity_manifest",
        }
    ]


def test_validate_run_outputs_detects_tampered_generated_output(tmp_path: Path):
    output_dir = tmp_path / "runs" / CASE_ID / "agent-run"
    write_good_run(output_dir)
    (output_dir / "report.md").write_text(
        "# Report\n\nGenerated report with bounded language.\nExtra line.\n",
        encoding="utf-8",
    )

    validation = validate_run_outputs({"output_dir": str(output_dir)})

    assert validation["validation_status"] == "fail"
    assert any(
        row["path"] == "report.md" and row["reason"] in {"size_mismatch", "sha256_mismatch"}
        for row in validation["integrity_violations"]
    )


def test_validate_run_outputs_reports_malformed_integrity_manifest(tmp_path: Path):
    output_dir = tmp_path / "runs" / CASE_ID / "agent-run"
    write_good_run(output_dir)
    (output_dir / "run_integrity_manifest.json").write_text("{not-json\n", encoding="utf-8")

    validation = validate_run_outputs({"output_dir": str(output_dir)})

    assert validation["validation_status"] == "fail"
    assert validation["integrity_violations"][0]["reason"] == "malformed_integrity_manifest"


def test_validate_run_outputs_detects_missing_required_files(tmp_path: Path):
    output_dir = tmp_path / "runs" / CASE_ID / "agent-run"
    write_good_run(output_dir)
    (output_dir / "decision_trace.json").unlink()
    (output_dir / "self_correction_events.json").unlink()

    validation = validate_run_outputs({"output_dir": str(output_dir)})

    assert validation["validation_status"] == "fail"
    assert validation["missing_files"] == [
        "decision_trace.json",
        "self_correction_events.json",
    ]


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
    assert violations[0]["question_id"] == "q_claim_subject"


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
    assert init_response["result"]["serverInfo"]["name"] == "elenchos-openclaw-adapter"
    assert tools_response is not None
    tools = tools_response["result"]["tools"]
    assert {tool["name"] for tool in tools} == {
        "emit_claim_boundary",
        "evaluate_action_policy",
        "finish_case_run",
        "inspect_run_state",
        "poll_case_run",
        "prepare_case",
        "record_model_rationale",
        "run_case",
        "summarize_run",
        "start_case_run",
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
    for forbidden in ("cmd", "executable", "raw_evidence_bytes"):
        assert forbidden not in manifest
