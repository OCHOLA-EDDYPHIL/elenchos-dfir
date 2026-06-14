from __future__ import annotations

import json
from pathlib import Path

from elenchos.integrations.run_state import inspect_run_state


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_case_prep(path: Path) -> None:
    artifact = path.parent / "extracted" / "mft" / "$MFT"
    artifact.parent.mkdir(parents=True, exist_ok=True)
    artifact.write_bytes(b"mft")
    _write_json(
        path,
        {
            "case_id": "case",
            "coverage_gaps": [],
            "prepared_artifacts": [
                {
                    "artifact_id": "prep_mft",
                    "artifact_type": "mft",
                    "parser_eligible": True,
                    "path": "extracted/mft/$MFT",
                    "source_id": "src1",
                    "status": "available",
                }
            ],
            "sources": [
                {
                    "analysis_scope": "primary",
                    "display_name": "source.E01",
                    "kind": "ewf_e01",
                    "role": "disk_image",
                    "source_id": "src1",
                    "status": "available",
                }
            ],
            "warnings": [],
        },
    )


def test_inspect_run_state_tolerates_missing_files(tmp_path: Path):
    output_dir = tmp_path / "runs" / "case" / "agent-run"

    summary = inspect_run_state(output_dir)

    assert summary.case_id is None
    assert summary.finding_status_counts == {}
    assert summary.recommended_next_actions == ["prepare_case"]


def test_inspect_run_state_counts_findings_and_questions(tmp_path: Path):
    output_dir = tmp_path / "runs" / "case" / "agent-run"
    _write_json(
        output_dir / "agent_run.json",
        {"case_id": "case", "status": "completed"},
    )
    _write_json(
        output_dir / "findings.json",
        {"findings": [{"status": "needs_review"}, {"status": "inferred"}]},
    )
    _write_json(
        output_dir / "case_questions.json",
        {
            "questions": [
                {"question": "Was theft supported?", "status": "not_assessed"},
                {"question": "What happened?", "status": "needs_review"},
            ]
        },
    )
    (output_dir / "report.md").write_text("# Report\n", encoding="utf-8")

    summary = inspect_run_state(output_dir)

    assert summary.finding_status_counts == {"inferred": 1, "needs_review": 1}
    assert summary.case_question_status_counts == {"needs_review": 1, "not_assessed": 1}
    assert summary.recommended_next_actions == ["summarize_run"]


def test_inspect_run_state_recommends_validation_after_summary(tmp_path: Path):
    output_dir = tmp_path / "runs" / "case" / "agent-run"
    _write_json(output_dir / "agent_run.json", {"case_id": "case"})
    _write_json(output_dir / "findings.json", {"findings": []})
    (output_dir / "report.md").write_text("# Report\n", encoding="utf-8")
    (output_dir / "progress.jsonl").write_text(
        json.dumps(
            {
                "timestamp": "2026-01-01T00:00:00Z",
                "case_id": "case",
                "phase": "summarize_run",
                "status": "completed",
                "message": "summarize_run completed",
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    summary = inspect_run_state(output_dir)

    assert summary.recommended_next_actions == ["validate_run_outputs"]


def test_inspect_run_state_recommends_claim_boundary(tmp_path: Path):
    output_dir = tmp_path / "runs" / "case" / "agent-run"
    _write_json(output_dir / "agent_run.json", {"case_id": "case"})
    _write_json(output_dir / "findings.json", {"findings": []})
    _write_json(
        output_dir / "case_questions.json",
        {
            "questions": [
                {
                    "question": "Was exfiltration supported?",
                    "status": "not_assessed",
                    "reason": "unsupported",
                }
            ]
        },
    )
    _write_json(output_dir / "validation_summary.json", {"validation_status": "pass"})
    (output_dir / "report.md").write_text("# Report\n", encoding="utf-8")
    (output_dir / "progress.jsonl").write_text(
        json.dumps(
            {
                "timestamp": "2026-01-01T00:00:00Z",
                "case_id": "case",
                "phase": "summarize_run",
                "status": "completed",
                "message": "summarize_run completed",
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    summary = inspect_run_state(output_dir)

    assert summary.claim_boundary_required is True
    assert summary.recommended_next_actions == ["emit_claim_boundary"]


def test_inspect_run_state_recommends_poll_for_active_job(tmp_path: Path):
    output_dir = tmp_path / "runs" / "case" / "agent-run"
    _write_json(output_dir / "run_job.json", {"status": "running", "job_id": "job_000001"})

    summary = inspect_run_state(output_dir)

    assert summary.active_job is not None
    assert summary.recommended_next_actions == ["poll_case_run"]


def test_inspect_run_state_returns_prepared_manifest_path(tmp_path: Path):
    output_dir = tmp_path / "runs" / "case" / "run"
    case_prep = tmp_path / "runs" / "case" / "prep" / "case_prep.json"
    _write_case_prep(case_prep)

    summary = inspect_run_state(output_dir)

    assert summary.prepared_manifest_path is not None
    assert summary.prepared_manifest_path.endswith("prep/case_prep.json")
    assert summary.prepared_manifest_validation is not None
    assert summary.recommended_next_actions == ["start_case_run", "run_case"]
