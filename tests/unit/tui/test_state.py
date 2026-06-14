from __future__ import annotations

import json
from pathlib import Path

from elenchos.tui.state import SAFE_FALLBACK_CLAIM_BOUNDARY, read_console_state


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, sort_keys=True) + "\n", encoding="utf-8")


def _append_jsonl(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, sort_keys=True))
        handle.write("\n")


def test_read_console_state_tolerates_empty_output_dir(tmp_path: Path):
    state = read_console_state(tmp_path)

    assert state.job_status is None
    assert state.validation_status == "pending"
    assert state.finding_counts == {}
    assert state.case_question_counts == {}
    assert state.claim_boundary == SAFE_FALLBACK_CLAIM_BOUNDARY


def test_read_console_state_reads_rationale_and_policy_messages(tmp_path: Path):
    _append_jsonl(
        tmp_path / "model_rationale.jsonl",
        {
            "timestamp_utc": "2026-06-14T00:00:00Z",
            "visible_message": "[model-rationale] Inspect generated state.",
        },
    )
    _append_jsonl(
        tmp_path / "policy_decisions.jsonl",
        {
            "timestamp_utc": "2026-06-14T00:00:01Z",
            "visible_policy_message": "[policy] proposed inspect_run_state -> allowed.",
        },
    )

    state = read_console_state(tmp_path)

    assert state.rationale_events[0].message == "[model-rationale] Inspect generated state."
    assert state.policy_events[0].message == "[policy] proposed inspect_run_state -> allowed."


def test_read_console_state_synthesizes_policy_line(tmp_path: Path):
    _append_jsonl(
        tmp_path / "policy_decisions.jsonl",
        {
            "timestamp_utc": "2026-06-14T00:00:01Z",
            "proposed_action": "poll_case_run",
            "decision": "allowed",
            "reason": "reads generated outputs only",
        },
    )

    state = read_console_state(tmp_path)

    assert state.policy_events[0].message == (
        "[policy] proposed poll_case_run -> allowed: reads generated outputs only"
    )


def test_read_console_state_reads_nested_run_level_files(tmp_path: Path):
    run_dir = tmp_path / "run"
    _write_json(run_dir / "run_job.json", {"status": "completed", "returncode": 0})
    _write_json(run_dir / "validation_summary.json", {"validation_status": "pass"})

    state = read_console_state(tmp_path)

    assert state.run_dir == run_dir.resolve()
    assert state.job_status == "completed"
    assert state.returncode == 0
    assert state.validation_status == "pass"


def test_read_console_state_deduplicates_root_and_run_policy_events(tmp_path: Path):
    row = {
        "timestamp_utc": "2026-06-14T00:00:01Z",
        "visible_policy_message": "[policy] proposed inspect_run_state -> allowed.",
    }
    _append_jsonl(tmp_path / "policy_decisions.jsonl", row)
    _append_jsonl(tmp_path / "run" / "policy_decisions.jsonl", row)

    state = read_console_state(tmp_path)

    assert [event.message for event in state.policy_events] == [
        "[policy] proposed inspect_run_state -> allowed."
    ]


def test_read_console_state_counts_statuses_and_normalized_events(tmp_path: Path):
    _write_json(
        tmp_path / "findings.json",
        {"findings": [{"status": "needs_review"}, {"status": "inferred"}]},
    )
    _write_json(
        tmp_path / "case_questions.json",
        {
            "questions": [
                {"status": "not_assessed"},
                {"status": "needs_review"},
                {"status": "needs_review"},
            ]
        },
    )
    _write_json(tmp_path / "normalized_events.json", {"events": [{}, {}, {}]})

    state = read_console_state(tmp_path)

    assert state.finding_counts == {"inferred": 1, "needs_review": 1}
    assert state.case_question_counts == {"needs_review": 2, "not_assessed": 1}
    assert state.normalized_events == 3


def test_read_console_state_prefers_generated_claim_boundary(tmp_path: Path):
    _write_json(
        tmp_path / "gap_analysis.json",
        {"claim_boundaries": [{"final_wording": "Generated conservative wording."}]},
    )

    state = read_console_state(tmp_path)

    assert state.claim_boundary == "Generated conservative wording."


def test_read_console_state_reports_invalid_json_without_crashing(tmp_path: Path):
    (tmp_path / "findings.json").write_text("{bad", encoding="utf-8")

    state = read_console_state(tmp_path)

    assert state.finding_counts == {}
    assert state.errors
