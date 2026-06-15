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
    assert state.raw_policy_event_count == 1


def test_read_console_state_collapses_adjacent_policy_repeats_for_display(tmp_path: Path):
    for second in range(4):
        _append_jsonl(
            tmp_path / "policy_decisions.jsonl",
            {
                "timestamp_utc": f"2026-06-14T00:00:0{second}Z",
                "proposed_action": "validate_run_outputs",
                "decision": "allowed",
                "reason": "generated-output read only",
                "normalized_action": {"tool": "validate_run_outputs"},
            },
        )

    state = read_console_state(tmp_path)

    assert len(state.policy_events) == 1
    assert state.policy_events[0].repeat_count == 4
    assert state.policy_events[0].display_message.endswith("(x4)")
    assert state.raw_policy_event_count == 4


def test_read_console_state_keeps_non_adjacent_policy_repeats_visible(tmp_path: Path):
    rows = [
        ("2026-06-14T00:00:00Z", "validate_run_outputs", "allowed"),
        ("2026-06-14T00:00:01Z", "inspect_run_state", "allowed"),
        ("2026-06-14T00:00:02Z", "validate_run_outputs", "allowed"),
    ]
    for timestamp, action, decision in rows:
        _append_jsonl(
            tmp_path / "policy_decisions.jsonl",
            {
                "timestamp_utc": timestamp,
                "proposed_action": action,
                "decision": decision,
                "reason": "generated-output read only",
            },
        )

    state = read_console_state(tmp_path)

    assert [event.repeat_count for event in state.policy_events] == [1, 1, 1]
    assert [event.message for event in state.policy_events].count(
        "[policy] proposed validate_run_outputs -> allowed: generated-output read only"
    ) == 2


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


def test_read_console_state_includes_openclaw_log_tail(tmp_path: Path):
    broad_plugin = "co" + "dex"
    (tmp_path / "openclaw-console.log").write_text(
        "\n".join(
            [
                "line 1",
                "\x1b[35m[plugins]\x1b[39m \x1b[33mplugins.allow is empty; "
                f"discovered non-bundled plugins may auto-load: {broad_plugin} (...)\x1b[39m",
                "^[[35m[plugins]^[[39m ^[[33mplugins.allow is empty; "
                f"discovered non-bundled plugins may auto-load: {broad_plugin} (...)^[[39m",
                "Try: openclaw agent --help",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    state = read_console_state(tmp_path)

    assert (
        "[plugins] plugins.allow is empty; discovered non-bundled plugins may "
        f"auto-load: {broad_plugin} (...)"
    ) in state.openclaw_log_tail
    assert "\x1b" not in "\n".join(state.openclaw_log_tail)
    assert "^[" not in "\n".join(state.openclaw_log_tail)


def test_read_console_state_reports_pending_self_correction_when_absent(tmp_path: Path):
    state = read_console_state(tmp_path)

    assert state.self_correction_count == 0
    assert state.self_correction_status == "pending"
    assert state.latest_self_correction is None


def test_read_console_state_reports_pending_self_correction_for_active_run(tmp_path: Path):
    _write_json(tmp_path / "run_job.json", {"status": "running", "returncode": None})

    state = read_console_state(tmp_path)

    assert state.self_correction_count == 0
    assert state.self_correction_status == "pending"


def test_read_console_state_reports_empty_self_correction_artifact_after_completion(
    tmp_path: Path,
):
    _write_json(tmp_path / "run_job.json", {"status": "completed", "returncode": 0})
    _write_json(tmp_path / "validation_summary.json", {"validation_status": "pass"})
    _write_json(tmp_path / "self_correction_events.json", [])

    state = read_console_state(tmp_path)

    assert state.self_correction_count == 0
    assert state.self_correction_status == "none"
    assert state.errors == []


def test_read_console_state_keeps_empty_self_correction_pending_until_validation(
    tmp_path: Path,
):
    _write_json(tmp_path / "run_job.json", {"status": "completed", "returncode": 0})
    _write_json(tmp_path / "self_correction_events.json", [])

    state = read_console_state(tmp_path)

    assert state.self_correction_count == 0
    assert state.self_correction_status == "pending"


def test_read_console_state_reads_self_correction_events_json(tmp_path: Path):
    _write_json(
        tmp_path / "self_correction_events.json",
        {
            "events": [
                {
                    "event_id": "correction-001",
                    "correction": "Downgraded unsupported conclusion.",
                    "status": "needs_review",
                }
            ]
        },
    )

    state = read_console_state(tmp_path)

    assert state.self_correction_count == 1
    assert state.self_correction_status == "observed"
    assert state.latest_self_correction == "Downgraded unsupported conclusion."
    assert state.latest_corrected_claim_status == "needs_review"


def test_read_console_state_reads_self_correction_events_jsonl(tmp_path: Path):
    _append_jsonl(
        tmp_path / "self_correction_events.jsonl",
        {
            "timestamp_utc": "2026-06-14T00:00:00Z",
            "summary": "Rejected unsupported claim path.",
            "corrected_status": "rejected",
        },
    )

    state = read_console_state(tmp_path)

    assert state.self_correction_count == 1
    assert state.latest_self_correction == "Rejected unsupported claim path."
    assert state.latest_corrected_claim_status == "rejected"


def test_read_console_state_reads_latest_agent_run_correction(tmp_path: Path):
    _write_json(
        tmp_path / "agent_run.json",
        {
            "corrections": [
                {
                    "correction_id": "correction-001",
                    "created_at": "2026-06-14T00:00:00Z",
                    "action": "downgrade_finding",
                    "trigger": "unsupported_finding",
                    "result": "First correction.",
                },
                {
                    "correction_id": "correction-002",
                    "created_at": "2026-06-14T00:00:01Z",
                    "action": "downgrade_claim",
                    "trigger": "unsupported_claim",
                    "result": "Latest correction.",
                },
            ]
        },
    )

    state = read_console_state(tmp_path)

    assert state.self_correction_count == 2
    assert state.latest_self_correction == "Latest correction."
    assert state.latest_corrected_claim_status == "downgrade_claim"
