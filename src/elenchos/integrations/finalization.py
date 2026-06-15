from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from elenchos.audit.execution_ledger import utc_now
from elenchos.integrations.rationale_trace import (
    POLICY_DECISIONS_FILENAME,
    RUN_JOB_FILENAME,
    append_orchestration_event,
    safe_read_json,
)
from elenchos.integrations.safe_paths import display_path
from elenchos.progress import progress_path_for_output_dir

ORCHESTRATION_FINALIZATION_FILENAME = "orchestration_finalization.json"
MAX_POST_VALIDATION_ACTIONS = 3
POST_VALIDATION_ALLOWED_ACTIONS = {"summarize_run", "emit_claim_boundary", "stop"}
TERMINAL_STATUS = "DONE"
UNSUPPORTED_BOUNDARY_TERMS = (
    "theft",
    "stolen",
    "exfiltration",
    "transfer",
    "memory",
    "compromise",
    "malware",
    "attribution",
)
UNSUPPORTED_BOUNDARY_STATUSES = {"not_assessed", "needs_review", "unsupported"}


def finalization_path(agent_run_dir: Path) -> Path:
    return agent_run_dir / ORCHESTRATION_FINALIZATION_FILENAME


def read_finalization(agent_run_dir: Path) -> dict[str, Any] | None:
    return safe_read_json(finalization_path(agent_run_dir))


def is_finalized(agent_run_dir: Path) -> bool:
    payload = read_finalization(agent_run_dir)
    return payload is not None and payload.get("status") == TERMINAL_STATUS


def mark_claim_boundary_emitted(agent_run_dir: Path) -> None:
    append_orchestration_event(
        agent_run_dir,
        event_type="emit_claim_boundary",
        payload={"status": "completed"},
    )


def maybe_finalize_orchestration(
    agent_run_dir: Path,
    *,
    reason: str | None = None,
) -> dict[str, Any] | None:
    existing = read_finalization(agent_run_dir)
    if existing is not None and existing.get("status") == TERMINAL_STATUS:
        return existing
    state = terminal_state(agent_run_dir)
    if not state["terminal_condition_met"]:
        return None
    return force_finalize_orchestration(
        agent_run_dir,
        reason=reason or str(state["reason"]),
        terminal_state=state,
    )


def force_finalize_orchestration(
    agent_run_dir: Path,
    *,
    reason: str,
    terminal_state: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    state = dict(terminal_state or terminal_state_snapshot(agent_run_dir))
    payload: dict[str, Any] = {
        "schema_version": 1,
        "status": TERMINAL_STATUS,
        "finalized": True,
        "reason": reason,
        "created_at_utc": utc_now(),
        "updated_at_utc": utc_now(),
        "output_dir": display_path(agent_run_dir),
        "terminal_state": state,
        "max_post_validation_actions": MAX_POST_VALIDATION_ACTIONS,
        "post_validation_action_count": post_validation_action_count(agent_run_dir),
    }
    path = finalization_path(agent_run_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    append_orchestration_event(
        agent_run_dir,
        event_type="orchestration_finalized",
        payload={
            "status": TERMINAL_STATUS,
            "reason": reason,
            "post_validation_action_count": payload["post_validation_action_count"],
        },
    )
    return payload


def terminal_state(agent_run_dir: Path) -> dict[str, Any]:
    state = terminal_state_snapshot(agent_run_dir)
    met = bool(
        state["run_completed_ok"]
        and state["summary_completed"]
        and state["validation_passed"]
        and state["claim_boundary_satisfied"]
    )
    reason = (
        "run completed, summary generated, validation passed, and claim boundary satisfied"
        if met
        else "waiting for deterministic completion, validation, or claim boundary"
    )
    state["terminal_condition_met"] = met
    state["reason"] = reason
    return state


def terminal_state_snapshot(agent_run_dir: Path) -> dict[str, Any]:
    boundary_required = claim_boundary_required(agent_run_dir)
    boundary_emitted = progress_has_phase(agent_run_dir, "emit_claim_boundary")
    return {
        "run_completed_ok": run_completed_ok(agent_run_dir),
        "summary_completed": progress_has_phase(agent_run_dir, "summarize_run"),
        "validation_passed": validation_passed(agent_run_dir),
        "claim_boundary_required": boundary_required,
        "claim_boundary_emitted": boundary_emitted,
        "claim_boundary_satisfied": (not boundary_required) or boundary_emitted,
    }


def run_completed_ok(agent_run_dir: Path) -> bool:
    job = safe_read_json(agent_run_dir / RUN_JOB_FILENAME)
    if job is None:
        return False
    return job.get("status") == "completed" and job.get("returncode") == 0


def validation_passed(agent_run_dir: Path) -> bool:
    validation = safe_read_json(agent_run_dir / "validation_summary.json")
    return validation is not None and validation.get("validation_status") == "pass"


def progress_has_phase(agent_run_dir: Path, phase: str) -> bool:
    path = progress_path_for_output_dir(agent_run_dir)
    if not path.exists():
        return False
    try:
        rows = _jsonl_rows(path)
    except ValueError:
        return False
    return any(row.get("phase") == phase and row.get("status") == "completed" for row in rows)


def post_validation_action_count(agent_run_dir: Path) -> int:
    path = agent_run_dir / POLICY_DECISIONS_FILENAME
    if not path.exists():
        return 0
    try:
        rows = _jsonl_rows(path)
    except ValueError:
        return 0
    total = 0
    for row in rows:
        if row.get("decision") != "allowed":
            continue
        if row.get("proposed_action") in POST_VALIDATION_ALLOWED_ACTIONS:
            total += 1
    return total


def post_validation_cap_reached(agent_run_dir: Path) -> bool:
    return validation_passed(agent_run_dir) and (
        post_validation_action_count(agent_run_dir) >= MAX_POST_VALIDATION_ACTIONS
    )


def claim_boundary_required(agent_run_dir: Path) -> bool:
    validation = safe_read_json(agent_run_dir / "validation_summary.json")
    if validation is not None and validation.get("claim_boundary_required") is True:
        return True
    gaps = safe_read_json(agent_run_dir / "gap_analysis.json")
    if gaps is not None:
        boundaries = gaps.get("claim_boundaries")
        if isinstance(boundaries, list) and boundaries:
            return True
        unsupported = gaps.get("unsupported_areas")
        if isinstance(unsupported, list):
            for row in unsupported:
                if not isinstance(row, dict):
                    continue
                area = str(row.get("area", "")).casefold()
                status = row.get("status")
                if status in UNSUPPORTED_BOUNDARY_STATUSES and any(
                    term in area for term in UNSUPPORTED_BOUNDARY_TERMS
                ):
                    return True
    questions = safe_read_json(agent_run_dir / "case_questions.json")
    if questions is None:
        return False
    return any(_question_requires_boundary(row) for row in _rows(questions, "questions"))


def _question_requires_boundary(question: Mapping[str, Any]) -> bool:
    status = question.get("status")
    if status not in UNSUPPORTED_BOUNDARY_STATUSES:
        return False
    text = " ".join(
        str(question.get(key, ""))
        for key in ("question", "question_id", "reason")
    ).casefold()
    gaps = question.get("gaps")
    if isinstance(gaps, list):
        text = f"{text} {' '.join(str(item) for item in gaps)}"
    return any(term in text for term in UNSUPPORTED_BOUNDARY_TERMS)


def _rows(payload: Mapping[str, Any], key: str) -> list[dict[str, Any]]:
    value = payload.get(key)
    if not isinstance(value, list):
        return []
    return [row for row in value if isinstance(row, dict)]


def _jsonl_rows(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for lineno, line in enumerate(handle, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                payload = json.loads(stripped)
            except json.JSONDecodeError as exc:
                raise ValueError(f"malformed JSONL at line {lineno} in {path}: {exc.msg}") from exc
            if not isinstance(payload, dict):
                raise ValueError(f"malformed JSONL at line {lineno} in {path}: not an object")
            rows.append(payload)
    return rows
