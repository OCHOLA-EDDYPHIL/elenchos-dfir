from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Literal, cast

from elenchos.audit.execution_ledger import utc_now
from elenchos.integrations.finalization import (
    POST_VALIDATION_ALLOWED_ACTIONS,
    force_finalize_orchestration,
    maybe_finalize_orchestration,
    post_validation_cap_reached,
    terminal_state,
    validation_passed,
)
from elenchos.integrations.prepared_manifest import (
    resolve_prepared_manifest_path,
    validate_prepared_manifest_for_run,
)
from elenchos.integrations.rationale_schema import (
    ActionPolicyResult,
    PolicyDecisionRecord,
)
from elenchos.integrations.rationale_trace import (
    agent_run_dir_from_output_dir,
    append_jsonl,
    append_orchestration_event,
    next_sequence_id,
    policy_decisions_path,
    run_job_path,
    safe_read_json,
)
from elenchos.integrations.safe_paths import display_path, resolve_user_path
from elenchos.policy.paths import MOUNTED_EVIDENCE_ROOT, is_generated_output_path, is_relative_to

ALLOWED_ACTIONS = {
    "prepare_case",
    "inspect_run_state",
    "record_model_rationale",
    "evaluate_action_policy",
    "run_case",
    "start_case_run",
    "poll_case_run",
    "finish_case_run",
    "summarize_run",
    "validate_run_outputs",
    "emit_claim_boundary",
    "emit_next_artifact_recommendations",
    "finalize_report_summary",
    "stop",
}

REJECTED_ACTIONS = {
    "inspect_raw_evidence",
    "read_raw_evidence",
    "write_evidence",
    "modify_evidence",
    "delete_evidence",
    "mount_rw",
    "arbitrary_shell",
    "arbitrary_command",
    "execute_command",
    "claim_confirmed_compromise",
    "claim_confirmed_theft",
    "claim_confirmed_exfiltration",
    "claim_confirmed_malware",
    "claim_memory_finding",
    "claim_attribution",
    "upgrade_finding_status",
}

BLOCKED_ARG_KEYS = {
    "argv",
    "bash",
    "cmd",
    "command",
    "evidence_write_path",
    "executable",
    "powershell",
    "raw_command",
    "raw_evidence_path",
    "script",
    "shell",
    "subprocess",
}

GENERATED_READ_ONLY_ACTIONS = {
    "inspect_run_state",
    "poll_case_run",
    "summarize_run",
    "validate_run_outputs",
    "emit_claim_boundary",
    "emit_next_artifact_recommendations",
    "finalize_report_summary",
}


def normalize_action(value: object) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("proposed_action must be a non-empty string")
    return value.strip()


def _flatten_blocked_fields(payload: object, prefix: str = "") -> list[str]:
    fields: list[str] = []
    if isinstance(payload, Mapping):
        for key, value in payload.items():
            key_text = str(key)
            dotted = f"{prefix}.{key_text}" if prefix else key_text
            if key_text.casefold() in BLOCKED_ARG_KEYS:
                fields.append(dotted)
            fields.extend(_flatten_blocked_fields(value, dotted))
    elif isinstance(payload, list):
        for index, item in enumerate(payload):
            fields.extend(_flatten_blocked_fields(item, f"{prefix}[{index}]"))
    return fields


def _path_arg_violations(action: str, action_args: Mapping[str, object]) -> list[str]:
    violations: list[str] = []
    for key, value in action_args.items():
        if not isinstance(value, str) or not value:
            continue
        key_lower = key.casefold()
        if action == "prepare_case" and key_lower in {"source_root", "source_manifest"}:
            continue
        if "source" not in key_lower and "evidence" not in key_lower:
            continue
        try:
            resolved = Path(value).expanduser().resolve(strict=False)
        except (OSError, ValueError):
            continue
        if is_relative_to(resolved, MOUNTED_EVIDENCE_ROOT):
            violations.append(key)
    return violations


def _output_dir_from_args(action_args: Mapping[str, object]) -> Path | None:
    value = action_args.get("output_dir")
    if not isinstance(value, str) or not value:
        return None
    return resolve_user_path(value, "output_dir")


def _prepared_manifest_is_valid(
    *,
    action: str,
    output_dir: Path,
    action_args: Mapping[str, object],
) -> bool:
    if action not in {"start_case_run", "run_case"}:
        return True
    explicit = action_args.get("prepared_manifest_path") or action_args.get("artifact_manifest")
    if explicit is None:
        return True
    if not isinstance(explicit, str) or not explicit:
        return False
    try:
        path = resolve_prepared_manifest_path(output_dir=output_dir, explicit_path=explicit)
        validate_prepared_manifest_for_run(path)
    except ValueError:
        return False
    return True


def _active_job(job_path: Path) -> dict[str, object] | None:
    payload = safe_read_json(job_path)
    if payload is None:
        return None
    status = payload.get("status")
    if status in {"starting", "running"}:
        return payload
    return None


def evaluate_action_policy(
    *,
    output_dir: Path,
    proposed_action: str,
    action_args: Mapping[str, object] | None = None,
    rationale_id: str | None = None,
    write_decision: bool = True,
) -> dict[str, object]:
    action_args = dict(action_args or {})
    action = normalize_action(proposed_action)
    agent_run_dir = agent_run_dir_from_output_dir(output_dir)
    policy_path = policy_decisions_path(agent_run_dir)
    blocked_fields = sorted(set(_flatten_blocked_fields(action_args)))
    evidence_path_fields = sorted(set(_path_arg_violations(action, action_args)))
    rejected_fields = sorted(set(blocked_fields + evidence_path_fields))
    explicit_output_dir = _output_dir_from_args(action_args)
    candidate_output_dir = explicit_output_dir or output_dir
    candidate_output_dir_resolved = candidate_output_dir.resolve()
    active_job = _active_job(run_job_path(agent_run_dir))
    prepared_manifest_valid = _prepared_manifest_is_valid(
        action=action,
        output_dir=candidate_output_dir_resolved,
        action_args=action_args,
    )
    validation_is_passed = validation_passed(agent_run_dir)
    terminal = terminal_state(agent_run_dir)
    terminal_condition_met = bool(terminal["terminal_condition_met"])
    if terminal_condition_met:
        maybe_finalize_orchestration(agent_run_dir)
    cap_reached = post_validation_cap_reached(agent_run_dir)
    if cap_reached:
        force_finalize_orchestration(
            agent_run_dir,
            reason=(
                "validation already passed and max_post_validation_actions was reached; "
                "workflow is complete"
            ),
        )
    post_validation_action_allowed = (
        not validation_is_passed
        or action in POST_VALIDATION_ALLOWED_ACTIONS
    )
    terminal_action_allowed = not (terminal_condition_met or cap_reached) or action == "stop"

    safety_checks = {
        "action_allowlisted": action in ALLOWED_ACTIONS,
        "action_not_explicitly_rejected": action not in REJECTED_ACTIONS,
        "no_arbitrary_execution_fields": not blocked_fields,
        "output_dir_is_generated": is_generated_output_path(candidate_output_dir_resolved),
        "output_dir_not_evidence": not is_relative_to(
            candidate_output_dir_resolved,
            MOUNTED_EVIDENCE_ROOT,
        ),
        "no_model_supplied_evidence_paths": not evidence_path_fields,
        "model_rationale_not_evidence": True,
        "model_rationale_cannot_change_status": action != "upgrade_finding_status",
        "duplicate_active_job_rejected": not (
            action == "start_case_run" and active_job is not None
        ),
        "prepared_manifest_valid": prepared_manifest_valid,
        "generated_read_only_action": action not in GENERATED_READ_ONLY_ACTIONS
        or is_generated_output_path(candidate_output_dir_resolved),
        "post_validation_action_allowed": post_validation_action_allowed,
        "terminal_action_allowed": terminal_action_allowed,
    }
    allowed = all(safety_checks.values())

    if action in REJECTED_ACTIONS:
        reason = _rejected_action_reason(action)
    elif action not in ALLOWED_ACTIONS:
        reason = "action is not in the bounded Elenchos allowlist"
    elif blocked_fields:
        reason = "model-supplied action args include arbitrary execution fields"
    elif evidence_path_fields:
        reason = "model-supplied action args reference raw evidence paths"
    elif not safety_checks["output_dir_is_generated"]:
        reason = "output_dir is not under a generated output directory"
    elif not safety_checks["output_dir_not_evidence"]:
        reason = "output_dir is under the mounted evidence root"
    elif action == "start_case_run" and active_job is not None:
        reason = "an active run job is already recorded"
    elif not prepared_manifest_valid:
        reason = "prepared_manifest_path is not a valid prepared case manifest"
    elif validation_is_passed and action == "start_case_run":
        reason = "run already completed and validation passed"
    elif cap_reached and action != "stop":
        reason = (
            "validation already passed and max_post_validation_actions was reached; "
            "workflow is complete"
        )
    elif terminal_condition_met and action != "stop":
        reason = "run already completed and validation passed"
    elif validation_is_passed and not post_validation_action_allowed:
        reason = (
            "validation already passed; only summarize_run, emit_claim_boundary, "
            "and stop are allowed"
        )
    elif action in GENERATED_READ_ONLY_ACTIONS:
        reason = "action is allowlisted and reads generated outputs only"
    elif action == "stop":
        reason = "workflow is complete and may stop"
    elif action == "start_case_run":
        reason = "bounded action, generated output directory, read-only evidence"
    elif action == "record_model_rationale":
        reason = "model rationale is recorded as operational explanation only"
    else:
        reason = "action is allowlisted by the bounded Elenchos policy"

    decision = cast(Literal["allowed", "rejected"], "allowed" if allowed else "rejected")
    normalized = action if allowed else None
    visible = f"[policy] proposed {action} -> {decision}: {reason}."
    result = ActionPolicyResult(
        decision=decision,
        reason=reason,
        safety_checks=safety_checks,
        rejected_fields=rejected_fields,
        normalized_action=normalized,
        next_allowed_tools=(
            ["stop"]
            if terminal_condition_met or cap_reached
            else sorted(POST_VALIDATION_ALLOWED_ACTIONS)
            if validation_is_passed
            else sorted(ALLOWED_ACTIONS)
        ),
        visible_policy_message=visible,
    )

    decision_record = PolicyDecisionRecord(
        policy_decision_id=next_sequence_id("policy", policy_path),
        timestamp_utc=utc_now(),
        rationale_id=rationale_id,
        proposed_action=action,
        decision=decision,
        reason=reason,
        safety_checks=safety_checks,
        rejected_fields=rejected_fields,
        normalized_action=normalized,
    )
    decision_payload = decision_record.to_dict()
    decision_payload["visible_policy_message"] = visible
    if write_decision:
        append_jsonl(policy_path, decision_payload)
        append_orchestration_event(
            agent_run_dir,
            event_type="policy_decision",
            payload={
                "policy_decision_id": decision_record.policy_decision_id,
                "proposed_action": action,
                "decision": decision,
                "reason": reason,
            },
        )

    payload = result.to_dict()
    payload.update(
        {
            "status": "completed",
            "policy_decision": decision_payload,
            "policy_decisions_path": display_path(policy_path),
            "output_dir": display_path(agent_run_dir),
        }
    )
    return payload


def _rejected_action_reason(action: str) -> str:
    if action in {"inspect_raw_evidence", "read_raw_evidence"}:
        return "raw evidence inspection by the model is outside the bounded interface"
    if action in {"write_evidence", "modify_evidence", "delete_evidence", "mount_rw"}:
        return "the proposed action would weaken read-only evidence boundaries"
    if action in {"arbitrary_shell", "arbitrary_command", "execute_command"}:
        return "arbitrary shell or command execution is not exposed"
    if action.startswith("claim_confirmed_") or action in {
        "claim_memory_finding",
        "claim_attribution",
    }:
        return "model-generated rationale cannot create confirmed forensic claims"
    if action == "upgrade_finding_status":
        return "model rationale cannot upgrade finding or question statuses"
    return "action is explicitly rejected by policy"
