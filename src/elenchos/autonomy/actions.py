"""Bounded action vocabulary for the autonomy loop.

The supervisor only executes actions in :data:`AUTONOMY_ACTIONS`. Each maps to a
canonical action in the deterministic policy engine's ``ALLOWED_ACTIONS`` so every
step is gated by the same code path the MCP surface uses. A provider that proposes
anything outside this vocabulary is routed through the policy gate under its raw
name -- so unsafe proposals (e.g. ``inspect_raw_evidence``) are genuinely rejected,
not silently ignored.
"""

from __future__ import annotations

# Analysis substrate: run the deterministic engine to produce the base bundle.
ANALYZE_CASE = "analyze_case"
# Read-only / generated-output steps the supervisor composes.
INSPECT_RUN_STATE = "inspect_run_state"
VERIFY_OUTPUTS = "verify_outputs"
APPLY_SELF_CORRECTION = "apply_self_correction"
BUILD_TRACE_MAP = "build_trace_map"
SUMMARIZE_RUN = "summarize_run"
VALIDATE_RUN_OUTPUTS = "validate_run_outputs"
EMIT_CLAIM_BOUNDARY = "emit_claim_boundary"
EMIT_NEXT_ARTIFACT_RECOMMENDATIONS = "emit_next_artifact_recommendations"
STOP = "stop"

AUTONOMY_ACTIONS = frozenset(
    {
        ANALYZE_CASE,
        INSPECT_RUN_STATE,
        VERIFY_OUTPUTS,
        APPLY_SELF_CORRECTION,
        BUILD_TRACE_MAP,
        SUMMARIZE_RUN,
        VALIDATE_RUN_OUTPUTS,
        EMIT_CLAIM_BOUNDARY,
        EMIT_NEXT_ARTIFACT_RECOMMENDATIONS,
        STOP,
    }
)

TERMINAL_ACTION = STOP

# Map each bounded autonomy action to the deterministic policy action used to gate
# it. Internal read/rewrite-of-generated-output steps borrow the closest allow-listed
# generated-output action so they pass through the same gate.
_ACTION_POLICY_MAP = {
    ANALYZE_CASE: "run_case",
    INSPECT_RUN_STATE: "inspect_run_state",
    VERIFY_OUTPUTS: "validate_run_outputs",
    APPLY_SELF_CORRECTION: "validate_run_outputs",
    BUILD_TRACE_MAP: "summarize_run",
    SUMMARIZE_RUN: "summarize_run",
    VALIDATE_RUN_OUTPUTS: "validate_run_outputs",
    EMIT_CLAIM_BOUNDARY: "emit_claim_boundary",
    EMIT_NEXT_ARTIFACT_RECOMMENDATIONS: "emit_next_artifact_recommendations",
    STOP: "stop",
}


def effective_policy_action(action: str) -> str:
    """Return the policy-engine action name used to gate ``action``.

    Unknown actions are returned unchanged so the policy gate evaluates (and, for
    rejected/unknown actions, denies) them under their real name.
    """

    return _ACTION_POLICY_MAP.get(action, action)


def is_bounded_action(action: str) -> bool:
    return action in AUTONOMY_ACTIONS
