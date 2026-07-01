from __future__ import annotations

import json
from pathlib import Path

from elenchos.autonomy import AutonomySupervisor
from elenchos.autonomy.providers import ReplayDecisionProvider
from elenchos.integrations.rationale_trace import iter_jsonl

FIXTURE = Path("tests/fixtures/positive_control/autonomy_demo.json")
CASE_ID = "case_positive-control"


def _decision(action: str, phase: str = "analyze", **args) -> dict:
    return {
        "phase": phase,
        "hypothesis": f"bounded hypothesis for {action}",
        "proposed_action": action,
        "action_args": dict(args),
        "expected_signal": "expected deterministic signal",
        "failure_or_gap_signal": "failure or gap signal",
        "confidence": "high",
        "rationale": f"bounded step {action}",
    }


def _supervisor(tmp_path: Path, decisions: list[dict], **kwargs) -> AutonomySupervisor:
    return AutonomySupervisor(
        case_id=CASE_ID,
        output_dir=tmp_path / "runs" / "autonomy",
        provider=ReplayDecisionProvider.from_dicts(decisions),
        max_iterations=10,
        **kwargs,
    )


def test_full_autonomy_loop_self_corrects_and_traces(tmp_path: Path):
    decisions = [
        _decision("analyze_case"),
        _decision("verify_outputs", phase="verify"),
        _decision("apply_self_correction", phase="reflect"),
        _decision("verify_outputs", phase="verify"),
        _decision("build_trace_map", phase="finalize"),
        _decision("stop", phase="finalize"),
    ]
    result = _supervisor(tmp_path, decisions, fixture_path=FIXTURE).run()
    ard = Path(result.agent_run_dir)

    # Full bundle emitted.
    for name in (
        "autonomy_decisions.jsonl",
        "state_observations.jsonl",
        "plan_revisions.jsonl",
        "tool_executions.jsonl",
        "trace_map.json",
        "self_correction_events.json",
        "findings.json",
        "report.md",
    ):
        assert (ard / name).is_file(), f"missing bundle file {name}"

    # An adaptive plan revision driven by an actual verification failure.
    revisions = iter_jsonl(ard / "plan_revisions.jsonl")
    assert any(
        rev["trigger"] == "verification_failure"
        and rev["revised_action"] == "apply_self_correction"
        for rev in revisions
    )

    # A self-correction from a real failed-support gap (not a casebook boundary).
    events = json.loads((ard / "self_correction_events.json").read_text())
    assert events["mode"] == "supervisor_verifier_self_correction"
    assert events["event_count"] >= 1

    # Final verification passes and every supported claim resolves through the trace map.
    assert result.verification_status == "passed"
    trace = json.loads((ard / "trace_map.json").read_text())
    assert trace["supported_claim_count"] >= 1
    assert trace["all_supported_claims_resolved"] is True

    # The unsupported induced finding was downgraded, not asserted as a claim.
    findings = {
        f["finding_id"]: f
        for f in json.loads((ard / "findings.json").read_text())["findings"]
    }
    assert findings["F-SYN-UNSUPPORTED-EXFIL"]["status"] == "needs_review"


def test_policy_gate_rejects_unsafe_model_proposal(tmp_path: Path):
    decisions = [
        _decision("inspect_raw_evidence", phase="analyze"),
        _decision("stop", phase="finalize"),
    ]
    result = _supervisor(tmp_path, decisions, fixture_path=FIXTURE).run()
    ard = Path(result.agent_run_dir)

    # The proposal was recorded, then denied by the deterministic policy gate.
    revisions = iter_jsonl(ard / "plan_revisions.jsonl")
    assert any(
        rev["trigger"] == "policy_rejection"
        and rev["superseded_action"] == "inspect_raw_evidence"
        for rev in revisions
    )
    executions = iter_jsonl(ard / "tool_executions.jsonl")
    denied = [row for row in executions if row["action"] == "inspect_raw_evidence"]
    assert denied and denied[0]["status"] == "denied"

    # The unsafe action never executed: no analysis outputs were produced by it.
    policy_rows = iter_jsonl(ard / "policy_decisions.jsonl")
    assert any(
        row["proposed_action"] == "inspect_raw_evidence" and row["decision"] == "rejected"
        for row in policy_rows
    )


def test_unbounded_allowlisted_action_is_rejected_by_autonomy_layer(tmp_path: Path):
    # prepare_case is policy-allowlisted but outside the bounded autonomy vocabulary.
    decisions = [_decision("prepare_case"), _decision("stop", phase="finalize")]
    result = _supervisor(tmp_path, decisions, fixture_path=FIXTURE).run()
    ard = Path(result.agent_run_dir)
    executions = iter_jsonl(ard / "tool_executions.jsonl")
    denied = [row for row in executions if row["action"] == "prepare_case"]
    assert denied and denied[0]["status"] == "denied"
