"""The autonomy supervisor: observe -> decide -> validate -> execute -> verify ->
reflect -> stop, composed over the deterministic Elenchos engine.

Design invariants (all enforced by reused deterministic code, not by prompt text):

* The provider only *proposes* a bounded action. Every proposal passes through the
  deterministic policy gate (:func:`evaluate_action_policy`) before execution.
* The deterministic verifier/self-correction own all finding-status changes. The model
  never mutates a finding, never creates evidence, and never asserts a claim.
* Self-correction here is triggered by an *actual* failed-support gap detected by the
  verifier -- not by a prewritten casebook boundary -- and is recorded with the audit
  evidence that triggered it.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, cast

from elenchos.agent.models import AgentRun
from elenchos.agent.runner import (
    run_agent_fixture_workflow,
    run_agent_workflow,
)
from elenchos.agent.self_correction import apply_self_correction
from elenchos.agent.verifier import VerificationResult, VerificationStatus, verify_agent_outputs
from elenchos.audit.execution_ledger import utc_now
from elenchos.autonomy import actions
from elenchos.autonomy.bundle import (
    AUTONOMY_BUNDLE_FILENAMES,
    append_decision,
    append_observation,
    append_plan_revision,
    append_tool_execution,
    next_decision_id,
    next_execution_id,
    next_observation_id,
    next_revision_id,
    resolve_agent_run_dir,
)
from elenchos.autonomy.decision import AutonomyDecision, PlanRevision, StateObservation
from elenchos.autonomy.providers import DecisionProvider
from elenchos.autonomy.trace_map import write_trace_map
from elenchos.integrations.rationale_policy import evaluate_action_policy
from elenchos.integrations.rationale_schema import JSONValue
from elenchos.integrations.rationale_trace import safe_read_json
from elenchos.integrations.run_state import inspect_run_state

SELF_CORRECTION_EVENTS_FILENAME = "self_correction_events.json"


@dataclass(slots=True)
class AutonomyResult:
    case_id: str
    output_dir: str
    agent_run_dir: str
    iterations: int
    stopped_reason: str
    decision_count: int
    plan_revision_count: int
    self_correction_count: int
    verification_status: str | None
    trace_map: dict[str, Any] | None
    bundle_files: dict[str, bool] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "output_dir": self.output_dir,
            "agent_run_dir": self.agent_run_dir,
            "iterations": self.iterations,
            "stopped_reason": self.stopped_reason,
            "decision_count": self.decision_count,
            "plan_revision_count": self.plan_revision_count,
            "self_correction_count": self.self_correction_count,
            "verification_status": self.verification_status,
            "trace_map_all_supported_claims_resolved": (
                None
                if self.trace_map is None
                else self.trace_map.get("all_supported_claims_resolved")
            ),
            "bundle_files": dict(self.bundle_files),
        }


class AutonomySupervisor:
    def __init__(
        self,
        *,
        case_id: str,
        output_dir: Path,
        provider: DecisionProvider,
        fixture_path: Path | None = None,
        manifest_path: Path | None = None,
        max_iterations: int = 10,
        max_normalized_events: int | None = None,
        clock=utc_now,
    ) -> None:
        if fixture_path is None and manifest_path is None:
            # Post-hoc mode: operate over an already-produced run directory.
            pass
        if fixture_path is not None and manifest_path is not None:
            raise ValueError("provide either fixture_path or manifest_path, not both")
        self._case_id = case_id
        self._output_dir = Path(output_dir)
        self._provider = provider
        self._fixture_path = fixture_path
        self._manifest_path = manifest_path
        self._max_iterations = max(1, int(max_iterations))
        self._max_normalized_events = max_normalized_events
        self._clock = clock
        self._agent_run_dir = resolve_agent_run_dir(self._output_dir / "agent-run")
        self._agent_run: AgentRun | None = None
        self._verification: VerificationResult | None = None
        self._plan_revisions = 0
        self._self_correction_events = 0
        self._trace_map: dict[str, Any] | None = None

    # -- public entrypoint -------------------------------------------------
    def run(self) -> AutonomyResult:
        self._agent_run_dir.mkdir(parents=True, exist_ok=True)
        history: list[AutonomyDecision] = []
        stopped_reason = "max_iterations_reached"
        iteration = 0
        for iteration in range(1, self._max_iterations + 1):
            state = inspect_run_state(self._output_dir)
            observation = StateObservation(
                observation_id=next_observation_id(self._agent_run_dir),
                timestamp_utc=self._clock(),
                iteration=iteration,
                run_state=cast("dict[str, JSONValue]", state.to_dict()),
            )
            append_observation(self._agent_run_dir, observation)

            proposed = self._provider.propose(state=state, history=history, iteration=iteration)
            decision = replace(
                proposed,
                decision_id=next_decision_id(self._agent_run_dir),
                timestamp_utc=self._clock(),
                observed_state_refs=[observation.observation_id],
            )
            append_decision(self._agent_run_dir, decision)
            history.append(decision)

            allowed = self._gate(decision)
            if not allowed:
                continue

            outcome = self._execute(decision, iteration)
            self._record_execution(decision, outcome)
            if decision.proposed_action == actions.STOP:
                stopped_reason = "provider_requested_stop"
                break

        bundle = {
            name: (self._agent_run_dir / name).exists() for name in AUTONOMY_BUNDLE_FILENAMES
        }
        return AutonomyResult(
            case_id=self._case_id,
            output_dir=str(self._output_dir),
            agent_run_dir=str(self._agent_run_dir),
            iterations=iteration,
            stopped_reason=stopped_reason,
            decision_count=len(history),
            plan_revision_count=self._plan_revisions,
            self_correction_count=self._self_correction_events,
            verification_status=(
                None if self._verification is None else self._verification.status.value
            ),
            trace_map=self._trace_map,
            bundle_files=bundle,
        )

    # -- gate --------------------------------------------------------------
    def _gate(self, decision: AutonomyDecision) -> bool:
        policy_action = actions.effective_policy_action(decision.proposed_action)
        try:
            policy = evaluate_action_policy(
                output_dir=self._agent_run_dir,
                proposed_action=policy_action,
                action_args=decision.action_args,
                rationale_id=decision.decision_id,
                write_decision=True,
            )
            policy_ok = policy.get("decision") == "allowed"
            reason = str(policy.get("reason", "rejected"))
        except Exception as exc:  # noqa: BLE001 - a raising gate is a rejection
            policy_ok = False
            reason = f"policy evaluation error: {exc}"

        bounded = actions.is_bounded_action(decision.proposed_action)
        if policy_ok and bounded:
            return True

        signal = reason if not policy_ok else "action is outside the bounded autonomy vocabulary"
        self._record_plan_revision(
            trigger="policy_rejection",
            observed_signal=signal,
            superseded_action=decision.proposed_action,
            revised_action="await_next_bounded_decision",
            rationale=(
                "The proposed action was denied by the deterministic policy gate; the "
                "supervisor discards it and requests a different bounded action."
            ),
            evidence_refs=["policy_decisions.jsonl"],
            iteration=None,
        )
        self._record_execution(
            decision,
            {"status": "denied", "reason": signal},
        )
        return False

    # -- execute -----------------------------------------------------------
    def _execute(self, decision: AutonomyDecision, iteration: int) -> dict[str, Any]:
        action = decision.proposed_action
        try:
            if action == actions.ANALYZE_CASE:
                return self._analyze_case()
            if action == actions.INSPECT_RUN_STATE:
                return {"status": "observed"}
            if action == actions.VERIFY_OUTPUTS:
                return self._verify_outputs(iteration)
            if action == actions.APPLY_SELF_CORRECTION:
                return self._apply_self_correction(iteration)
            if action == actions.BUILD_TRACE_MAP:
                return self._build_trace_map()
            if action == actions.STOP:
                return {"status": "stopped"}
            # Remaining bounded actions are read-only generated-output tools.
            return self._dispatch_generated_tool(action)
        except Exception as exc:  # noqa: BLE001 - record and keep the loop alive
            return {"status": "failed", "error": str(exc)}

    def _analyze_case(self) -> dict[str, Any]:
        if self._fixture_path is not None:
            self._agent_run = run_agent_fixture_workflow(
                case_id=self._case_id,
                fixture_path=self._fixture_path,
                output_dir=self._agent_run_dir,
                max_iterations=6,
                max_normalized_events=self._max_normalized_events,
                clock=self._clock,
            )
        elif self._manifest_path is not None:
            self._agent_run = run_agent_workflow(
                case_id=self._case_id,
                manifest_path=self._manifest_path,
                output_dir=self._agent_run_dir,
                max_iterations=6,
                max_normalized_events=self._max_normalized_events,
                clock=self._clock,
            )
        else:
            raise ValueError("analyze_case requires a configured fixture or manifest")
        # The base run stops at the VERIFY phase and defers correction, so the supervisor
        # owns verification and self-correction as its own audited bounded steps rather
        # than delegating them to the engine's internal single retry.
        return {
            "status": "completed",
            "run_status": self._agent_run.status.value,
            "output_refs": dict(self._agent_run.output_refs),
        }

    def _verify_outputs(self, iteration: int) -> dict[str, Any]:
        agent_run = self._require_agent_run()
        result = verify_agent_outputs(
            case_id=self._case_id,
            output_dir=self._agent_run_dir,
            agent_run=agent_run,
            audit_log_path=self._agent_run_dir / "audit.jsonl",
            clock=self._clock,
        )
        self._verification = result
        if result.status is VerificationStatus.FAILED:
            kinds = sorted({failure.kind.value for failure in result.failures})
            finding_ids = sorted(
                {failure.finding_id for failure in result.failures if failure.finding_id}
            )
            self._record_plan_revision(
                trigger="verification_failure",
                observed_signal=(
                    f"verifier reported {len(result.failures)} failure(s): {', '.join(kinds)}"
                ),
                superseded_action="finalize",
                revised_action=actions.APPLY_SELF_CORRECTION,
                rationale=(
                    "A finding lacked deterministic support; the supervisor changes plan "
                    "to run verifier-driven self-correction before any final claim."
                ),
                evidence_refs=["audit.jsonl", "findings.json"] + finding_ids,
                iteration=iteration,
            )
        return result.to_dict()

    def _apply_self_correction(self, iteration: int) -> dict[str, Any]:
        agent_run = self._require_agent_run()
        if self._verification is None or self._verification.status is not VerificationStatus.FAILED:
            return {"status": "skipped", "reason": "no failed verification to correct"}
        result = apply_self_correction(
            case_id=self._case_id,
            output_dir=self._agent_run_dir,
            agent_run=agent_run,
            verification_result=self._verification,
            audit_log_path=self._agent_run_dir / "audit.jsonl",
            clock=self._clock,
        )
        events = [
            {
                "event_id": f"self-correction-{index + 1:03d}",
                "phase": "verify",
                "correction_id": correction.correction_id,
                "problem_detected": correction.diagnosis,
                "correction": correction.action.value,
                "trigger": correction.trigger.value,
                "result": correction.result,
                "human_intervention": False,
                "model_output_used_as_evidence": False,
                "source": "supervisor_verifier_self_correction",
            }
            for index, correction in enumerate(result.corrections)
        ]
        self._write_self_correction_events(events)
        return result.to_dict()

    def _build_trace_map(self) -> dict[str, Any]:
        self._trace_map = write_trace_map(self._agent_run_dir, clock=self._clock)
        return {
            "status": "completed",
            "all_supported_claims_resolved": self._trace_map.get("all_supported_claims_resolved"),
            "supported_claim_count": self._trace_map.get("supported_claim_count"),
        }

    def _dispatch_generated_tool(self, action: str) -> dict[str, Any]:
        from elenchos.integrations.tool_adapter import dispatch_tool

        result = dispatch_tool(action, {"output_dir": str(self._agent_run_dir)})
        return {"status": "completed", "result": result}

    # -- helpers -----------------------------------------------------------
    def _require_agent_run(self) -> AgentRun:
        if self._agent_run is not None:
            return self._agent_run
        payload = safe_read_json(self._agent_run_dir / "agent_run.json")
        if payload is None:
            raise ValueError("no agent_run.json is available to verify")
        self._agent_run = AgentRun.from_dict(payload)
        return self._agent_run

    def _write_self_correction_events(self, events: list[dict[str, Any]]) -> None:
        if not events:
            return
        path = self._agent_run_dir / SELF_CORRECTION_EVENTS_FILENAME
        existing = safe_read_json(path) or {}
        prior_events = existing.get("events")
        prior = prior_events if isinstance(prior_events, list) else []
        combined = list(prior) + events
        payload = {
            "case_id": self._case_id,
            "mode": "supervisor_verifier_self_correction",
            "generated_at_utc": self._clock(),
            "event_count": len(combined),
            "events": combined,
        }
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        self._self_correction_events = len(combined)

    def _record_plan_revision(
        self,
        *,
        trigger: str,
        observed_signal: str,
        superseded_action: str | None,
        revised_action: str,
        rationale: str,
        evidence_refs: list[str],
        iteration: int | None,
    ) -> None:
        revision = PlanRevision(
            revision_id=next_revision_id(self._agent_run_dir),
            timestamp_utc=self._clock(),
            iteration=iteration if iteration is not None else 0,
            trigger=trigger,
            observed_signal=observed_signal,
            superseded_action=superseded_action,
            revised_action=revised_action,
            rationale=rationale,
            evidence_refs=[ref for ref in evidence_refs if ref],
        )
        append_plan_revision(self._agent_run_dir, revision)
        self._plan_revisions += 1

    def _record_execution(self, decision: AutonomyDecision, outcome: dict[str, Any]) -> None:
        record = {
            "execution_id": next_execution_id(self._agent_run_dir),
            "timestamp_utc": self._clock(),
            "decision_id": decision.decision_id,
            "action": decision.proposed_action,
            "status": outcome.get("status", "completed"),
            "outcome": outcome,
        }
        append_tool_execution(self._agent_run_dir, record)


def run_autonomy(
    *,
    case_id: str,
    output_dir: Path,
    provider: DecisionProvider,
    fixture_path: Path | None = None,
    manifest_path: Path | None = None,
    max_iterations: int = 10,
    max_normalized_events: int | None = None,
    clock=utc_now,
) -> AutonomyResult:
    supervisor = AutonomySupervisor(
        case_id=case_id,
        output_dir=output_dir,
        provider=provider,
        fixture_path=fixture_path,
        manifest_path=manifest_path,
        max_iterations=max_iterations,
        max_normalized_events=max_normalized_events,
        clock=clock,
    )
    return supervisor.run()
