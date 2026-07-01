# Autonomy Scorecard

This maps each Find Evil "Autonomous Execution Quality" (Criterion 1) anchor to the
exact code that implements it and the exact bundle artifact that evidences it. The
committed, reproducible reference bundle is
[docs/examples/autonomy-runs/case-autonomy-demo/](examples/autonomy-runs/case-autonomy-demo/),
regenerable with `PYTHONPATH=src python scripts/generate_autonomy_example.py`.

## Loop shape

`observe -> decide -> validate -> execute -> verify -> reflect -> stop`, implemented in
`src/elenchos/autonomy/supervisor.py::AutonomySupervisor.run`. The loop *composes* the
deterministic engine; it does not replace it. `run_agent_workflow` remains the
execution primitive.

| Anchor | Implementation | Bundle evidence |
|---|---|---|
| Observes state before acting | `supervisor.run` calls `inspect_run_state` each iteration | `state_observations.jsonl` (one `RunStateSummary` snapshot per step) |
| Forms a hypothesis and chooses a bounded action based on evidence | `DecisionProvider.propose` returns an `AutonomyDecision` with `hypothesis`, `expected_signal`, `failure_or_gap_signal` (`src/elenchos/autonomy/decision.py`) | `autonomy_decisions.jsonl` |
| Chooses tools based on observed state, not a fixed script | `ReplayDecisionProvider` / `ClaudeCodeDecisionProvider` (`src/elenchos/autonomy/providers.py`) propose per-step; only `AUTONOMY_ACTIONS` execute (`actions.py`) | `autonomy_decisions.jsonl` + `state_observations.jsonl` |
| Reacts to a failed/contradictory result | `_verify_outputs` detects a real verifier failure and records a plan revision to `apply_self_correction` | `plan_revisions.jsonl` (`trigger: verification_failure`) |
| Changes plan after an unexpected result | Same plan-revision record supersedes `finalize` with `apply_self_correction` | `plan_revisions.jsonl` |
| Genuine self-correction without human intervention | `_apply_self_correction` runs the deterministic verifier-driven downgrade; `human_intervention: false` | `self_correction_events.json` |
| Self-correction is triggered by an actual evidence gap (not a prewritten casebook boundary) | Trigger is `VerificationFailureKind.MISSING_EVIDENCE_REFS` from `verify_agent_outputs`, not casebook metadata | `self_correction_events.json` (`mode: supervisor_verifier_self_correction`) + `audit.jsonl` |
| Guardrails hold during autonomy | Every proposal is gated by `evaluate_action_policy` before execution; unsafe/unbounded proposals are denied | `policy_decisions.jsonl` (`decision: rejected` rows) + `tool_executions.jsonl` (`status: denied`) |
| Findings trace to evidence, not to model narration | `trace_map.py` joins report claim -> finding -> evidence ref -> normalized event -> tool execution -> artifact hash | `trace_map.json` (`all_supported_claims_resolved: true`) |
| Model output is never evidence and never changes status | Enforced by policy (`model_rationale_cannot_change_status`) and by the fact that only the deterministic verifier mutates findings | `autonomy_decisions.jsonl` (`model_output_used_as_evidence: false`) |

## What the reference bundle shows

1. `analyze_case` produces a base run that includes a finding
   (`F-SYN-UNSUPPORTED-EXFIL`) lacking evidence support (the base run stops at the
   VERIFY phase and defers correction so the supervisor owns it).
2. `verify_outputs` fails -> a `plan_revisions.jsonl` entry
   (`trigger: verification_failure -> revised_action: apply_self_correction`).
3. `apply_self_correction` downgrades the unsupported finding to `needs_review`
   (`self_correction_events.json`).
4. `verify_outputs` now passes.
5. `build_trace_map` emits `trace_map.json` with
   `all_supported_claims_resolved: true` -- the one supported claim
   (`F-TL-...`, a drop -> execution -> persistence timeline for `updater.exe`) resolves
   to normalized events, a tool execution, and artifact hashes.

## Honesty notes

- The reference bundle uses **synthetic control data**; it is a mechanism demonstration,
  not a real-case result. A real-case bundle requires the SIFT toolchain, evidence, and
  (for the live path) an OpenClaw/model provider.
- The preferred live provider is **Claude Code** (`ClaudeCodeDecisionProvider`, shelling
  out to `claude --bare -p ... --output-format json`): Claude Code proposes bounded
  decisions; Elenchos policy/verifier executes, gates, and corrects. Its parsing/validation
  is unit-tested via an injected runner; the live CLI path runs only where `claude` is
  installed/authenticated and is not covered by CI. `replay` remains the deterministic,
  offline public/CI driver. A legacy openai-compatible provider is retained for back-compat.
- The deterministic verifier -- not the model -- performs every finding-status change.
  The supervisor's role is to observe, decide the next bounded step, and record.
