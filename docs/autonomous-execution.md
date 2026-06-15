# Autonomous Execution

Older OpenClaw guidance described a blocking sequence:

```text
prepare_case -> run_case -> summarize_run -> validate_run_outputs
```

That sequence remains available when blocking execution is acceptable. The live
autonomy protocol adds a visible, auditable loop:

```text
inspect_run_state
show [model-rationale]
record_model_rationale
evaluate_action_policy
show [policy]
execute allowed bounded action
poll progress
validate outputs
finalize claim boundary
```

The model observes generated Elenchos state, explains the operational reason
for its next proposed action, and submits that action to deterministic policy.
The policy gate decides whether the action is allowed. Elenchos deterministic
code remains the source of findings, statuses, reports, validation, and
evidence-backed traceability.

Agent hosts should still call `evaluate_action_policy` explicitly and print the
returned `[policy]` line. The tool adapter also self-gates bounded tool calls
through the same policy layer, records `policy_decisions.jsonl`, and rejects
unsafe calls before execution if an agent skips the explicit policy step.

For live progress, use:

- `start_case_run` to start deterministic `agent run-case` with a fixed argv
  builder, `shell=False`, and generated stdout/stderr traces.
- `poll_case_run` to read `run_job.json`, `progress.jsonl`, and generated
  outputs only.
- `finish_case_run` to confirm terminal job state without killing processes.
- `stop` to mark generated orchestration complete after validation and any
  required claim-boundary emission.

The live handoff from preparation to execution uses one manifest contract.
`prepare_case` creates the prepared case manifest and returns
`prepared_manifest_path`. `inspect_run_state` also reports
`prepared_manifest_path` when the generated state contains a valid
`case_prep.json`. Pass that exact value into `start_case_run`, or into
`run_case` when using blocking execution. `run_integrity_manifest.json` is
written after a deterministic run to describe generated-output integrity; it is
not a case-prep manifest and must never be used as `prepared_manifest_path`.

Generated autonomy logs:

- `model_rationale.jsonl`: model-generated operational rationale, not forensic
  evidence.
- `policy_decisions.jsonl`: deterministic allow/reject policy decisions.
- `orchestration_trace.json`: adapter-level non-evidence orchestration trace.
- `run_job.json`: bounded async job metadata.
- `progress.jsonl`: runtime telemetry.

Local adapter tests use synthetic generated outputs and fake or harmless
job runners. They do not require OpenClaw credentials, ROCBA evidence, SIFT
parser tools, or real forensic runs.

SIFT Workstation validation uses a live OpenClaw agent to confirm visible
`[model-rationale]` and `[policy]` lines, verify start/poll/finish behavior,
and ensure deterministic validation controls claim boundaries.
