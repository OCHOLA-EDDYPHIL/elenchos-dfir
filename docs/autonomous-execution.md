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

For live progress, use:

- `start_case_run` to start deterministic `agent run-case` with a fixed argv
  builder, `shell=False`, and generated stdout/stderr traces.
- `poll_case_run` to read `run_job.json`, `progress.jsonl`, and generated
  outputs only.
- `finish_case_run` to confirm terminal job state without killing processes.

Generated autonomy logs:

- `model_rationale.jsonl`: model-generated operational rationale, not forensic
  evidence.
- `policy_decisions.jsonl`: deterministic allow/reject policy decisions.
- `orchestration_trace.json`: adapter-level non-evidence orchestration trace.
- `run_job.json`: bounded async job metadata.
- `progress.jsonl`: runtime telemetry.

Local Codex-machine tests use synthetic generated outputs and fake or harmless
job runners. They do not require OpenClaw credentials, ROCBA evidence, SIFT
parser tools, or real forensic runs.

Pre-merge validation on the SIFT Workstation should run this branch with a live
OpenClaw agent, confirm visible `[model-rationale]` and `[policy]` lines, verify
start/poll/finish behavior, and ensure deterministic validation still controls
claim boundaries.
