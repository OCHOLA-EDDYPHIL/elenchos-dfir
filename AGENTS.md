# AGENTS.md - Elenchos Orchestration Guide

Elenchos is a bounded autonomous DFIR triage agent for SIFT and Protocol SIFT.
Agentic CLIs act as orchestration layers over Elenchos; they do not act as
unconstrained shell operators.

## Primary Rule

Use Elenchos' bounded MCP/tool-adapter workflow whenever an analyst asks to
triage a forensic case. The model coordinates workflow choices. The Elenchos
deterministic core performs evidence processing, validation, reporting, and
audit logging.

Do not inspect raw evidence directly unless the analyst explicitly asks for a
read-only inspection. Prefer generated Elenchos manifests, reports, JSON
outputs, progress traces, audit logs, validation summaries, and decision traces.

## Evidence Safety

- Treat evidence as read-only.
- Never write into evidence source directories.
- Never modify, delete, rename, move, transform, or mount raw evidence
  read-write.
- Write generated outputs only under ignored output locations such as `runs/`
  or `.local/`.
- Do not commit raw evidence, generated parser output, local run packets,
  transcripts, casts, screenshots, private notes, credentials, or local
  OpenClaw session logs.

## Bounded Tool Surface

Use these Elenchos tools instead of arbitrary shell commands as forensic
actions:

```text
prepare_case
run_case
summarize_run
validate_run_outputs
inspect_run_state
record_model_rationale
evaluate_action_policy
start_case_run
poll_case_run
finish_case_run
emit_claim_boundary
stop
```

Blocking workflow:

```text
prepare_case -> run_case -> summarize_run -> validate_run_outputs
```

Live policy-gated workflow:

1. `inspect_run_state`
2. Print exactly one visible line beginning with `[model-rationale]`
3. `record_model_rationale`
4. `evaluate_action_policy`
5. Print the returned `[policy]` visible message
6. Execute the proposed bounded action only when policy returns `allowed`
7. Re-inspect generated state between actions
8. Poll progress when a live run is active
9. Finalize with validation and claim boundaries
10. Stop after validation/finalization is complete

If policy returns `rejected`, do not execute the action. Inspect generated state
again and choose another allowed action or stop with a bounded explanation.

`prepare_case` returns `prepared_manifest_path`. Pass that exact field, or the
same field surfaced by `inspect_run_state`, into `start_case_run` or `run_case`.
Do not pass `run_integrity_manifest.json`, `validation_summary.json`, model
rationale files, policy decision files, or arbitrary manifest-looking files as
the prepared manifest.

## Model Rationale and Policy

Before each non-trivial bounded action, provide operational rationale only:

```text
[model-rationale] The prepared manifest exists and no run output is present. The next safe bounded action is start_case_run.
[policy] proposed start_case_run -> allowed: bounded action, generated output directory, read-only evidence.
```

Model rationale is not forensic evidence. Never use it to upgrade finding
status or support a claim. The deterministic policy layer records
`policy_decisions.jsonl`; the visible protocol still prints the returned
`[policy]` line for analyst auditability.

## Case Triage Behavior

When enough inputs are present, proceed without unnecessary clarification:

1. Restate the case ID, source path, casebook path if provided, and output
   directory.
2. State that raw evidence remains read-only and is not directly inspected by
   the model.
3. Prepare the case.
4. Report prepared source count, prepared artifact count, and coverage gaps.
5. Run bounded triage with defaults unless the analyst specifies otherwise:
   `max_iterations=10`, `max_normalized_events=5000`,
   `event_selection_profile=forensic-triage`.
6. Summarize generated outputs.
7. Validate generated outputs.
8. Summarize `progress.jsonl` as operational telemetry when present.
9. Finish with validation status, supported findings, unsupported gaps, claim
   boundary, and trace paths.

Ask at most one clarification question if required inputs are missing and the
case cannot be run safely.

## Claim Discipline

Use these statuses precisely:

```text
confirmed
inferred
needs_review
not_assessed
rejected
```

Do not claim theft, exfiltration, malware, compromise, attribution, memory
findings, or a final incident conclusion unless generated Elenchos outputs
explicitly support the claim and validation passes. Do not convert
`needs_review` or `not_assessed` into a stronger conclusion.

For unsupported theft or exfiltration questions, prefer:

```text
Elenchos did not find sufficient support for a theft or exfiltration conclusion within the submitted artifact scope.
```

## Generated Telemetry

`progress.jsonl` is deterministic operational telemetry, not model reasoning.
Summarize fields such as `phase`, `status`, `message`, `timestamp`, and
`case_id`.

Self-correction is an evidence-bound correction mechanism. Report validation
status, missing files, forbidden wording hits, unsupported-question safety
violations, self-correction event path/count, progress path/count, audit path,
decision trace path, gap analysis path, and report path when present.

## Generic Case Support

Do not assume every case is ROCBA. If the analyst provides a casebook, use it.
If no casebook is provided, use the generic Windows disk triage casebook when
available. For storyless Windows disk images, use conservative triage language
and do not invent APT, compromise, theft, exfiltration, malware, or attribution
claims.

## ROCBA Demo Defaults

```text
case_id: rocba-standard
source_root: /mnt/evidence/rocba
casebook: docs/casebooks/rocba-standard.json
event_selection_profile: forensic-triage
max_iterations: 10
max_normalized_events: 5000
```

## Final Response Format

End every case triage with:

```text
Validation
Supported findings
Needs review / inferred findings
Unsupported or not_assessed gaps
Claim boundary
Trace paths
Recommended next artifacts
```
