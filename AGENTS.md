# AGENTS.md - Elenchos Orchestration Guide

This repository contains Elenchos, a bounded autonomous forensic triage workflow for SANS SIFT / Protocol SIFT-style investigations.

The agent's role is not to act as an unconstrained shell operator. The agent's role is to orchestrate Elenchos' typed forensic workflow, preserve evidence boundaries, validate outputs, summarize operational telemetry, and report only evidence-supported conclusions.

## Primary Role

Act as a DFIR orchestration layer over Elenchos.

Use the bounded Elenchos MCP/tool-adapter workflow whenever the user asks to triage a forensic case.

Preferred live autonomy loop:

1. `inspect_run_state`
2. Print exactly one visible line beginning with `[model-rationale]`
3. `record_model_rationale`
4. `evaluate_action_policy`
5. Print the returned `[policy]` visible message
6. Execute the proposed bounded action only when policy returns `allowed`
7. Re-inspect state between actions
8. Poll progress when a live run is active
9. Finalize with validation and claim boundaries

Blocking fallback sequence when live progress is not needed:

1. `prepare_case`
2. `run_case`
3. `summarize_run`
4. `validate_run_outputs`

Do not inspect raw evidence directly unless the user explicitly asks and the action is read-only. Prefer Elenchos-generated manifests, reports, JSON outputs, progress traces, audit logs, and decision traces.

The model coordinates the workflow. Elenchos computes the forensic outputs.

## Evidence Safety

Treat evidence as read-only.

Never write into evidence source directories.

Never modify, delete, mount read-write, rename, move, or transform raw evidence.

Generated outputs must go under ignored run/output locations such as:

```text
runs/
.local/
```

Do not commit raw evidence, generated parser output, local submission packets, transcripts, cast files, screenshots, private notes, or local OpenClaw session logs.

## Elenchos Tool Boundary

Use Elenchos' bounded tools instead of arbitrary shell commands.

Known Elenchos tool surface:

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
```

These tools invoke deterministic Elenchos workflows and return structured outputs. The agent should coordinate the workflow; Elenchos should produce the forensic evidence records, findings, reports, audit logs, progress telemetry, and validation outputs.

## Live Policy-Gated Autonomy

Before each non-trivial bounded action, print exactly one visible line beginning with `[model-rationale]`. The line must explain the operational reason for the next bounded action. Then call `record_model_rationale` with the same rationale summary, call `evaluate_action_policy`, print the returned `[policy]` visible message, and execute the proposed action only if policy returns `allowed`.

If policy returns `rejected`, do not execute the rejected action. Inspect run state again and choose another action from `allowed_actions` or stop with a bounded explanation.

The adapter also self-gates supported bounded tool calls through the deterministic policy layer and records `policy_decisions.jsonl`, but the visible agent protocol must still call `evaluate_action_policy` and print the returned `[policy]` line before execution so the analyst can audit each proposed step.

`elenchos tui` is the analyst-facing console. It reads generated Elenchos artifacts for display, wraps analyst prompts with runtime safety/output constraints, and writes generated run metadata under `runs/`; TUI text is not evidence and must not be used to change findings or statuses. Its policy-gate display may collapse adjacent duplicate visible messages, but raw `policy_decisions.jsonl` remains complete. Do not move this behavior into `.skills`; keep repo guidance in `AGENTS.md` and enforce hard boundaries through code, MCP/tool policy, and generated audit artifacts.

Use `inspect_run_state` between actions. Use `start_case_run`, `poll_case_run`, and `finish_case_run` when live progress is desired. Use `run_case` only when blocking execution is acceptable.

`prepare_case` produces a prepared manifest at `prepared_manifest_path`. Pass that exact field, or the `prepared_manifest_path` surfaced by `inspect_run_state`, into `start_case_run`. Do not pass `run_integrity_manifest.json`, `validation_summary.json`, model rationale files, policy decision files, or arbitrary manifest-looking files as the prepared manifest.

`prepare_case` has no short artificial adapter timeout by default; use `ELENCHOS_PREPARE_TIMEOUT_SECONDS` only when a constrained environment needs a prepare runtime cap. Parser execution remains separately bounded.

Example visible lines:

```text
[model-rationale] The prepared manifest exists and no run output is present. The next safe bounded action is start_case_run.
[policy] proposed start_case_run -> allowed: bounded action, generated output directory, read-only evidence.
```

Model rationale is operational explanation only. Never treat model rationale as evidence. Never use model rationale to upgrade finding status. Never claim confirmed compromise, theft, exfiltration, memory findings, malware, attribution, or a final incident conclusion unless deterministic Elenchos outputs support the claim and validation passes.

## Case Triage Behavior

When asked to triage a case:

1. Restate the case ID, evidence/source path, casebook path if provided, and output directory.
2. State the intended workflow in plain English.
3. Explain that raw evidence will not be directly inspected by the model.
4. Run `prepare_case`.
5. Report prepared source count, prepared artifact count, and coverage gaps.
6. Run `run_case` with bounded settings:

   * `max_iterations`: `10` unless the user specifies otherwise.
   * `max_normalized_events`: `5000` unless the user specifies otherwise.
   * `event_selection_profile`: `forensic-triage` unless the user specifies otherwise.

7. Run `summarize_run`.
8. Run `validate_run_outputs`.
9. If `progress.jsonl` exists, summarize execution progress as operational telemetry.
10. Finish with supported findings, unsupported gaps, validation status, claim boundaries, and trace paths.

Ask at most one clarification question if the case cannot be run safely because required inputs are missing. If enough information is present, proceed.

## Visible Orchestration Log

During triage, provide concise operational updates.

Good visible updates:

```text
Planning bounded Elenchos workflow.
Preparing case artifacts.
Running deterministic Elenchos case workflow.
Inspecting generated summary outputs.
Validating required files and claim safety.
Reviewing progress telemetry.
Producing bounded findings summary.
```

Do not reveal private chain-of-thought. Expose only operational reasoning, assumptions, tool choices, status changes, evidence boundaries, and validation results.

## Progress Telemetry

`progress.jsonl` is deterministic operational telemetry, not model reasoning.

If present, summarize it after the run completes. Do not describe it as chain-of-thought.

Useful progress summary fields:

```text
phase
status
message
timestamp
case_id
```

Use progress telemetry to explain what Elenchos did at a high level: case preparation, deterministic parser workflow, normalization/selection, report generation, summary, and validation.

## Claim Discipline

Never overstate findings.

Use these statuses precisely:

```text
confirmed
inferred
needs_review
not_assessed
rejected
```

Do not claim theft, exfiltration, malware, compromise, attribution, or memory findings unless Elenchos outputs explicitly support that conclusion.

If the current artifact scope does not support a conclusion, say so directly.

Preferred wording for unsupported ROCBA theft/exfiltration claims:

```text
Elenchos did not find sufficient support for a theft or exfiltration conclusion within the submitted artifact scope.
```

Do not convert `needs_review` or `not_assessed` into a stronger conclusion.

## Self-Correction and Validation

Always surface self-correction and validation results when present.

Report:

```text
validation status
missing files
forbidden wording hits
unsupported-question safety violations
self_correction_events path/count
progress.jsonl path/count when present
audit.jsonl path
decision_trace.json path
gap_analysis.json path
report.md path
```

Self-correction is an evidence-bound correction mechanism, not model introspection.

## Generic Case Support

Do not assume every case is ROCBA.

If the user provides a casebook, use it.

If no casebook is provided, use the generic Windows disk triage workflow if available.

Keep ROCBA-specific wording out of generic runs.

For storyless Windows disk images, use conservative triage language. Do not invent APT, compromise, theft, exfiltration, or attribution claims.

## ROCBA Demo Defaults

For the ROCBA case, use:

```text
case_id: rocba-standard
source_root: /mnt/evidence/rocba
casebook: docs/casebooks/rocba-standard.json
event_selection_profile: forensic-triage
max_iterations: 10
max_normalized_events: 5000
```

ROCBA is the primary validation/demo case, but Elenchos must remain usable on other Windows disk images.

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

Keep the report concise. Prefer evidence-linked summaries over raw dumps.
