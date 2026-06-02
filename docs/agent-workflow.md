# Agent Workflow

## Purpose

The agent workflow adds a deterministic control loop around the existing
SIFTGuard pipeline. It plans a constrained forensic workflow, executes existing
inventory/parser/correlation/validation/reporting code, verifies generated
outputs, applies safe self-correction where possible, and records traceable
artifacts.

The goal is analyst-assist triage with audit-visible decisions, not autonomous
proof.

## Workflow

```text
plan -> execute -> verify -> correct -> report
```

- Plan: create an `AgentPlan` with inventory, parse, correlate, validate,
  report, and verify phases.
- Execute: run only constrained SIFTGuard Python workflow functions through
  `siftguard agent run`.
- Verify: check generated outputs before trusting findings or reports.
- Correct: retry or fall back only through explicit safe paths, then downgrade
  unsupported findings to `needs_review` where needed.
- Report: write final generated artifacts and audit entries under ignored
  output paths.

## Core Objects

- `AgentRun`: top-level record for one agent workflow, including status,
  steps, corrections, warnings/errors, output references, and timestamps.
- `AgentPlan`: deterministic plan for the case, including ordered agent steps.
- `AgentStep`: one workflow phase with status, attempts, inputs, outputs, and
  error context.
- `AgentState`: mutable run state tracking artifacts, completed steps,
  attempts, errors, corrections, and final status.
- `AgentCorrection`: audit-friendly correction record with trigger, diagnosis,
  action, result, related step, evidence references where applicable, and time.

## Execution

The constrained entrypoint is:

```bash
.venv/bin/python -m siftguard agent run-case \
  --artifact-manifest runs/CASE-ID/case-prep/case_prep.json \
  --casebook docs/casebooks/CASE-ID.json \
  --output-dir runs/CASE-ID/agent-run \
  --max-iterations 10 \
  --max-normalized-events 5000 \
  --event-selection-profile forensic-triage
```

`agent run-case` is the manifest-first path after `siftguard case prepare`.
It consumes the SIFTGuard-generated `case_prep.json`, adapts available
parser-eligible artifacts into the deterministic agent workflow, preserves
source provenance, and carries case-prep coverage gaps forward. The casebook is
optional for now and must be JSON when provided; YAML casebooks are rejected.
Memory sources from `case_prep.json` remain inventoried/not assessed for final
scope, and Amcache remains disk-first from the prepared artifact set.

The lower-level manifest entrypoint remains available:

```bash
.venv/bin/python -m siftguard agent run \
  --case-id CASE-ID \
  --manifest runs/CASE-ID/manifest.json \
  --output-dir runs/CASE-ID/agent-run \
  --max-iterations 7
```

The runner requires an explicit manifest and output directory. It does not
derive outputs from evidence paths, and it rejects output directories that are
not under ignored generated paths such as `runs/`, `outputs/`, `analysis/`, or
`reports/generated/`.

## Verification

The verifier checks that generated workflow outputs are internally consistent:

- Expected parser or normalized-event outputs exist before correlation is
  trusted.
- Confirmed and inferred findings include `evidence_refs`.
- Findings rendered in the Markdown report exist in validated finding objects.
- Unsupported confirmed findings are flagged with machine-readable failures.

Verification failures are not silently ignored. They are written to the audit
ledger and can drive the self-correction policy.

## Self-Correction

Self-correction is deterministic and intentionally narrow:

- Missing parser/output artifacts trigger a constrained retry or safe fallback
  where available; otherwise finalization is blocked for review.
- Missing evidence causes an inventory re-check before finalization.
- Unsupported confirmed or inferred findings are downgraded to `needs_review`.
- Report-only unsupported claims are removed by regenerating reports from
  validated or corrected findings.

The correction policy does not invent evidence references and does not convert
unsupported claims into confirmed findings.

## Audit

Agent-level audit events are written as JSONL entries. Key event names include:

- `agent_run_started`
- `agent_step_started`
- `agent_step_completed`
- `verification_failed`
- `correction_applied`
- `agent_run_completed`

Audit entries include stable fields such as timestamps, case id, run id, step
id where applicable, status, duration, and output references.

## Outputs

A successful agent run writes generated artifacts under the selected output
directory:

- `agent_run.json`
- `audit.jsonl`
- `coverage_summary.json`
- `normalized_events.json`
- `subject_timelines.json`
- `findings.json`
- `report.md`
- `decision_trace.json` for `agent run-case`
- `gap_analysis.json` for `agent run-case`
- `performance_summary.json` for `agent run-case`

`agent run-case` writes the extra decision, gap, and performance files as
basic initial structures for later #117/#119 expansion.

## Limitations

SIFTGuard is triage and analyst-assist tooling. It helps make deterministic
workflow execution, evidence grounding, verification, correction, and audit
visibility explicit. It does not make final forensic claims by itself, and
analyst review remains required.

Unsupported findings become `needs_review` rather than final certainty. The
workflow depends on validated inputs, constrained execution, and careful local
evidence handling.
