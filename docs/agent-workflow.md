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

When a JSON casebook is provided, `agent run-case` maps normalized MFT,
Amcache, Registry Run/RunOnce, and NTUSER Registry user-activity evidence to
explicit case questions. User-activity coverage currently includes UserAssist,
RecentDocs, OpenSavePidlMRU, LastVisitedPidlMRU, and TypedPaths. Statuses are
intentionally strict:

- `confirmed`: direct case context plus multiple supported artifacts with
  evidence references and same-source provenance.
- `inferred`: at least two independent supported evidence references or an
  already validated inferred finding with matching casebook context.
- `needs_review`: relevant evidence exists, but it is weak, single-source,
  ambiguous, or context-dependent.
- `not_assessed`: the question requires unsupported artifacts or staged memory.
- `rejected`: a proposed claim was contradicted or failed validation.

`not_assessed` is deliberate, not a workflow failure. Under the current final
scope, memory, theft contents, transfer destination, and exfiltration method
questions remain `not_assessed` unless future supported parsers produce direct
evidence.

Casebooks may include an optional `triage_profile` with `keywords`,
`sensitive_paths`, and `file_extensions` to prioritize file-candidate review.
These profile values are analyst-provided hints only; they do not prove theft,
exfiltration, compromise, or any unsupported claim.

Registry user-activity findings are review leads. RecentDocs and OpenSave
events can identify file-access or open/save candidates; UserAssist and
LastVisitedPidlMRU can identify program-use or dialog-interaction candidates;
TypedPaths can identify user-navigation candidates. A single user-activity
source remains `needs_review`. `inferred` requires independent corroboration
from another supported artifact class, and transfer/cloud/archive candidates
remain `needs_review` unless direct evidence supports a stronger claim.

`case prepare` extracts each discovered `Users/*/NTUSER.DAT` hive into a
sanitized profile-specific path such as
`extracted/registry/profiles/profile-0001/NTUSER.DAT`. `agent run-case` parses
each available profile hive independently and carries `profile_id` provenance
into events, findings, gaps, and report sections. Coverage is not reported as
complete when any discovered profile hive failed extraction or parsing.

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
- `case_questions.json` for `agent run-case`
- `decision_trace.json` for `agent run-case`
- `gap_analysis.json` for `agent run-case`
- `self_correction_events.json` for real unsupported-scope posture revisions
- `performance_summary.json` for `agent run-case`

`case_questions.json` records the casebook question status, linked evidence,
and recommended manual review. `decision_trace.json` records concise product
reasoning for manifest intake, provenance checks, casebook handling, scope
selection, parser planning, Registry user-activity handling, validation,
correction, case-question mapping, status assignment, and report generation.
`gap_analysis.json` carries case-prep and user-activity parser/key gaps forward
and links unsupported areas back to the same question IDs.
`self_correction_events.json` records deterministic real-gap posture revisions,
including the ROCBA theft/exfiltration gap when the submitted artifact scope is
insufficient for that conclusion.

## Limitations

SIFTGuard is triage and analyst-assist tooling. It helps make deterministic
workflow execution, evidence grounding, verification, correction, and audit
visibility explicit. It does not make final forensic claims by itself, and
analyst review remains required.

Unsupported findings become `needs_review` rather than final certainty. The
workflow depends on validated inputs, constrained execution, and careful local
evidence handling.
