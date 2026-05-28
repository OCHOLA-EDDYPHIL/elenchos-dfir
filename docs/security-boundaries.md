# Security Boundaries

## Evidence Integrity

Evidence remains local-only and read-only. SIFTGuard demos use synthetic inputs
unless a maintainer explicitly prepares a local evidence demo. Generated
outputs go under ignored run paths such as `runs/`, and raw evidence is never
committed.

The active permission policy surface is intentionally small: read-only evidence
posture, generated outputs outside evidence roots, and no arbitrary shell as the
agent interface. Enforcement lives in path validation, parser wrappers,
subprocess execution, and the deterministic agent runner; `permissions.py`
declares those current invariants without claiming a comprehensive sandbox.

## Constrained Execution

OpenClaw is instructed to call constrained SIFTGuard entrypoints. The workflow
boundary is `siftguard agent run`; raw shell is not the forensic interface.
SIFTGuard does not expose arbitrary command execution as an agent feature.

The OpenClaw smoke helper is fixed to the synthetic agent workflow. It does not
accept a free-form command string.

The planner is deterministic. It constructs the fixed inventory, parse,
correlate, validate, report, and verify workflow phases rather than accepting
free-form LLM-generated action plans.

## Verification And Correction

The verifier blocks unsupported outputs from becoming trusted final results.
Confirmed and inferred findings must have evidence references. Reported
findings must exist in validated finding objects. Unsupported confirmed
findings are flagged.

Self-correction is deterministic and narrow. Missing evidence causes inventory
re-check or review/block-finalization behavior. Unsupported confirmed or
inferred findings are downgraded to `needs_review`. The system must not invent
`evidence_refs`.

## Audit Trail

Every agent run records audit-visible lifecycle events. Runs, steps,
verification failures, corrections, and completion events are written to JSONL.
`agent_run.json` and `audit.jsonl` provide traceability from final outputs back
to workflow execution and correction decisions.

## Secrets And Runtime State

Do not commit credentials, provider tokens, API keys, browser/device-code
values, account identifiers, OpenClaw auth state, Codex auth state, gateway
logs, transcripts, shell history, or `.codex` / `.openclaw` contents.

Do not paste raw evidence, secrets, local case paths, private hostnames, or
usernames into OpenClaw prompts or committed documentation.

## Limitations

SIFTGuard is triage and analyst-assist tooling. Deterministic verification and
audit-visible correction reduce interpretation risk, but they do not eliminate
the need for analyst review. The project should not be presented as
final forensic proof.
