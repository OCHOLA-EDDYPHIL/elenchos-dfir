# Execution Log Traceability

## Purpose

SIFTGuard MCP writes structured local execution artifacts so an evaluator or
practitioner can trace generated findings back to workflow steps, tool
executions, normalized records, and manifest artifacts. Raw private logs,
private paths, raw evidence, and generated parser outputs are not committed.

This document describes the log fields, traceability chain, regeneration
commands, and sanitized run summaries used for final evaluation.

## Generated Files

A constrained agent run writes these generated files under an ignored output
directory such as `runs/<case-id>/agent-run/`:

- `agent_run.json`: agent status, plan, executed steps, corrections, warnings,
  errors, and output references.
- `audit.jsonl`: append-only JSONL execution ledger for lifecycle events, tool
  executions, verification, and correction.
- `coverage_summary.json`: artifact coverage, parser status, bounded selection
  counts, skipped/unavailable artifacts, and limitations.
- `normalized_events.json`: normalized observations produced from parser output
  or parser wrappers.
- `subject_timelines.json`: correlated timelines grouped by subject.
- `findings.json`: validated finding objects and validation status.
- `report.md`: analyst-readable Markdown report generated from validated
  findings.

Generated outputs normally remain local. Commit only deliberately sanitized
examples that have been reviewed for private paths, hostnames, usernames,
secrets, raw evidence content, and sensitive case data.

## Field Reference

Common `agent_run.json` and `audit.jsonl` fields:

| Field | Meaning |
| --- | --- |
| `timestamp_utc` | UTC event time. |
| `event_type` / `action` | Agent lifecycle, verification, correction, or tool execution event. |
| `case_id` | Local case identifier. Use sanitized labels in documentation. |
| `run_id` | Agent run identifier when the event is agent-scoped. |
| `step_id` | Workflow step such as `step_inventory`, `step_parse`, or `step_verify`. |
| `phase` | Agent phase such as `inventory`, `parse`, `correlate`, `validate`, `report`, or `verify`. |
| `tool_name` | Parser wrapper tool name for tool execution entries, such as `mftecmd`, `recmd`, or `amcacheparser`. |
| `command` | Sanitized argv-style tool operation recorded for parser wrapper entries. |
| `status` | Step, run, parser, verification, or correction status. |
| `duration_ms` | Duration recorded for the event or tool execution. |
| `output_refs` | Repo-local or run-local generated output references. |
| `stdout_path` / `stderr_path` | Parser wrapper output log references where present. |
| `exit_code` | Tool process exit code where present. |
| `error` / `warnings` | Error or warning state when present. |
| `correction_*` | Correction id, trigger, action, and result when self-correction runs. |

## Traceability Chain

A final report sentence should be traceable through this chain:

```text
report.md sentence
-> finding id
-> findings.json
-> evidence_refs
-> normalized_events.json
-> coverage_summary.json
-> parser/tool execution
-> audit.jsonl event
-> original manifest artifact entry
```

For private evidence runs, keep the full chain local. Committed documentation
should use placeholders for case paths, artifact ids, hashes, and any sensitive
host or user context.

To map a specific finding:

1. Open `report.md` and copy the finding id shown in the narrative.
2. Look up the same id in `findings.json`.
3. Record the finding status and `evidence_refs`.
4. Match each evidence reference to the related normalized event or parser
   result entry.
5. Use `coverage_summary.json` to confirm artifact coverage, parser status,
   bounded selection, skipped artifacts, and limitations.
6. Use `audit.jsonl` to identify the parser or agent step that produced the
   referenced output.
7. Use `manifest.json` to confirm the source artifact class and local artifact
   entry without publishing private paths or hashes.

## Regeneration Commands

Use local staged evidence outside the repository:

```bash
CASE_ID="case_staged-primary"
RUN_ROOT="runs/${CASE_ID}"
MANIFEST_PATH="${RUN_ROOT}/manifest.json"
AGENT_OUT="${RUN_ROOT}/agent-run"

mkdir -p "$RUN_ROOT"

.venv/bin/python -m siftguard inventory <STAGED_PRIMARY_ROOT> \
  --manifest-out "$MANIFEST_PATH"
```

Read the manifest case id before running the agent:

```bash
MANIFEST_CASE_ID="$(
  .venv/bin/python - <<'PY'
import json
from pathlib import Path
print(json.loads(Path("runs/case_staged-primary/manifest.json").read_text())["case_id"])
PY
)"
```

Run the constrained agent workflow:

```bash
.venv/bin/python -m siftguard agent run \
  --case-id "$MANIFEST_CASE_ID" \
  --manifest "$MANIFEST_PATH" \
  --output-dir "$AGENT_OUT" \
  --max-iterations 7 \
  --max-normalized-events 5000 \
  --event-selection-profile forensic-triage
```

Run controlled validation fixtures:

```bash
.venv/bin/python -m siftguard agent run-fixture \
  --case-id case_positive-control \
  --fixture tests/fixtures/positive_control/positive_chain.json \
  --output-dir runs/case_positive-control/agent-run \
  --max-iterations 7

.venv/bin/python -m siftguard agent run-fixture \
  --case-id case_self-correction-control \
  --fixture tests/fixtures/positive_control/unsupported_claim.json \
  --output-dir runs/case_self-correction-control/agent-run \
  --max-iterations 7
```

Inspect generated summaries without committing raw logs:

```bash
find "$AGENT_OUT" -maxdepth 2 -type f -printf '%P %s bytes\n'
.venv/bin/python -m siftguard audit-read "$AGENT_OUT/audit.jsonl"
SUMMARY_PATH="$AGENT_OUT/coverage_summary.json" .venv/bin/python - <<'PY'
import json
import os
from pathlib import Path
summary = json.loads(Path(os.environ["SUMMARY_PATH"]).read_text())
print(summary["selection_profile"], summary["normalized_events_written"])
PY
```

## Primary Staged-Evidence Run

The primary local run used staged artifacts matching `docs/dataset.md`:

- `$MFT`
- `registry/SOFTWARE`
- `registry/NTUSER.DAT`
- `amcache/Amcache.hve`

An initial unbounded run completed inventory and started parse, then exited
`137` before final outputs were written. Local kernel logs showed the Python
process was killed by the OOM path at approximately 3.3 GB resident memory. The
completed run below therefore used the resource-adaptive `forensic-triage`
profile with an explicit deterministic normalized-event cap. It is bounded
triage, not exhaustive full-`$MFT` analysis.

Sanitized run facts:

| Item | Value |
| --- | --- |
| Manifest case id | `case_staged-primary` |
| Manifest artifact count | 4 |
| Agent command | `siftguard agent run --case-id case_staged-primary --manifest runs/<case-id>/manifest.json --output-dir runs/<case-id>/agent-run-final --max-iterations 7 --max-normalized-events 5000 --event-selection-profile forensic-triage` |
| Agent exit code | 0 |
| Agent final status | `completed` |
| Step count | 6 |
| Completed agent phases | inventory, parse, correlate, validate, report, verify |
| Event selection profile | `forensic-triage` |
| Max normalized events | 5000 |
| Limit reached | yes |
| Normalized event count | 5000 |
| Total source events seen | 947241 |
| Timeline count | 1347 |
| Finding count | 128 |
| Finding status counts | `needs_review`: 128 |
| MFT-only findings | 0 |
| Audit entry count | 22 |
| Warning count | 6 |
| Error count | 0 |
| Correction count | 0 |

Sanitized parser contribution counts:

| Artifact class | Normalized events included | Parser status |
| --- | ---: | --- |
| `SOFTWARE` Run/RunOnce | 1 | `success` |
| `Amcache.hve` | 128 | `partial_success` |
| `$MFT` | 4871 | `partial_success`, bounded |
| user `NTUSER.DAT` Run/RunOnce | 0 | `failed` for queried keys |

The primary staged-evidence bounded run generated local audit, finding,
timeline, normalized-event, coverage, agent-run, and report outputs. These
outputs remain local because they are derived from private evidence. The
committed summary is limited to sanitized counts and the explicit bounded-mode
setting.

## Positive-Control Fixture Run

The positive-control fixture is synthetic and proves that the same agent path
emits a supportable finding when a coherent chain is present.

| Item | Value |
| --- | --- |
| Case id | `case_positive-control` |
| Input source | `synthetic_positive_control` |
| Agent status | `completed` |
| Step count | 6 |
| Correction count | 0 |
| Normalized event count | 6 |
| Timeline count | 2 |
| Finding count | 1 |
| Finding status counts | `inferred`: 1 |
| Evidence categories | `$MFT`, Registry, Amcache |
| Audit entry count | 17 |

## Self-Correction Fixture Run

The self-correction fixture is synthetic and introduces an unsupported proposed
`inferred` claim. The verifier detects missing evidence support, the correction
path downgrades the finding, and the final report is regenerated from corrected
findings.

| Item | Value |
| --- | --- |
| Case id | `case_self-correction-control` |
| Input source | `synthetic_self_correction_control` |
| Agent status | `completed` |
| Step count | 7 |
| Correction count | 2 |
| Final finding status counts | `needs_review`: 2 |
| Audit entry count | 27 |
| Correction audit events | `correction_applied`: 2 |

## Successful Synthetic Agent Path

The successful full-path example was generated with the repository's synthetic
agent smoke helper:

```bash
./scripts/openclaw-agent-smoke.sh
```

Sanitized summary:

| Item | Value |
| --- | --- |
| Case id | `CASE-AGENT-OPENCLAW-SMOKE` |
| Agent status | `completed` |
| Step count | 6 |
| Correction count | 0 |
| Error count | 0 |
| Warning count | 0 |
| Normalized event count | 4 |
| Timeline count | 1 |
| Finding count | 1 |
| Finding status counts | `inferred`: 1 |
| Audit entry count | 16 |

Audit event counts:

| Event type | Count |
| --- | ---: |
| `agent_run_started` | 1 |
| `agent_step_started` | 6 |
| `agent_step_completed` | 6 |
| `verification_started` | 1 |
| `verification_completed` | 1 |
| `agent_run_completed` | 1 |

## Synthetic Induced Self-Correction Path

The primary staged-evidence run did not reach a natural self-correction episode.
Self-correction evidence was therefore generated separately from the repository's
existing synthetic unsupported-finding fixture. This is not primary evidence
accuracy data; it is controlled execution-log evidence for verifier and
correction behavior.

Sanitized summary:

| Item | Value |
| --- | --- |
| Case id | `CASE-SYN-INDUCED-CORRECTION` |
| Initial verification status | `failed` |
| Follow-up verification status | `passed` |
| Agent status | `completed` |
| Correction count | 2 |
| Finding count | 1 |
| Final finding status counts | `needs_review`: 1 |
| Audit entry count | 10 |

Audit event counts:

| Event type | Count |
| --- | ---: |
| `verification_started` | 2 |
| `verification_failed` | 2 |
| `verification_completed` | 2 |
| `correction_started` | 1 |
| `correction_applied` | 2 |
| `correction_completed` | 1 |

The induced correction recorded an inventory re-check followed by a downgrade
from unsupported `confirmed` to `needs_review`.

## Sanitized Examples

Agent step completion:

```json
{
  "event_type": "agent_step_completed",
  "case_id": "<CASE_ID>",
  "run_id": "run_<CASE_ID>",
  "step_id": "step_inventory",
  "phase": "inventory",
  "status": "completed",
  "duration_ms": 0,
  "output_refs": {}
}
```

Parser wrapper execution:

```json
{
  "case_id": "<CASE_ID>",
  "tool_name": "mftecmd",
  "command": ["MFTECmd", "-f", "<STAGED_PRIMARY_ROOT>/mft/$MFT"],
  "status": "success",
  "exit_code": 0,
  "duration_ms": 1000,
  "stdout_path": "runs/<case-id>/agent-run/<case-id>/logs/<tool-stdout>.log",
  "stderr_path": "runs/<case-id>/agent-run/<case-id>/logs/<tool-stderr>.log"
}
```

Self-correction event:

```json
{
  "event_type": "correction_applied",
  "case_id": "<SYNTHETIC_CASE_ID>",
  "correction_id": "correction_000002",
  "correction_trigger": "unsupported_finding",
  "correction_action": "downgrade_finding",
  "status": "completed",
  "step_id": "step_verify",
  "output_refs": {
    "findings": "findings.json",
    "report": "report.md"
  }
}
```

## Closure Notes

Issue #90 can be closed when this document is committed with validation output:

- It documents generated execution-log fields and regeneration commands.
- It records a full successful synthetic investigation path.
- It records a synthetic induced self-correction path.
- It records the incomplete primary staged-evidence attempt honestly.

Issue #89 should remain open until false positives, missed artifacts,
unsupported claims, and final accuracy status are reviewed.
