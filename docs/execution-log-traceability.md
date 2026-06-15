# Execution Log Traceability

## Purpose

Elenchos writes structured local execution artifacts so an evaluator or
practitioner can trace generated findings back to workflow steps, tool
executions, normalized records, and manifest artifacts. Raw private logs,
private paths, raw evidence, and generated parser outputs are not committed.

This document describes log fields, the traceability chain, regeneration
commands, and sanitized run summaries.

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

.venv/bin/python -m elenchos inventory <STAGED_PRIMARY_ROOT> \
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
.venv/bin/python -m elenchos agent run \
  --case-id "$MANIFEST_CASE_ID" \
  --manifest "$MANIFEST_PATH" \
  --output-dir "$AGENT_OUT" \
  --max-iterations 7 \
  --max-normalized-events 5000 \
  --event-selection-profile forensic-triage
```

Run controlled validation fixtures:

```bash
.venv/bin/python -m elenchos agent run-fixture \
  --case-id case_positive-control \
  --fixture tests/fixtures/positive_control/positive_chain.json \
  --output-dir runs/case_positive-control/agent-run \
  --max-iterations 7

.venv/bin/python -m elenchos agent run-fixture \
  --case-id case_self-correction-control \
  --fixture tests/fixtures/positive_control/unsupported_claim.json \
  --output-dir runs/case_self-correction-control/agent-run \
  --max-iterations 7
```

Inspect generated summaries without committing raw logs:

```bash
find "$AGENT_OUT" -maxdepth 2 -type f -printf '%P %s bytes\n'
.venv/bin/python -m elenchos audit-read "$AGENT_OUT/audit.jsonl"
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
| Agent command | `elenchos agent run --case-id case_staged-primary --manifest runs/<case-id>/manifest.json --output-dir runs/<case-id>/agent-run-final --max-iterations 7 --max-normalized-events 5000 --event-selection-profile forensic-triage` |
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

## Internal Verifier Fixture Run

The verifier fixture is synthetic and introduces an unsupported proposed
`inferred` claim. It remains useful for regression testing verifier downgrade
behavior. The bounded OpenClaw workflow uses casebook-defined claim-boundary
posture revisions recorded by Elenchos outputs.

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

## OpenClaw/MCP Adapter Smoke Path

The preferred OpenClaw/MCP smoke example is generated through the bounded
adapter harness:

```bash
.venv/bin/python scripts/openclaw_elenchos_smoke.py --dry-run --output-dir runs/openclaw-smoke
```

Sanitized summary:

| Item | Value |
| --- | --- |
| Case id | `CASE-OPENCLAW-ELENCHOS-SMOKE` |
| Prepare status | `completed` |
| Run status | `completed` |
| Validation status | `pass` |
| Finding status counts | `{}` |
| Case-question status counts | `not_assessed`: 4 |
| Claim-boundary self-correction events | `claim-boundary-001`: 1 |

Adapter trace outputs:

| Trace file | Purpose |
| --- | --- |
| `runs/openclaw-smoke/openclaw-trace/prepare_case.stdout` | Prepared-case adapter stdout |
| `runs/openclaw-smoke/openclaw-trace/prepare_case.stderr` | Prepared-case adapter stderr |
| `runs/openclaw-smoke/openclaw-trace/run_case.stdout` | Run-case adapter stdout |
| `runs/openclaw-smoke/openclaw-trace/run_case.stderr` | Run-case adapter stderr |
| `runs/openclaw-smoke/openclaw-trace/summary.json` | Combined smoke summary |
| `runs/openclaw-smoke/agent-run/self_correction_events.json` | Casebook-defined claim-boundary posture event |

## Real-Gap OpenClaw Self-Correction Path

Real-gap OpenClaw self-correction is not an induced error. OpenClaw calls the
bounded Elenchos tools, reads generated outputs only, and observes that the
configured claim-boundary questions remain unsupported by the submitted
artifact scope. Elenchos records this as `self_correction_events.json` from
casebook metadata so OpenClaw can revise its investigative posture without
treating model output as evidence.

Sanitized summary:

| Item | Value |
| --- | --- |
| Event id | `claim-boundary-001` |
| Phase | `claim_validation` |
| Human intervention | `false` |
| Source questions | Casebook-defined primary and related claim-boundary question IDs |
| Final wording | Elenchos did not find sufficient support for a theft or exfiltration conclusion within the submitted artifact scope. |
| Scope boundary | The current artifact scope does not support a theft/exfiltration conclusion; additional artifacts such as browser history, cloud sync logs, network telemetry, removable-device artifacts, or memory analysis would be required. |

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

## Documentation Notes

This document records generated execution-log fields, regeneration commands,
synthetic validation paths, the bounded OpenClaw/MCP adapter path, real-gap
posture sidecars, and sanitized primary-run limits. Accuracy review should
continue to distinguish false positives, missed artifacts, unsupported claims,
and validated findings.
