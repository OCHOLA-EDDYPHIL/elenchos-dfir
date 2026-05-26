# M3 Completion Review — Correlation and Validation

## Scope Summary

M3 added the correlation and validation layer that sits after normalized parser
outputs. The work added:

- An evidence-backed finding schema with claim status, confidence, provenance,
  raw record references, rationale, and report-support gating.
- Deterministic subject timeline correlation from normalized observations.
- Claim candidate validation with conservative downgrade behavior.
- Markdown reporting from validated findings only.
- A CLI workflow for normalized event JSON.
- MCP request/response schema and helper exposure for the correlation workflow.
- Audit JSONL generation for workflow steps.

M3 does not change parser behavior, parser wrapper output semantics, or raw
evidence handling.

## Implementation Issue And PR Map

| Issue | Scope | PR | Result |
| --- | --- | --- | --- |
| #37 | Finding claim-proof schema | PR #56 | Closed / merged |
| #51 | Subject timeline correlation | PR #57 | Closed / merged |
| #52 | Claim validation | PR #58 | Closed / merged |
| #53 | Validated findings report | PR #59 | Closed / merged |
| #54 | CLI/MCP workflow exposure | PR #60 | Closed / merged |

## What Was Built

The M3 pipeline is:

```text
normalized parser output JSON
→ TimelineEvent
→ SubjectTimeline
→ ClaimCandidate
→ ClaimValidationResult / Finding
→ Markdown report
→ audit JSONL
```

The implementation is evidence-conservative:

- Unsupported confirmed claims are blocked or downgraded before report
  rendering.
- Inferred claims require supporting evidence and rationale or inference-rule
  context.
- Rejected claims preserve rejection rationale and contradicting evidence when
  provided.
- Ambiguous timeline correlations become `needs_review` instead of invented
  certainty.
- The report layer defensively prevents unsupported confirmed or inferred
  findings from appearing in final report sections.

## Running The Workflow

The correlation workflow consumes existing normalized parser-event JSON, not raw
evidence images or raw registry/filesystem artifacts.

```bash
siftguard correlate \
  --case-id CASE-SYN-001 \
  --input normalized-events.json \
  --output-dir runs/CASE-SYN-001
```

Generated files include:

- `subject_timelines.json`
- `findings.json`
- `report.md`
- `audit.jsonl`

Generated paths such as `runs/` are ignored output paths. Do not commit
generated workflow outputs, parser outputs, reports, or audit ledgers.

## Input Contract Summary

The workflow expects a JSON object with a case identifier and an `events` array.
Events are normalized parser observations that can be converted into
`TimelineEvent` objects. A compact synthetic example:

```json
{
  "case_id": "CASE-SYN-001",
  "events": [
    {
      "event_type": "drop",
      "timestamp": "2026-01-01T00:00:01Z",
      "source": "mft",
      "path": "C:/Users/Alice/AppData/Local/Temp/example-a.exe",
      "evidence_refs": [
        {
          "evidence_id": "EV-SYN-MFT-001",
          "parser": "mftecmd",
          "source": "$MFT",
          "raw_record_ref": "csv:mft.csv:1842"
        }
      ]
    }
  ]
}
```

This is synthetic documentation data only. The workflow preserves supplied
evidence identifiers and raw record references; it does not invent evidence
provenance.

## Validation And Report Safety

- Confirmed findings require evidence references, raw record support, rationale,
  and artifact hashes or a documented hash limitation.
- Inferred findings require evidence references plus rationale and inference
  support.
- Rejected findings preserve rejection rationale and contradicting evidence
  references when available.
- `needs_review` captures incomplete, ambiguous, or insufficient support.
- Report sections are status-gated.
- Unsupported claims are not shown as confirmed.

## Audit Trail

The workflow writes a generated JSONL audit ledger with these actions:

- `workflow_started`
- `input_loaded`
- `timelines_built`
- `claims_validated`
- `report_rendered`
- `workflow_completed`

Audit ledgers are generated outputs and should not be committed.

## Tests And Gates

Final #54 implementation gates recorded after PR #60:

| Gate | Result |
| --- | --- |
| `git diff --check` | passed |
| `.venv/bin/python -m pytest` | 242 passed, 3 skipped |
| `.venv/bin/python -m ruff check .` | passed |
| `.venv/bin/python -m mypy src` | passed |

Docs PR #55 gates recorded on 2026-05-26 UTC:

| Gate | Result |
| --- | --- |
| `git diff --check` | passed |
| `.venv/bin/python -m pytest` | 242 passed, 3 skipped |
| `.venv/bin/python -m ruff check .` | passed |
| `.venv/bin/python -m mypy src` | passed; no issues in 44 source files |

## Evidence Safety

The closeout uses these safety checks before commit:

- A tracked-file grep for evidence, generated output, parser output, audit
  ledger, VM image, hive, and private-path patterns.
- A repo-local `find` for evidence images, registry hives, `$MFT`, and
  `audit.jsonl`.
- Final `git status --short`.

Recorded safety outcome for M3 closeout:

- No evidence committed.
- No parser outputs committed.
- No generated reports committed.
- No audit ledgers committed.
- No secrets or private paths committed.
- `runs/` and `.local/` remain uncommitted generated/local paths.

## Limitations And Out Of Scope

- M3 does not add memory forensics.
- M3 does not add remote triage.
- M3 does not add a web UI.
- M3 does not add new parser families.
- MCP workflow exposure accepts paths to normalized parser output JSON; it does
  not upload raw evidence bytes.
- The workflow expects normalized parser outputs from existing parser contracts.
- Synthetic tests validate software behavior. Real evidence validation remains
  environment-gated.
- Findings are evidence-backed software outputs, not legal conclusions.

## Next Work

Subsequent work can add agent self-correction, richer validation policies, and
broader evidence fixtures after M3 is closed.
