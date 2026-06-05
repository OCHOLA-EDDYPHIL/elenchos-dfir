# SIFTGuard MCP

SIFTGuard MCP is a local-first, constrained DFIR workflow for SANS SIFT
Workstation and Linux terminal environments. It addresses Windows disk-artifact
triage by inventorying evidence, running typed parser workflows, correlating
drop / persistence / execution signals, validating findings, and producing
traceable audit logs and analyst-readable reports.

The supported submission scope is intentionally narrow: `$MFT`, Registry
`Run`/`RunOnce` keys, and `Amcache.hve`. Evidence is treated as read-only input.
Parser and agent outputs are written to ignored generated-output directories,
not into raw evidence locations. Public command surfaces use typed arguments and
constrained SIFTGuard entrypoints instead of arbitrary shell execution.

## What This Does

- Inventories locally staged evidence and records SHA256-backed manifests.
- Runs constrained parser workflows for `$MFT`, Registry Run Keys, and Amcache.
- Normalizes parser observations into `ParserEvent` records.
- Correlates drop, persistence, and execution signals from normalized events.
- Validates findings and distinguishes confirmed, inferred, rejected, and
  needs-review claims.
- Produces JSON, JSONL audit ledgers, and Markdown reports under generated
  output paths such as `runs/`.
- Supports a constrained deterministic agent workflow with verification and
  self-correction records.
- Exposes typed MCP schemas for the supported workflow boundaries.

## What This Does Not Do

- Does not certify legal admissibility or evidentiary certainty.
- Does not modify raw evidence.
- Does not perform offensive operations.
- Does not claim broad DFIR coverage.
- Does not currently support memory forensics, packet analysis, cloud incident
  response, or remote endpoint triage.
- Does not replace analyst review.

Parser observations are not findings by themselves. SIFTGuard is triage and
analyst-assist tooling that makes evidence references, validation status, and
audit trail quality explicit.

## Quick Start

Use Python 3.10 or newer in a Linux/SIFT-compatible shell.

```bash
git clone https://github.com/OCHOLA-EDDYPHIL/siftguard-mcp.git
cd siftguard-mcp

python -m venv .venv
source .venv/bin/activate
.venv/bin/python -m pip install -e ".[dev]"

.venv/bin/python -m pytest
.venv/bin/python -m ruff check .
.venv/bin/python -m mypy src
```

The package also installs a `siftguard` console script. The examples below use
`.venv/bin/python -m siftguard` so they work without relying on shell `PATH`.

## Local Evidence Layout

Stage evidence outside the repository. The commands below use `/cases/demo/evidence`
as a placeholder.

```text
/cases/demo/evidence/
  mft/$MFT
  registry/NTUSER.DAT
  registry/SOFTWARE
  amcache/Amcache.hve
```

Set reusable shell variables:

```bash
export EVIDENCE_ROOT="/cases/demo/evidence"
export CASE_ID="case_evidence"
export RUN_DIR="runs/demo"
export LEDGER_PATH="$RUN_DIR/audit.jsonl"

mkdir -p "$RUN_DIR"
```

For the placeholder evidence root above, the inventory command derives
`case_id=case_evidence`. If you use a different evidence directory name, update
`CASE_ID` to match the `case_id=` value printed by `siftguard inventory`.

Raw evidence and generated parser outputs should remain uncommitted unless a
specific sanitized example is intentionally added for documentation.

## Evidence Inventory And Hashing

Inventory staged evidence and write a manifest:

```bash
.venv/bin/python -m siftguard inventory "$EVIDENCE_ROOT" \
  --manifest-out "$RUN_DIR/manifest.json"
```

Hash a specific artifact when needed:

```bash
.venv/bin/python -m siftguard hash "$EVIDENCE_ROOT/mft/\$MFT"
```

Expected output:

- `manifest.json` with artifact IDs, relative paths, sizes, SHA256 hashes, and
  artifact classifications.
- A printed SHA256 digest for `hash`.

## Case Preparation

For E01-backed cases, SIFTGuard can discover sources and prepare the supported
artifact set itself. Analysts should not hand-author the prepared artifact
manifest consumed by later workflows.

Source-root discovery writes a local JSON source manifest under ignored
`.local/` and writes generated case-prep outputs under ignored run paths:

```bash
.venv/bin/python -m siftguard case prepare \
  --case-id "$CASE_ID" \
  --source-root "<SOURCE_ROOT>" \
  --source-manifest-out ".local/cases/$CASE_ID/source-manifest.json" \
  --output-dir "$RUN_DIR/case-prep"
```

An existing JSON source manifest can be reused:

```bash
.venv/bin/python -m siftguard case prepare \
  --case-id "$CASE_ID" \
  --source-manifest ".local/cases/$CASE_ID/source-manifest.json" \
  --output-dir "$RUN_DIR/case-prep"
```

Expected outputs include `case_prep.json`, `source_manifest.json`,
`source_image_manifest.json`, `extraction_audit.jsonl`, `warnings.json`, and
available extracted artifacts under `extracted/`. Memory sources are staged and
inventoried only for the final submission scope. Amcache preparation searches
the disk image first for `Windows/AppCompat/Programs/Amcache.hve`.

## Parser Workflow

The parser commands are implemented, but they require locally staged artifacts
and the documented SIFT parser tools to be available in the environment. See
[docs/parser-tooling-matrix.md](docs/parser-tooling-matrix.md) for tool details.

Run MFTECmd against a staged `$MFT`:

```bash
.venv/bin/python -m siftguard parse-mft \
  --case-id "$CASE_ID" \
  --artifact-id "EV-MFT-0001" \
  --mft-path "$EVIDENCE_ROOT/mft/\$MFT" \
  --runs-root "$RUN_DIR" \
  --evidence-root "$EVIDENCE_ROOT" \
  --ledger-path "$LEDGER_PATH" \
  --json-out "normalized/EV-MFT-0001-mftecmd.json"
```

Run RECmd against user and machine Run Key hives:

```bash
.venv/bin/python -m siftguard parse-registry-runkeys \
  --case-id "$CASE_ID" \
  --artifact-id "EV-REG-USER-0001" \
  --hive-path "$EVIDENCE_ROOT/registry/NTUSER.DAT" \
  --artifact-type registry_hive \
  --runs-root "$RUN_DIR" \
  --evidence-root "$EVIDENCE_ROOT" \
  --ledger-path "$LEDGER_PATH" \
  --json-out "normalized/EV-REG-USER-0001-recmd.json"

.venv/bin/python -m siftguard parse-registry-runkeys \
  --case-id "$CASE_ID" \
  --artifact-id "EV-REG-SOFTWARE-0001" \
  --hive-path "$EVIDENCE_ROOT/registry/SOFTWARE" \
  --artifact-type registry_hive \
  --runs-root "$RUN_DIR" \
  --evidence-root "$EVIDENCE_ROOT" \
  --ledger-path "$LEDGER_PATH" \
  --json-out "normalized/EV-REG-SOFTWARE-0001-recmd.json"
```

Run AmcacheParser against a staged `Amcache.hve`:

```bash
.venv/bin/python -m siftguard parse-amcache \
  --case-id "$CASE_ID" \
  --artifact-id "EV-AMCACHE-0001" \
  --amcache-path "$EVIDENCE_ROOT/amcache/Amcache.hve" \
  --runs-root "$RUN_DIR" \
  --evidence-root "$EVIDENCE_ROOT" \
  --ledger-path "$LEDGER_PATH" \
  --json-out "normalized/EV-AMCACHE-0001-amcacheparser.json"
```

Expected parser outputs:

- `ParserResult` JSON under `$RUN_DIR/normalized/`.
- Tool stdout/stderr logs and parser outputs under generated run paths.
- Audit JSONL entries at `$LEDGER_PATH`.
- Normalized parser events embedded in each parser result JSON.

## Correlation And Validation Workflow

The direct correlation command consumes one normalized parser-output JSON file
and writes timelines, findings, a Markdown report, and an audit ledger.

```bash
.venv/bin/python -m siftguard correlate \
  --case-id "$CASE_ID" \
  --input "$RUN_DIR/normalized/EV-MFT-0001-mftecmd.json" \
  --output-dir "$RUN_DIR/correlation"
```

Expected correlation outputs:

- `$RUN_DIR/correlation/subject_timelines.json`
- `$RUN_DIR/correlation/findings.json`
- `$RUN_DIR/correlation/report.md`
- `$RUN_DIR/correlation/audit.jsonl`

Use the agent workflow below for a manifest-driven run across the staged
artifact set.

## Agent Workflow

The constrained agent workflow runs the deterministic SIFTGuard pipeline around
an evidence manifest or supported parser-output manifest. With raw artifacts, it
requires the same staged evidence and SIFT parser tools as the parser workflow.

For E01-backed cases prepared by SIFTGuard, use the generated
`case_prep.json` from `case prepare`; analysts do not hand-author the prepared
artifact manifest. Memory source records are preserved as inventory/provenance
only and are not analyzed in the final submission scope.

```bash
.venv/bin/python -m siftguard agent run-case \
  --artifact-manifest "$RUN_DIR/case-prep/case_prep.json" \
  --casebook "docs/casebooks/$CASE_ID.json" \
  --output-dir "$RUN_DIR/agent-run" \
  --max-iterations 10 \
  --max-normalized-events 5000 \
  --event-selection-profile forensic-triage
```

The `--casebook` argument is optional until the JSON casebook is available. YAML
casebooks are not supported in the final sprint. `agent run-case` carries
case-prep coverage gaps forward, keeps memory out of scope, and applies the
same disk-first Amcache scope established during case preparation.

With a JSON casebook, `agent run-case` also writes case-question summaries and
strict finding statuses. `confirmed` requires multiple supported artifacts with
evidence references and same-source provenance, `inferred` requires independent
supported evidence, `needs_review` marks weak or ambiguous support, `rejected`
marks contradicted claims, and `not_assessed` marks unsupported questions. Memory,
theft contents, transfer destination, and exfiltration method questions are
`not_assessed` under the current final scope unless direct parsed evidence is
added later.

When a prepared `NTUSER.DAT` hive is available, `agent run-case` also attempts
generic Registry user-activity coverage for UserAssist, RecentDocs,
OpenSavePidlMRU, LastVisitedPidlMRU, and TypedPaths. These events can produce
file, program, and navigation review candidates with provenance; they do not
prove theft, transfer, exfiltration, or compromise by themselves.
`case prepare` stages each discovered `Users/*/NTUSER.DAT` profile hive under a
sanitized profile path such as
`extracted/registry/profiles/profile-0001/NTUSER.DAT`. Coverage is only complete
for profile hives that were discovered, extracted, and considered by
`agent run-case`; per-profile extraction or parser failures remain explicit
coverage gaps.

```bash
.venv/bin/python -m siftguard agent run \
  --case-id "$CASE_ID" \
  --manifest "$RUN_DIR/manifest.json" \
  --output-dir "$RUN_DIR/agent-run" \
  --max-iterations 7 \
  --max-normalized-events 5000 \
  --event-selection-profile forensic-triage
```

Expected agent outputs:

- `$RUN_DIR/agent-run/agent_run.json`
- `$RUN_DIR/agent-run/audit.jsonl`
- `$RUN_DIR/agent-run/coverage_summary.json`
- `$RUN_DIR/agent-run/normalized_events.json`
- `$RUN_DIR/agent-run/subject_timelines.json`
- `$RUN_DIR/agent-run/findings.json`
- `$RUN_DIR/agent-run/report.md`
- `$RUN_DIR/agent-run/case_questions.json` for `agent run-case`
- `$RUN_DIR/agent-run/decision_trace.json` for `agent run-case`
- `$RUN_DIR/agent-run/gap_analysis.json` for `agent run-case`
- `$RUN_DIR/agent-run/self_correction_events.json` for real unsupported-scope
  posture revisions
- `$RUN_DIR/agent-run/performance_summary.json` for `agent run-case`

The agent records plan, execute, verify, correct, and report phases. Unsupported
or internally inconsistent outputs are downgraded, retried through constrained
paths, or marked for review rather than silently treated as confirmed findings.
The `--max-normalized-events` value is an explicit bounded-triage setting for
large staged artifacts; remove it only when the local environment can complete
the full normalized event volume. `--event-selection-profile forensic-triage`
preserves available Registry and Amcache observations before deterministic MFT
selection and records bounded/skipped coverage in `coverage_summary.json`.
Use `--event-selection-profile first-n` to preserve the earlier bounded
selection behavior.

Read an audit ledger summary:

```bash
.venv/bin/python -m siftguard audit-read "$RUN_DIR/agent-run/audit.jsonl"
```

## Natural-Language/OpenClaw Workflow

SIFTGuard provides a bounded OpenClaw/MCP-style analyst workflow. OpenClaw is
the natural-language agent host; SIFTGuard remains the deterministic,
model-agnostic forensic core. The model may request typed tools, but SIFTGuard
computes the evidence-backed result and no model output is treated as forensic
evidence.

See [docs/openclaw-mcp-workflow.md](docs/openclaw-mcp-workflow.md). A reusable
operator prompt is available at
[examples/openclaw/case-triage.prompt.md](examples/openclaw/case-triage.prompt.md).

Preferred final OpenClaw/MCP path:

```bash
.venv/bin/python -m siftguard.integrations.mcp_server
```

Bounded tools:

```text
prepare_case -> run_case -> summarize_run -> validate_run_outputs
```

Smoke the preferred MCP/tool-adapter boundary without ROCBA evidence or provider
keys:

```bash
.venv/bin/python scripts/openclaw_siftguard_smoke.py --dry-run --output-dir runs/openclaw-smoke
```

The direct CLI remains the reproducible fallback:

```bash
.venv/bin/python -m siftguard case prepare ...
.venv/bin/python -m siftguard agent run-case ...
```

Case-specific claim boundaries belong in JSON casebook metadata. When
SIFTGuard emits claim-boundary events, OpenClaw should repeat the generated
`final_wording` and `scope_boundary` rather than inventing model wording.
For storyless Windows disk images, use
`docs/casebooks/generic-windows-disk-triage.json` for conservative
evidence-led triage without default incident conclusions.

## Controlled Validation Fixtures

The repository includes tiny synthetic fixtures that exercise the same
deterministic agent workflow without raw evidence. They are controlled
validation inputs, not real compromise claims.

Positive-control fixture:

```bash
rm -rf runs/case_positive-control
.venv/bin/python -m siftguard agent run-fixture \
  --case-id case_positive-control \
  --fixture tests/fixtures/positive_control/positive_chain.json \
  --output-dir runs/case_positive-control/agent-run \
  --max-iterations 7
```

Self-correction fixture:

```bash
rm -rf runs/case_self-correction-control
.venv/bin/python -m siftguard agent run-fixture \
  --case-id case_self-correction-control \
  --fixture tests/fixtures/positive_control/unsupported_claim.json \
  --output-dir runs/case_self-correction-control/agent-run \
  --max-iterations 7
```

The positive-control fixture contains a synthetic drop / execution /
persistence chain and should emit one `inferred` finding. The self-correction
fixture introduces an unsupported proposed claim and should record correction
events while downgrading the final status to `needs_review`.

## Output And Evidence Safety

- Evidence remains local-only and should be mounted or staged read-only.
- Raw evidence must stay outside the repository.
- Generated outputs belong under ignored paths such as `runs/`, `outputs/`,
  `analysis/`, or `reports/generated/`.
- Do not commit raw parser outputs, generated reports, audit ledgers, OpenClaw
  traces, private paths, hostnames, usernames, tokens, VM files, or disk images.
- Commit only intentionally sanitized documentation or examples.

## Submission Readiness Map

| Item | Repo-relative location |
| --- | --- |
| Final submission compliance checklist | `docs/submission-compliance-checklist.md` |
| Architecture and data flow | `docs/architecture.md` |
| Evidence dataset handling | `docs/dataset.md` |
| Accuracy report template | `docs/accuracy-report.md` |
| Execution-log traceability | `docs/execution-log-traceability.md` |
| Demo workflow | `docs/demo.md` |
| Limitations | `docs/limitations.md` |
| Security boundaries | `docs/security-boundaries.md` |
| Parser tooling matrix | `docs/parser-tooling-matrix.md` |
| Parser validation notes | `docs/parser-validation.md` |
| Agent workflow | `docs/agent-workflow.md` |
| OpenClaw/MCP analyst workflow | `docs/openclaw-mcp-workflow.md` |
| MCP/parser contracts | `docs/parser-contracts.md` |

## License

MIT (see `LICENSE`).
