# SIFTGuard MCP

SIFTGuard MCP is a constrained DFIR workflow foundation for SANS SIFT
Workstation. It provides deterministic evidence inventory, audited parser
wrapper execution, normalized parser observations, and typed MCP schema
boundaries for the FIND EVIL hackathon.

## What This Project Is

- A local-first Python workflow for SIFT Workstation.
- A constrained wrapper layer for verified SIFT parser tools.
- A reproducible foundation for audit trails, provenance checks, and
  evidence-backed reporting from normalized parser observations.
- An M2 parser workflow that currently supports:
  - `$MFT` parsing through MFTECmd.
  - Registry `Run` and `RunOnce` key parsing through RECmd.
  - `Amcache.hve` parsing through AmcacheParser.

Parser outputs are normalized into observational `ParserEvent` records. They
are not findings.

## What This Project Is Not

- Not an offensive tooling framework.
- Not a claim of court admissibility or evidentiary certainty.
- Not a full incident conclusion engine.
- Not proof of malware, compromise, persistence, or execution by itself.

## Submission Compliance Map

| Submission item | Repo-relative location | Status |
| --- | --- | --- |
| Code repository | `.` | In progress |
| LICENSE | `LICENSE` | Present |
| Setup instructions | `README.md#quick-start-local-development` | Present |
| Step-by-step local run instructions | `README.md#m2-parser-workflow`, `README.md#correlation-and-validation-workflow`, and `docs/dataset.md` | Present |
| Feature/functionality description | `README.md#what-this-project-is` and `docs/architecture.md` | Present |
| Demo video | `<Devpost video URL placeholder>` | Pending final submission |
| Architecture diagram | `docs/architecture.md` | Text architecture present; final diagram pending |
| Evidence dataset documentation | `docs/dataset.md` | Present |
| Accuracy report | `docs/parser-validation.md` | M2 parser validation present |
| Agent execution logs | `runs/` local only; summarized in `docs/parser-validation.md` | Local only / not committed |

## Quick Start Local Development

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
.venv/bin/python -m pytest
.venv/bin/python -m ruff check .
.venv/bin/python -m mypy src
```

## M2 Parser Workflow

The M2 workflow expects evidence to be staged locally outside the repository.
Commands below use placeholders; replace `<LOCAL_EVIDENCE_ROOT>` with a local
path in the SIFT VM.

```bash
export CASE_ID="CASE-DEMO"
export EVIDENCE_ROOT="<LOCAL_EVIDENCE_ROOT>"
export RUNS_ROOT="runs"
export LEDGER_PATH="$RUNS_ROOT/$CASE_ID/audit.jsonl"
```

Inventory local evidence:

```bash
.venv/bin/python -m siftguard inventory "$EVIDENCE_ROOT" \
  --manifest-out "$RUNS_ROOT/$CASE_ID/manifest.json"
```

Run MFTECmd against a staged `$MFT`:

```bash
.venv/bin/python -m siftguard parse-mft \
  --case-id "$CASE_ID" \
  --artifact-id "EV-MFT-0001" \
  --mft-path "$EVIDENCE_ROOT/mft/\$MFT" \
  --runs-root "$RUNS_ROOT" \
  --evidence-root "$EVIDENCE_ROOT" \
  --ledger-path "$LEDGER_PATH" \
  --json-out "$RUNS_ROOT/$CASE_ID/normalized/EV-MFT-0001-mftecmd.json"
```

Run RECmd against user and machine Run Key hives:

```bash
.venv/bin/python -m siftguard parse-registry-runkeys \
  --case-id "$CASE_ID" \
  --artifact-id "EV-REG-USER-0001" \
  --hive-path "$EVIDENCE_ROOT/registry/NTUSER.DAT" \
  --artifact-type registry_hive \
  --runs-root "$RUNS_ROOT" \
  --evidence-root "$EVIDENCE_ROOT" \
  --ledger-path "$LEDGER_PATH" \
  --json-out "$RUNS_ROOT/$CASE_ID/normalized/EV-REG-USER-0001-recmd.json"

.venv/bin/python -m siftguard parse-registry-runkeys \
  --case-id "$CASE_ID" \
  --artifact-id "EV-REG-SOFTWARE-0001" \
  --hive-path "$EVIDENCE_ROOT/registry/SOFTWARE" \
  --artifact-type registry_hive \
  --runs-root "$RUNS_ROOT" \
  --evidence-root "$EVIDENCE_ROOT" \
  --ledger-path "$LEDGER_PATH" \
  --json-out "$RUNS_ROOT/$CASE_ID/normalized/EV-REG-SOFTWARE-0001-recmd.json"
```

Run AmcacheParser against a staged `Amcache.hve`:

```bash
.venv/bin/python -m siftguard parse-amcache \
  --case-id "$CASE_ID" \
  --artifact-id "EV-AMCACHE-0001" \
  --amcache-path "$EVIDENCE_ROOT/amcache/Amcache.hve" \
  --runs-root "$RUNS_ROOT" \
  --evidence-root "$EVIDENCE_ROOT" \
  --ledger-path "$LEDGER_PATH" \
  --json-out "$RUNS_ROOT/$CASE_ID/normalized/EV-AMCACHE-0001-amcacheparser.json"
```

Parser wrappers call SIFT tools through constrained argv-based execution.
Outputs, stdout/stderr logs, `ParserResult` JSON, and audit ledgers are written
under `runs/`. Normalized `ParserEvent` records can feed the correlation and
validation workflow.

## Correlation And Validation Workflow

The workflow consumes normalized parser-event JSON and writes generated
timelines, validated findings, a Markdown report, and an audit ledger under an
ignored output directory.

```bash
siftguard correlate \
  --case-id CASE-SYN-001 \
  --input normalized-events.json \
  --output-dir runs/CASE-SYN-001
```

Generated files include `subject_timelines.json`, `findings.json`,
`report.md`, and `audit.jsonl`. Do not commit generated outputs. The workflow
expects normalized parser JSON, not raw evidence images.

## Evidence Safety Summary

- Evidence is local-only.
- Raw evidence is not committed.
- Generated parser outputs are not committed.
- `runs/` is gitignored.
- `.local/` is gitignored.
- Mounted evidence should be handled read-only.
- Only sanitized documentation is committed.

## Documentation Map

- `docs/architecture.md` - system architecture and data flow.
- `docs/dataset.md` - local evidence staging and dataset handling.
- `docs/development-notes.md` - developer workflow for parser wrappers.
- `docs/limitations.md` - interpretation and reproducibility limits.
- `docs/openclaw-agent-workflow.md` - constrained OpenClaw agent workflow path.
- `docs/parser-contracts.md` - parser event/result contracts.
- `docs/parser-validation.md` - SIFT validation results.

## License

MIT (see `LICENSE`).
