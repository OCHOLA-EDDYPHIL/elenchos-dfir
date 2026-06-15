# Elenchos

Elenchos is a bounded autonomous DFIR triage agent for SIFT and Protocol SIFT.
I use model-driven orchestration to choose safe next steps, deterministic
forensic tooling to process evidence, and policy gates to prevent unsupported
or unsafe actions.

Elenchos takes its name from the ancient Greek term associated with refutation
and cross-examination. I use that idea operationally: every forensic claim must
survive evidence checks, unsupported conclusions are downgraded, and analyst
review remains explicit.

## Core Idea

Elenchos keeps the model and the evidence-processing layer separate:

- The model coordinates bounded workflow actions.
- The Elenchos deterministic core prepares cases, runs supported parsers,
  validates findings, and writes reports.
- Policy decisions reject unsafe or unsupported actions.
- Raw evidence remains read-only.
- Model rationale is operational explanation, not forensic evidence.

Current scope is Windows disk-artifact triage for `$MFT`, Registry artifacts,
Amcache, and prepared NTUSER user-activity artifacts supported by the codebase.
Memory, packet, browser/cloud, remote endpoint, mobile, legal certification,
and full enterprise IR remain out of scope unless explicitly implemented.

## Install

Use Python 3.10 or newer in a Linux/SIFT-compatible shell.

```bash
git clone <repository-url>
cd <repository-directory>

python -m venv .venv
source .venv/bin/activate
.venv/bin/python -m pip install -e ".[dev]"

.venv/bin/python -m pytest
.venv/bin/python -m ruff check .
.venv/bin/python -m mypy src
```

The package installs an `elenchos` console script. Examples use
`.venv/bin/python -m elenchos` so they do not depend on shell `PATH`.

## Evidence and Outputs

Stage evidence outside the repository and mount or copy it read-only.

```text
/cases/demo/evidence/
  mft/$MFT
  registry/NTUSER.DAT
  registry/SOFTWARE
  amcache/Amcache.hve
```

Generated outputs belong under ignored paths such as `runs/`, `.local/`,
`outputs/`, `analysis/`, or `reports/generated/`. Do not commit raw evidence,
generated parser output, local OpenClaw state, transcripts, screenshots,
credentials, private paths, or private run logs.

See [docs/dataset.md](docs/dataset.md) for supported datasets and
[docs/security-boundaries.md](docs/security-boundaries.md) for evidence safety.

## Deterministic CLI

Set local variables:

```bash
export CASE_ID="case_evidence"
export RUN_DIR="runs/demo"
mkdir -p "$RUN_DIR"
```

Prepare an E01-backed or source-root case:

```bash
.venv/bin/python -m elenchos case prepare \
  --case-id "$CASE_ID" \
  --source-root "<SOURCE_ROOT>" \
  --source-manifest-out ".local/cases/$CASE_ID/source-manifest.json" \
  --output-dir "$RUN_DIR/case-prep"
```

Run deterministic manifest-driven triage:

```bash
.venv/bin/python -m elenchos agent run-case \
  --artifact-manifest "$RUN_DIR/case-prep/case_prep.json" \
  --casebook "docs/casebooks/generic-windows-disk-triage.json" \
  --output-dir "$RUN_DIR/agent-run" \
  --max-iterations 10 \
  --max-normalized-events 5000 \
  --event-selection-profile forensic-triage
```

Direct parser and correlation commands remain available; see
[docs/parser-contracts.md](docs/parser-contracts.md),
[docs/parser-tooling-matrix.md](docs/parser-tooling-matrix.md), and
[docs/agent-workflow.md](docs/agent-workflow.md).

## OpenClaw Runtime

OpenClaw is the natural-language runtime. Elenchos remains the deterministic,
model-agnostic forensic core. OpenClaw controls provider and model selection;
model output is not forensic evidence.

Preferred OpenClaw/MCP path:

```bash
.venv/bin/python -m elenchos.integrations.mcp_server
```

Blocking fallback tools:

```text
prepare_case -> run_case -> summarize_run -> validate_run_outputs
```

Live autonomy adds:

```text
inspect_run_state -> [model-rationale] -> record_model_rationale
  -> evaluate_action_policy -> [policy] -> execute allowed bounded action
  -> poll progress -> validate outputs -> emit_claim_boundary -> stop
```

Smoke the bounded adapter without private evidence or provider credentials:

```bash
.venv/bin/python scripts/demo_elenchos_preflight.py
.venv/bin/python scripts/openclaw_elenchos_smoke.py --dry-run --output-dir runs/openclaw-smoke
```

The direct CLI remains the reproducible fallback:

```bash
.venv/bin/python -m elenchos case prepare ...
.venv/bin/python -m elenchos agent run-case ...
```

Use [examples/openclaw/case-triage.prompt.md](examples/openclaw/case-triage.prompt.md)
as a reusable operator prompt. Use
[docs/casebooks/generic-windows-disk-triage.json](docs/casebooks/generic-windows-disk-triage.json)
for storyless Windows disk triage. See
[docs/openclaw-mcp-workflow.md](docs/openclaw-mcp-workflow.md) and
[docs/tui.md](docs/tui.md) for the full runtime workflow.

## Outputs and Traceability

Typical generated outputs include `report.md`, `findings.json`, `audit.jsonl`,
`decision_trace.json`, `gap_analysis.json`, `validation_summary.json`,
`model_rationale.jsonl`, `policy_decisions.jsonl`, `progress.jsonl`, and
`run_integrity_manifest.json`.

Trace a report statement through:

```text
report.md sentence
-> finding id
-> findings.json
-> evidence refs
-> normalized events
-> parser result
-> audit.jsonl
-> manifest artifact and hash
```

See [docs/execution-log-traceability.md](docs/execution-log-traceability.md)
for trace maps and sanitized examples.

## Claim Boundaries

Elenchos labels findings as `confirmed`, `inferred`, `needs_review`,
`not_assessed`, or `rejected`. It does not claim theft, exfiltration, malware,
memory findings, attribution, compromise, or a final incident conclusion unless
generated Elenchos outputs support the claim and validation passes.

See [docs/limitations.md](docs/limitations.md) and
[docs/model-rationale-boundary.md](docs/model-rationale-boundary.md).

## Documentation Map

| Need | Start here |
| --- | --- |
| Architecture and data flow | [docs/architecture.md](docs/architecture.md) |
| Agent workflow | [docs/agent-workflow.md](docs/agent-workflow.md) |
| OpenClaw/MCP workflow | [docs/openclaw-mcp-workflow.md](docs/openclaw-mcp-workflow.md) |
| Elenchos TUI | [docs/tui.md](docs/tui.md) |
| Dataset handling | [docs/dataset.md](docs/dataset.md) |
| Parser validation | [docs/parser-validation.md](docs/parser-validation.md) |
| Traceability | [docs/execution-log-traceability.md](docs/execution-log-traceability.md) |
| Security boundaries | [docs/security-boundaries.md](docs/security-boundaries.md) |

## License

MIT. See [LICENSE](LICENSE).
