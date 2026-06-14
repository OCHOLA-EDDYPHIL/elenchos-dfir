# OpenClaw MCP Workflow

## Purpose

Elenchos' analyst-facing architecture is a natural-language OpenClaw/MCP
workflow over a deterministic forensic core. OpenClaw is the agent host where
the analyst asks for work in natural language. Elenchos exposes bounded tools
that OpenClaw can call, while Elenchos Python code performs case preparation,
parser execution, validation, self-correction, reporting, and audit logging.

The preferred integration path is the bounded MCP/tool adapter. Elenchos
remains model-agnostic. It does not require Claude Code, does not select an
OpenClaw provider or model, and does not treat model output as forensic
evidence.

### Agent orchestration guidance

This repository includes [`AGENTS.md`](../AGENTS.md) for OpenClaw, Claude Code,
and other agentic CLI hosts. It instructs agents to use Elenchos as a bounded
forensic orchestration layer, preserve read-only evidence handling, summarize
progress telemetry, validate outputs, and avoid unsupported claims.

## Component Roles

- OpenClaw: analyst-facing agent host and natural-language front end.
- Elenchos adapter: bounded MCP/OpenClaw tool surface with typed JSON inputs.
- Elenchos core: deterministic forensic execution, evidence validation,
  decision trace, generated report, and audit trail.
- SIFT parser layer: deterministic local parser wrappers for the supported
  artifact scope.

The intended flow is:

```text
Analyst natural-language prompt
  -> OpenClaw / agent host
  -> bounded Elenchos MCP/tool adapter
  -> Elenchos deterministic CLI/core
  -> report + findings + audit + decision trace
  -> OpenClaw-visible summary and trace paths
```

## Architecture Mapping

| Architecture role | Current repo implementation |
| --- | --- |
| Bounded MCP/tool server | `src/elenchos/integrations/` stdio server and JSON tool adapter |
| Deterministic forensic orchestrator | `src/elenchos/agent/` workflow modules |
| Evidence ledger and findings store | `findings.json`, `normalized_events.json`, and evidence refs |
| Execution logs | `audit.jsonl`, `decision_trace.json`, and adapter/OpenClaw traces |
| Reports | Generated `report.md` and validation summaries |

## Tool Boundary

The adapter exposes four operations only:

- `prepare_case`: validates paths, rejects unsafe output locations, and runs
  `.venv/bin/python -m elenchos case prepare ...` through argv subprocesses.
- `run_case`: validates a prepared `case_prep.json`, rejects unsafe output
  locations, and runs `.venv/bin/python -m elenchos agent run-case ...`.
- `summarize_run`: reads generated JSON/report outputs only and returns concise
  finding counts, case-question statuses, parser coverage, event-family counts,
  unsupported areas, limitations, and traceability paths.
- `validate_run_outputs`: checks required generated outputs, forbidden overclaim
  wording, and unsupported theft/exfiltration/memory question safety.

Run the stdio MCP server:

```bash
.venv/bin/python -m elenchos.integrations.mcp_server
```

The same bounded surface is available as a JSON CLI dispatcher:

```bash
.venv/bin/python -m elenchos.integrations.tool_adapter manifest
.venv/bin/python -m elenchos.integrations.tool_adapter summarize-run --json-input '{"output_dir":"runs/<CASE_ID>/agent-run"}'
```

## Safety Model

- No arbitrary shell command execution is exposed.
- Subprocess calls use argv lists and `sys.executable`; `shell=True` is not used.
- Output directories under `/mnt/evidence`, source roots, or parsed evidence
  roots are rejected.
- Evidence remains read-only; generated outputs stay under ignored directories
  such as `runs/`.
- `summarize_run` and `validate_run_outputs` read generated Elenchos outputs
  only, not raw evidence.
- `run_case` writes `run_integrity_manifest.json` with SHA-256 hashes for
  generated run outputs. `validate_run_outputs` verifies that manifest and
  reports tamper-evident mismatches. This supports integrity checking; it is not
  a cryptographic guarantee that a forensic conclusion is true.
- Raw evidence contents, parser CSVs, hives, memory images, private paths,
  tokens, and OpenClaw provider credentials must not be committed.
- The model may request bounded tools, but Elenchos computes the
  evidence-backed result. Model output is not forensic evidence.
- Do not paste or transmit raw evidence contents to OpenClaw or any LLM.
- Do not ask OpenClaw or any LLM to decide compromise from raw parser data.

## Local Setup

Check the locally installed OpenClaw interface:

```bash
which openclaw || true
which claw || true
openclaw --version || true
openclaw mcp --help || true
openclaw agent --help || true
```

On the validated workstation, `openclaw` is installed and exposes
`openclaw mcp set`, `openclaw mcp list --json`, and
`openclaw agent --message ... --json`. `claw` is not installed locally.
OpenClaw provider/model configuration is local to the operator's OpenClaw
installation and must not be committed.

Register the Elenchos server with OpenClaw locally:

```bash
REPO_ROOT="$(pwd)"
openclaw mcp set elenchos "{
  \"command\": \"$REPO_ROOT/.venv/bin/python\",
  \"args\": [\"-m\", \"elenchos.integrations.mcp_server\"],
  \"cwd\": \"$REPO_ROOT\"
}"
```

This writes OpenClaw-owned local configuration. Do not commit OpenClaw config,
provider credentials, transcripts, gateway logs, or auth state.

The project does not require a committed OpenClaw config file. If a shell needs
OpenClaw-specific `PATH` setup, keep that in local shell configuration rather
than repository files.

Before recording a demo, run the preflight from the current checkout:

```bash
.venv/bin/python scripts/demo_elenchos_preflight.py
```

The preflight confirms that OpenClaw points at the current repository, that the
MCP server exposes exactly the four Elenchos tools, and that the local SIFT /
Zimmerman commands needed by the deterministic workflow are available. If it
reports a stale path, re-run the `openclaw mcp set elenchos ...` command above.
`AGENTS.md` is orchestration guidance for compatible agent hosts; the enforced
boundary is the typed MCP adapter plus Elenchos' path validation, deterministic
CLI calls, generated-output validation, and claim-boundary files.

Run the deterministic smoke harness without OpenClaw credentials or ROCBA
evidence:

```bash
.venv/bin/python scripts/openclaw_elenchos_smoke.py --dry-run --output-dir runs/openclaw-smoke
```

The automated smoke test exercises the same bounded tool boundary without
requiring a live model/provider key.

The deterministic CLI remains the reproducible fallback for every adapter
operation:

```bash
.venv/bin/python -m elenchos case prepare ...
.venv/bin/python -m elenchos agent run-case ...
```

## Casebook Selection

Use `docs/casebooks/rocba-standard.json` for the ROCBA final validation/demo.
Use `docs/casebooks/generic-windows-disk-triage.json` when the operator only
has a Windows forensic image and no case-specific story. The generic casebook
is marked `reusable_template: true`, so it can be used with arbitrary prepared
case IDs while generated outputs preserve the actual prepared case ID and
record the template identity separately.

With the generic casebook, Elenchos performs conservative evidence-led triage
and does not infer theft, exfiltration, APT attribution, or confirmed
compromise. Case-specific conclusions require a case-specific JSON casebook
plus supporting evidence in generated Elenchos outputs.

## Case Triage Workflow

Example analyst request:

```text
Prepare and triage the case, then summarize supported findings,
unsupported gaps, and trace paths. Do not inspect raw evidence directly.
Use only the Elenchos tools.
```

Canonical tool sequence:

1. `prepare_case`
2. `run_case`
3. `summarize_run`
4. `validate_run_outputs`

Expected generated outputs include:

- `runs/<CASE_ID>/case-prep/case_prep.json`
- `runs/<CASE_ID>/agent-run/report.md`
- `runs/<CASE_ID>/agent-run/findings.json`
- `runs/<CASE_ID>/agent-run/audit.jsonl`
- `runs/<CASE_ID>/agent-run/decision_trace.json`
- `runs/<CASE_ID>/agent-run/gap_analysis.json`
- `runs/<CASE_ID>/agent-run/self_correction_events.json`
- `runs/<CASE_ID>/agent-run/performance_summary.json`
- `runs/<CASE_ID>/agent-run/openclaw-trace/*.stdout|*.stderr`

Casebooks may define claim-boundary metadata. When generated case-question
statuses satisfy a configured boundary, Elenchos records that posture revision
in `self_correction_events.json`, `gap_analysis.json`, and summary/validation
tool output. OpenClaw should repeat the generated `final_wording` and
`scope_boundary` exactly and should not replace them with model wording.

Use [`examples/openclaw/case-triage.prompt.md`](../examples/openclaw/case-triage.prompt.md)
as a reusable operator prompt.

## Model Statement

OpenClaw controls provider and model selection through local operator
configuration. Elenchos itself does not call a model during forensic
validation, does not require a Claude Code subscription, and does not store or
ship model API keys. Natural-language orchestration can request Elenchos
tools, but Elenchos deterministic code performs the evidence-backed work.

## Limitations

- The adapter does not expand Elenchos artifact scope.
- The adapter does not make unsupported compromise, theft, exfiltration, or
  memory claims.
- The workflow remains bounded to supported generated outputs and direct CLI
  fallback.
- OpenClaw gateway/provider availability may vary by local installation.
- The smoke harness proves the tool boundary without requiring ROCBA evidence or
  a live model provider.
