# OpenClaw MCP Workflow

## Purpose

SIFTGuard's analyst-facing architecture is a natural-language OpenClaw/MCP
workflow over a deterministic forensic core. OpenClaw is the agent host where
the analyst asks for work in natural language. SIFTGuard exposes bounded tools
that OpenClaw can call, while SIFTGuard Python code performs case preparation,
parser execution, validation, self-correction, reporting, and audit logging.

The preferred integration path is the bounded MCP/tool adapter. SIFTGuard
remains model-agnostic. It does not require Claude Code, does not select an
OpenClaw provider or model, and does not treat model output as forensic
evidence.

## Component Roles

- OpenClaw: analyst-facing agent host and natural-language front end.
- SIFTGuard adapter: bounded MCP/OpenClaw tool surface with typed JSON inputs.
- SIFTGuard core: deterministic forensic execution, evidence validation,
  decision trace, generated report, and audit trail.
- SIFT parser layer: deterministic local parser wrappers for the supported
  artifact scope.

The intended flow is:

```text
Analyst natural-language prompt
  -> OpenClaw / agent host
  -> bounded SIFTGuard MCP/tool adapter
  -> SIFTGuard deterministic CLI/core
  -> report + findings + audit + decision trace
  -> OpenClaw-visible summary and trace paths
```

## Architecture Mapping

| Architecture role | Current repo implementation |
| --- | --- |
| Bounded MCP/tool server | `src/siftguard/integrations/` stdio server and JSON tool adapter |
| Deterministic forensic orchestrator | `src/siftguard/agent/` workflow modules |
| Evidence ledger and findings store | `findings.json`, `normalized_events.json`, and evidence refs |
| Execution logs | `audit.jsonl`, `decision_trace.json`, and adapter/OpenClaw traces |
| Reports | `report.md` and `docs/accuracy-report.md` |

## Tool Boundary

The adapter exposes four operations only:

- `prepare_case`: validates paths, rejects unsafe output locations, and runs
  `.venv/bin/python -m siftguard case prepare ...` through argv subprocesses.
- `run_case`: validates a prepared `case_prep.json`, rejects unsafe output
  locations, and runs `.venv/bin/python -m siftguard agent run-case ...`.
- `summarize_run`: reads generated JSON/report outputs only and returns concise
  finding counts, case-question statuses, parser coverage, event-family counts,
  unsupported areas, limitations, and traceability paths.
- `validate_run_outputs`: checks required generated outputs, forbidden overclaim
  wording, and unsupported theft/exfiltration/memory question safety.

Run the stdio MCP server:

```bash
.venv/bin/python -m siftguard.integrations.mcp_server
```

The same bounded surface is available as a JSON CLI dispatcher:

```bash
.venv/bin/python -m siftguard.integrations.tool_adapter manifest
.venv/bin/python -m siftguard.integrations.tool_adapter summarize-run --json-input '{"output_dir":"runs/<CASE_ID>/agent-run"}'
```

## Safety Model

- No arbitrary shell command execution is exposed.
- Subprocess calls use argv lists and `sys.executable`; `shell=True` is not used.
- Output directories under `/mnt/evidence`, source roots, or parsed evidence
  roots are rejected.
- Evidence remains read-only; generated outputs stay under ignored directories
  such as `runs/`.
- `summarize_run` and `validate_run_outputs` read generated SIFTGuard outputs
  only, not raw evidence.
- Raw evidence contents, parser CSVs, hives, memory images, private paths,
  tokens, and OpenClaw provider credentials must not be committed.
- The model may request bounded tools, but SIFTGuard computes the
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

Register the SIFTGuard MCP server with OpenClaw locally:

```bash
openclaw mcp set siftguard '{
  "command": "/absolute/path/to/siftguard-mcp/.venv/bin/python",
  "args": ["-m", "siftguard.integrations.mcp_server"],
  "cwd": "/absolute/path/to/siftguard-mcp"
}'
```

This writes OpenClaw-owned local configuration. Do not commit OpenClaw config,
provider credentials, transcripts, gateway logs, or auth state.

The project does not require a committed OpenClaw config file. If a shell needs
OpenClaw-specific `PATH` setup, keep that in local shell configuration rather
than repository files.

Run the deterministic smoke harness without OpenClaw credentials or ROCBA
evidence:

```bash
.venv/bin/python scripts/openclaw_siftguard_smoke.py --dry-run --output-dir runs/openclaw-smoke
```

The automated smoke test exercises the same bounded tool boundary without
requiring a live model/provider key.

The deterministic CLI remains the reproducible fallback for every adapter
operation:

```bash
.venv/bin/python -m siftguard case prepare ...
.venv/bin/python -m siftguard agent run-case ...
```

## ROCBA Demo Workflow

Example analyst request:

```text
Prepare and triage the ROCBA case, then summarize supported findings,
unsupported gaps, and trace paths. Do not inspect raw evidence directly.
Use only the SIFTGuard tools.
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

Unsupported theft contents, transfer destination, exfiltration method, and
memory questions remain `not_assessed` unless future supported parsers produce
direct evidence.

For the final ROCBA demo, use the copy-paste prompt in
[`docs/demo/openclaw-rocba-gap-demo-prompt.md`](demo/openclaw-rocba-gap-demo-prompt.md)
and the runbook in
[`docs/demo/openclaw-gap-self-correction-runbook.md`](demo/openclaw-gap-self-correction-runbook.md).
The real-gap self-correction story is not an induced parser failure. It is the
posture revision recorded when generated case-question and gap outputs show
that the submitted artifact scope does not support a theft/exfiltration
conclusion.

OpenClaw should use this final wording when presenting that revision:

```text
SIFTGuard did not find sufficient support for a theft or exfiltration conclusion within the submitted artifact scope.
```

OpenClaw should also preserve this claim boundary:

```text
The current artifact scope does not support a theft/exfiltration conclusion; additional artifacts such as browser history, cloud sync logs, network telemetry, removable-device artifacts, or memory analysis would be required.
```

## Model Statement

OpenClaw controls provider and model selection through local operator
configuration. SIFTGuard itself does not call a model during forensic
validation, does not require a Claude Code subscription, and does not store or
ship model API keys. Natural-language orchestration can request SIFTGuard
tools, but SIFTGuard deterministic code performs the evidence-backed work.

## Limitations

- The adapter does not expand SIFTGuard artifact scope.
- The adapter does not make unsupported compromise, theft, exfiltration, or
  memory claims.
- The workflow remains bounded to supported generated outputs and direct CLI
  fallback.
- OpenClaw gateway/provider availability may vary by local installation.
- The smoke harness proves the tool boundary without requiring ROCBA evidence or
  a live model provider.
