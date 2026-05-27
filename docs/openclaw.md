# OpenClaw Setup

## Role In SIFTGuard

OpenClaw is a runtime orchestrator for M4. It can initiate or supervise the
constrained SIFTGuard agent workflow, but it is not the forensic engine.
Forensic parsing, validation, verification, correction, reporting, and audit
logic stay in deterministic SIFTGuard Python code.

The detailed constrained workflow is documented in
[OpenClaw Agent Workflow](openclaw-agent-workflow.md). The runtime viability
proof is documented in [OpenClaw Runtime Viability](openclaw-viability.md).

## Environment

The proven environment is a SIFT Workstation/dev VM class host with:

- User-level/local-prefix OpenClaw install.
- Local-prefix Node runtime available to the shell that starts OpenClaw.
- Local OpenClaw provider auth already configured.
- Project Python virtual environment ready at `.venv/`.
- Existing constrained CLI entrypoint:
  `.venv/bin/python -m siftguard agent run`.

If a shell does not already include the OpenClaw local-prefix paths, use the
PATH setup recorded in [OpenClaw Agent Workflow](openclaw-agent-workflow.md).

## Auth And Provider Assumptions

OpenClaw auth must be configured locally before running the OpenClaw smoke
workflow. The successful M4 proof used OpenClaw's own OpenAI/Codex
browser/device-code auth flow.

Do not overwrite, import, inspect, print, or modify existing Azure/Codex CLI
configuration while preparing SIFTGuard demos. Do not copy browser/device-code
values, account emails, tokens, provider credentials, OpenClaw auth state, or
Codex auth state into the repository or documentation.

## Smoke Workflow

Run the fixed synthetic smoke helper from the repository root:

```bash
./scripts/openclaw-agent-smoke.sh
```

The helper creates synthetic/local-only parser CSV inputs under `runs/`, writes
a synthetic manifest, invokes `siftguard agent run`, and verifies these outputs:

- `agent_run.json`
- `audit.jsonl`
- `findings.json`
- `report.md`

OpenClaw can initiate this helper from a narrow natural-language task. Use the
prompt and command sequence in
[OpenClaw Agent Workflow](openclaw-agent-workflow.md).

## Output Handling

Generated outputs stay under ignored paths such as `runs/`. Raw OpenClaw
responses and local execution traces should be saved only under ignored run
output directories and must not be committed.

Do not commit generated parser outputs, agent run outputs, OpenClaw state,
auth state, gateway logs, shell history, transcripts, or local case artifacts.

## Troubleshooting

Use safe version and command-visibility checks:

```bash
openclaw --version
node -v
.venv/bin/python -m siftguard agent run --help
./scripts/openclaw-agent-smoke.sh
```

If OpenClaw cannot run the smoke helper, confirm the local-prefix Node and
OpenClaw CLI are on `PATH`, the local OpenClaw agent is configured, and the
project virtual environment exists. Do not rerun browser/device-code auth
unless intentionally re-authorizing OpenClaw.
