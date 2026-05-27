# OpenClaw Agent Workflow

## Purpose

This document describes the Milestone 4 OpenClaw path for initiating the
constrained SIFTGuard agent workflow. OpenClaw is used as a runtime
orchestrator over documented SIFTGuard commands. SIFTGuard remains the
forensic engine.

The intended flow is:

```text
OpenClaw natural-language task
  -> fixed SIFTGuard smoke command
  -> siftguard agent run
  -> AgentRun JSON
  -> audit JSONL
  -> findings JSON
  -> Markdown report
```

## Preconditions

- Use the SIFT Workstation/dev VM environment validated in
  `docs/openclaw-viability.md`.
- OpenClaw is installed with the user-level local-prefix runtime.
- The local-prefix Node runtime is on `PATH` for the shell that starts
  OpenClaw.
- OpenClaw auth is already configured.
- The Python virtual environment exists and project gates can run from
  `.venv/bin/python`.
- `.venv/bin/python -m siftguard agent run --help` exits successfully.
- No real evidence is required for this synthetic proof.

If the shell does not already include the OpenClaw local-prefix paths, use:

```bash
export PATH="$HOME/.openclaw/tools/node-v22.22.0/bin:$HOME/.openclaw/bin:$PATH"
```

## Safety Boundary

- Do not paste raw evidence into OpenClaw prompts.
- Do not ask OpenClaw to inspect evidence directly.
- Do not expose arbitrary forensic shell execution as the submission path.
- Do not ask OpenClaw to read secrets, credential stores, shell history,
  browser profiles, or OpenClaw/Codex auth state.
- Do not commit OpenClaw transcripts, credentials, runtime state, generated run
  outputs, parser outputs, VM files, private paths, hostnames, usernames, or
  local case artifacts.
- Evidence remains read-only.
- Agent workflow outputs stay under ignored generated paths such as `runs/`.
- OpenClaw should invoke constrained SIFTGuard entrypoints only.

## Synthetic Smoke Command

The repository includes a fixed smoke helper:

```bash
./scripts/openclaw-agent-smoke.sh
```

The helper creates synthetic/local parser CSV inputs under `runs/`, writes a
synthetic manifest, and runs:

```bash
.venv/bin/python -m siftguard agent run \
  --case-id CASE-M4-OPENCLAW-SMOKE \
  --manifest runs/CASE-M4-OPENCLAW-SMOKE/manifest.json \
  --output-dir runs/CASE-M4-OPENCLAW-SMOKE/agent-run \
  --max-iterations 7
```

The helper does not require real evidence, parser tools, OpenClaw credentials,
network access, or external services. It does not accept a free-form command.

Optional environment overrides are available for local testing:

```bash
CASE_ID=CASE-M4-OPENCLAW-SMOKE \
RUN_ROOT=runs/CASE-M4-OPENCLAW-SMOKE \
MAX_ITERATIONS=7 \
./scripts/openclaw-agent-smoke.sh
```

`RUN_ROOT` must be under an ignored generated output path such as `runs/`,
`outputs/`, `analysis/`, or `reports/generated/`.

## Recommended OpenClaw Prompt

Use a narrow prompt that allows only the documented smoke command:

```text
You may only run this documented SIFTGuard command sequence:
cd siftguard-mcp && ./scripts/openclaw-agent-smoke.sh

Do not inspect evidence.
Do not read secrets.
Do not run unrelated shell commands.
Do not modify tracked repository files.
Use only the synthetic/local SIFTGuard smoke path.
Report only whether the command exits successfully and whether
agent_run.json, audit.jsonl, findings.json, and report.md exist.
```

A headless OpenClaw task can be started with:

```bash
mkdir -p runs/CASE-M4-OPENCLAW-SMOKE/openclaw-trace

openclaw agent --agent main --json --timeout 900 --message "
You may only run this documented SIFTGuard command sequence:
cd siftguard-mcp && ./scripts/openclaw-agent-smoke.sh

Do not inspect evidence.
Do not read secrets.
Do not run unrelated shell commands.
Do not modify tracked repository files.
Use only the synthetic/local SIFTGuard smoke path.
Report only whether the command exits successfully and whether
agent_run.json, audit.jsonl, findings.json, and report.md exist.
" > runs/CASE-M4-OPENCLAW-SMOKE/openclaw-trace/openclaw-agent-turn.json
```

The `main` agent id was the configured local agent used for the Milestone 4
proof. If a different local agent id is configured, list available agents with
`openclaw agents list --json` and substitute that id. The `cd siftguard-mcp`
prefix is used when the OpenClaw agent workspace is the parent project
directory. If OpenClaw is already scoped to this repository, run only
`./scripts/openclaw-agent-smoke.sh`.

The raw OpenClaw trace must stay under the ignored run output directory and
must not be committed.

## Local Proof Result

The Milestone 4 runtime proof used a natural-language OpenClaw task with the
constrained command sequence above. OpenClaw reported that the command exited
successfully and that `agent_run.json`, `audit.jsonl`, `findings.json`, and
`report.md` existed after the run. The raw OpenClaw response was saved under
`runs/CASE-M4-OPENCLAW-SMOKE/openclaw-trace/` and was not committed.

## Expected Outputs

The OpenClaw-initiated smoke run should create:

```text
runs/CASE-M4-OPENCLAW-SMOKE/agent-run/agent_run.json
runs/CASE-M4-OPENCLAW-SMOKE/agent-run/audit.jsonl
runs/CASE-M4-OPENCLAW-SMOKE/agent-run/findings.json
runs/CASE-M4-OPENCLAW-SMOKE/agent-run/report.md
```

The runner may also write deterministic intermediate outputs such as
`normalized_events.json` and `subject_timelines.json` under the same output
directory.

## Verification Checklist

After the smoke run:

```bash
test -f runs/CASE-M4-OPENCLAW-SMOKE/agent-run/agent_run.json
test -f runs/CASE-M4-OPENCLAW-SMOKE/agent-run/audit.jsonl
test -f runs/CASE-M4-OPENCLAW-SMOKE/agent-run/findings.json
test -f runs/CASE-M4-OPENCLAW-SMOKE/agent-run/report.md
grep -q agent_run_started runs/CASE-M4-OPENCLAW-SMOKE/agent-run/audit.jsonl
grep -q agent_run_completed runs/CASE-M4-OPENCLAW-SMOKE/agent-run/audit.jsonl
grep -q verification_failed runs/CASE-M4-OPENCLAW-SMOKE/agent-run/audit.jsonl || true
grep -q correction_applied runs/CASE-M4-OPENCLAW-SMOKE/agent-run/audit.jsonl || true
```

The `verification_failed` and `correction_applied` checks are optional for this
successful synthetic smoke path. The induced-failure fixture in the unit tests
demonstrates those audit events without requiring real evidence.

## Trace Handling

- Store raw OpenClaw traces only under ignored run output paths such as
  `runs/CASE-M4-OPENCLAW-SMOKE/openclaw-trace/`.
- Commit only sanitized documentation.
- Do not commit account identifiers, tokens, device codes, provider logs,
  gateway logs, shell history, private paths, or local case data.

## Demo Note

This synthetic OpenClaw path proves runtime orchestration of the constrained
SIFTGuard agent workflow. A real evidence demo should be prepared separately
with local-only evidence, read-only handling, and no committed generated
outputs or transcripts.
