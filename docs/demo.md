# Demo Guide

## Demo Goals

The agent workflow demo should show:

- A constrained agent run.
- OpenClaw/MCP invoking the bounded SIFTGuard tool-adapter workflow.
- Real-gap self-correction: OpenClaw discovers from SIFTGuard outputs that the
  submitted ROCBA artifact scope does not support a theft/exfiltration
  conclusion.
- Audit and trace visibility for supported findings, gaps, and generated
  sidecars.

## From A Clean Repo

Start from a clean worktree:

```bash
git status --short
```

Run the preferred OpenClaw/MCP adapter dry-run harness. This exercises the
bounded tool interface and writes generated outputs under ignored `runs/`
paths without provider keys or ROCBA evidence:

```bash
.venv/bin/python scripts/openclaw_siftguard_smoke.py --dry-run --output-dir runs/openclaw-smoke
```

The synthetic induced-failure test remains an internal verifier regression
check. Do not use it as the final OpenClaw demo self-correction story:

```bash
.venv/bin/python -m pytest tests/unit/agent/test_induced_failure_demo.py
```

## Expected OpenClaw/MCP Smoke Outputs

The adapter smoke harness should create:

```text
runs/openclaw-smoke/openclaw-trace/prepare_case.stdout
runs/openclaw-smoke/openclaw-trace/prepare_case.stderr
runs/openclaw-smoke/openclaw-trace/run_case.stdout
runs/openclaw-smoke/openclaw-trace/run_case.stderr
runs/openclaw-smoke/openclaw-trace/summary.json
runs/openclaw-smoke/agent-run/agent_run.json
runs/openclaw-smoke/agent-run/audit.jsonl
runs/openclaw-smoke/agent-run/findings.json
runs/openclaw-smoke/agent-run/report.md
runs/openclaw-smoke/agent-run/self_correction_events.json
```

The harness also writes deterministic intermediate outputs such as
`normalized_events.json` and `subject_timelines.json` under the same generated
output directory.

## Inspect Real-Gap Correction Visibility

The final demo self-correction is not an induced failure. It is the posture
revision recorded when the generated ROCBA case-question and gap outputs show
that theft contents, transfer destination, and exfiltration method remain
`not_assessed` under the submitted artifact scope.

For a local run directory, inspect audit and correction records with:

```bash
.venv/bin/python -m siftguard.integrations.tool_adapter summarize-run \
  --json-input '{"output_dir":"runs/openclaw-smoke/agent-run"}'
```

```bash
.venv/bin/python - <<'PY'
import json
from pathlib import Path

path = Path("runs/openclaw-smoke/agent-run/self_correction_events.json")
data = json.loads(path.read_text())
print(json.dumps(data.get("events", []), indent=2))
PY
```

OpenClaw should revise its final posture to:

```text
SIFTGuard did not find sufficient support for a theft or exfiltration conclusion within the submitted artifact scope.
```

The claim boundary is:

```text
The current artifact scope does not support a theft/exfiltration conclusion; additional artifacts such as browser history, cloud sync logs, network telemetry, removable-device artifacts, or memory analysis would be required.
```

## OpenClaw Runtime Demo

The preferred final OpenClaw path is the bounded MCP/tool-adapter workflow in
[OpenClaw MCP Workflow](openclaw-mcp-workflow.md). Use the adapter smoke harness
to demonstrate the typed tool boundary without provider keys or ROCBA evidence:

```bash
.venv/bin/python scripts/openclaw_siftguard_smoke.py --dry-run --output-dir runs/openclaw-smoke
```

For a live OpenClaw setup, register the MCP server documented in
[OpenClaw MCP Workflow](openclaw-mcp-workflow.md), then have OpenClaw invoke
`prepare_case`, `run_case`, `summarize_run`, and `validate_run_outputs`.
Use the reusable operator prompt in
[`examples/openclaw/case-triage.prompt.md`](../examples/openclaw/case-triage.prompt.md).
Case-specific claim-boundary wording is read from the JSON casebook metadata,
not from OpenClaw.

## Cleanup

Remove local generated smoke outputs after the demo:

```bash
rm -rf runs/openclaw-smoke
```

## Safety Reminder

Do not commit generated outputs, OpenClaw traces, credentials, raw evidence,
parser outputs, local case artifacts, VM files, private paths, hostnames, or
usernames. Do not paste raw evidence into OpenClaw prompts, and do not expose
arbitrary shell as the demo interface.
