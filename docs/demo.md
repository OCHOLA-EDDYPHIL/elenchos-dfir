# Demo Guide

## Demo Goals

The agent workflow demo should show:

- A constrained agent run.
- Verifier detection of an unsupported claim.
- Self-correction downgrading an unsupported finding to `needs_review`.
- Audit visibility for verification and correction events.
- OpenClaw/MCP invoking the bounded SIFTGuard tool-adapter workflow.

## From A Clean Repo

Start from a clean worktree:

```bash
git status --short
```

Run the synthetic induced-failure test. This proves the self-correction path
without real evidence, parser tools, OpenClaw, network access, or external
services:

```bash
.venv/bin/python -m pytest tests/unit/agent/test_induced_failure_demo.py
```

Run the preferred OpenClaw/MCP adapter dry-run harness. This exercises the
bounded tool interface and writes generated outputs under ignored `runs/`
paths without provider keys or ROCBA evidence:

```bash
.venv/bin/python scripts/openclaw_siftguard_smoke.py --dry-run --output-dir runs/openclaw-smoke
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
```

The harness also writes deterministic intermediate outputs such as
`normalized_events.json` and `subject_timelines.json` under the same generated
output directory.

## Inspect Correction Visibility

The induced-failure test is the repeatable correction proof. It asserts that an
unsupported confirmed finding with empty `evidence_refs` is detected, downgraded
to `needs_review`, written to `agent_run.json`, and audited with
`verification_failed` and `correction_applied`.

For a local run directory, inspect audit and correction records with:

```bash
grep -E 'verification_failed|correction_applied' \
  runs/case_self-correction-control/agent-run/audit.jsonl
```

```bash
.venv/bin/python - <<'PY'
import json
from pathlib import Path

path = Path("runs/case_self-correction-control/agent-run/agent_run.json")
data = json.loads(path.read_text())
print(json.dumps(data.get("corrections", []), indent=2))
PY
```

Use the induced-failure test above when demonstrating self-correction. The
adapter dry-run smoke is expected to complete cleanly and prove the tool
boundary, not correction behavior.

## Optional jq Inspection

If `jq` is installed:

```bash
jq '.corrections' runs/case_self-correction-control/agent-run/agent_run.json
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
