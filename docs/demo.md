# Demo Guide

## Demo Goals

The agent workflow demo should show:

- A constrained agent run.
- Verifier detection of an unsupported claim.
- Self-correction downgrading an unsupported finding to `needs_review`.
- Audit visibility for verification and correction events.
- OpenClaw initiating the constrained SIFTGuard workflow.

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

Run the constrained OpenClaw smoke helper. This creates synthetic/local inputs
and writes generated outputs under ignored `runs/` paths:

```bash
./scripts/openclaw-agent-smoke.sh
```

## Expected OpenClaw Smoke Outputs

The smoke helper should create:

```text
runs/CASE-AGENT-OPENCLAW-SMOKE/agent-run/agent_run.json
runs/CASE-AGENT-OPENCLAW-SMOKE/agent-run/audit.jsonl
runs/CASE-AGENT-OPENCLAW-SMOKE/agent-run/findings.json
runs/CASE-AGENT-OPENCLAW-SMOKE/agent-run/report.md
```

The helper may also write deterministic intermediate outputs such as
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
  runs/CASE-AGENT-OPENCLAW-SMOKE/agent-run/audit.jsonl
```

```bash
.venv/bin/python - <<'PY'
import json
from pathlib import Path

path = Path("runs/CASE-AGENT-OPENCLAW-SMOKE/agent-run/agent_run.json")
data = json.loads(path.read_text())
print(json.dumps(data.get("corrections", []), indent=2))
PY
```

The successful smoke helper is expected to complete cleanly, so those commands
may show no correction entries for that specific run. Use the induced-failure
test above when demonstrating self-correction.

## Optional jq Inspection

If `jq` is installed:

```bash
jq '.corrections' runs/CASE-AGENT-OPENCLAW-SMOKE/agent-run/agent_run.json
```

## OpenClaw Runtime Demo

Use the narrow OpenClaw prompt and headless command in
[OpenClaw Agent Workflow](openclaw-agent-workflow.md) to have OpenClaw initiate
the smoke helper. Save raw OpenClaw output only under the ignored trace
directory documented there.

## Cleanup

Remove local generated smoke outputs after the demo:

```bash
rm -rf runs/CASE-AGENT-OPENCLAW-SMOKE
```

## Safety Reminder

Do not commit generated outputs, OpenClaw traces, credentials, raw evidence,
parser outputs, local case artifacts, VM files, private paths, hostnames, or
usernames. Do not paste raw evidence into OpenClaw prompts, and do not expose
arbitrary shell as the demo interface.
