# Demo Script v0 (Under 5 Minutes)

1. Show repository hygiene
- `git status --short`
- `git ls-files | grep -Ei '(^runs/|^\.local/|\.E01$|\.raw$|\.dd$)' || true`

2. Show OpenClaw/MCP bounded tool path
- `.venv/bin/python scripts/openclaw_siftguard_smoke.py --dry-run --output-dir runs/openclaw-smoke`
- Show sanitized summary: `prepare_case`, `run_case`, `summarize_run`, and
  `validate_run_outputs` all ran through the bounded adapter without provider
  keys or raw ROCBA evidence.

3. Show real-gap self-correction posture
- Open `docs/demo/openclaw-rocba-gap-demo-prompt.md`.
- Show `runs/openclaw-smoke/agent-run/self_correction_events.json`.
- State: SIFTGuard did not find sufficient support for a theft or exfiltration
  conclusion within the submitted artifact scope.
- State: The current artifact scope does not support a theft/exfiltration
  conclusion; additional artifacts such as browser history, cloud sync logs,
  network telemetry, removable-device artifacts, or memory analysis would be
  required.

4. Show real staged primary bounded triage
- `.venv/bin/python -m siftguard agent run --case-id case_staged-primary --manifest runs/case_staged-primary/manifest.json --output-dir runs/case_staged-primary/agent-run-final --max-iterations 7 --max-normalized-events 5000 --event-selection-profile forensic-triage`
- Show sanitized summary: 5000 normalized events, 1347 timelines, 128
  `needs_review` findings, 0 confirmed/inferred/rejected, 0 MFT-only findings.

5. Show local outputs without committing them
- `find runs/openclaw-smoke/agent-run -maxdepth 1 -type f -printf '%f\n' | sort`

6. Close with limitations
- OpenClaw orchestrates bounded SIFTGuard tools; SIFTGuard computes the
  evidence-backed result.
- Real primary evidence remains conservative bounded triage.
- Generated `runs/` outputs and private evidence stay local-only.
