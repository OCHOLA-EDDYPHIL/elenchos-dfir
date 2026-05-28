# Demo Script v0 (Under 5 Minutes)

1. Show repository hygiene
- `git status --short`
- `git ls-files | grep -Ei '(^runs/|^\.local/|\.E01$|\.raw$|\.dd$)' || true`

2. Show controlled positive detection
- `rm -rf runs/case_positive-control`
- `.venv/bin/python -m siftguard agent run-fixture --case-id case_positive-control --fixture tests/fixtures/positive_control/positive_chain.json --output-dir runs/case_positive-control/agent-run --max-iterations 7`
- Show sanitized summary: one `inferred` finding with `$MFT`, Registry, and
  Amcache evidence categories.

3. Show controlled self-correction
- `rm -rf runs/case_self-correction-control`
- `.venv/bin/python -m siftguard agent run-fixture --case-id case_self-correction-control --fixture tests/fixtures/positive_control/unsupported_claim.json --output-dir runs/case_self-correction-control/agent-run --max-iterations 7`
- Show sanitized summary: unsupported induced claim downgraded to
  `needs_review`, correction records present, `correction_applied` in audit.

4. Show real staged primary bounded triage
- `.venv/bin/python -m siftguard agent run --case-id case_staged-primary --manifest runs/case_staged-primary/manifest.json --output-dir runs/case_staged-primary/agent-run-final --max-iterations 7 --max-normalized-events 5000 --event-selection-profile forensic-triage`
- Show sanitized summary: 5000 normalized events, 1347 timelines, 128
  `needs_review` findings, 0 confirmed/inferred/rejected, 0 MFT-only findings.

5. Show local outputs without committing them
- `find runs/case_positive-control/agent-run -maxdepth 1 -type f -printf '%f\n' | sort`
- `find runs/case_self-correction-control/agent-run -maxdepth 1 -type f -printf '%f\n' | sort`

6. Close with limitations
- Controlled fixtures prove pipeline behavior.
- Real primary evidence remains conservative bounded triage.
- Generated `runs/` outputs and private evidence stay local-only.
