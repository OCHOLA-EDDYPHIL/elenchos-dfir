# OpenClaw Gap Self-Correction Runbook

## Purpose

This demo leads with OpenClaw as the analyst-facing orchestration layer and
SIFTGuard as the bounded forensic execution and validation layer. OpenClaw
plans and requests work through the SIFTGuard MCP/tool adapter. SIFTGuard
constrains tool access, runs deterministic workflows, validates claims against
generated evidence records, and records the audit trail.

The self-correction is not a fake induced error. The correction is OpenClaw
discovering, through SIFTGuard-generated outputs, that the ROCBA case asks theft
and exfiltration questions but the submitted artifact scope does not support a
theft/exfiltration conclusion. SIFTGuard preserves that as a gap instead of
hallucinating an answer.

## Demo Flow

1. Start OpenClaw with local provider/model configuration.
2. Register or confirm the SIFTGuard MCP server:

   ```bash
   .venv/bin/python -m siftguard.integrations.mcp_server
   ```

3. Provide the prompt from
   `docs/demo/openclaw-rocba-gap-demo-prompt.md`.
4. OpenClaw calls bounded SIFTGuard tools only:
   `prepare_case`, `run_case`, `summarize_run`, `validate_run_outputs`.
5. SIFTGuard prepares supported artifacts and writes generated outputs under
   ignored `runs/` paths.
6. SIFTGuard runs deterministic analysis and writes `report.md`,
   `findings.json`, `case_questions.json`, `gap_analysis.json`,
   `decision_trace.json`, `self_correction_events.json`, `audit.jsonl`, and
   `performance_summary.json`.
7. OpenClaw summarizes supported findings and generated trace paths.
8. OpenClaw validates outputs through `validate_run_outputs`.
9. OpenClaw discovers insufficient support for theft/exfiltration from
   `case_questions.json`, `gap_analysis.json`, and
   `self_correction_events.json`.
10. OpenClaw revises the final posture:

    SIFTGuard did not find sufficient support for a theft or exfiltration conclusion within the submitted artifact scope.

11. OpenClaw explains the claim boundary:

    The current artifact scope does not support a theft/exfiltration conclusion; additional artifacts such as browser history, cloud sync logs, network telemetry, removable-device artifacts, or memory analysis would be required.

12. The final report and machine-readable outputs preserve evidence refs, gaps,
    limitations, audit records, and decision trace paths.

## Smoke Harness

Use the deterministic smoke harness when ROCBA evidence or OpenClaw provider
configuration is unavailable:

```bash
.venv/bin/python scripts/openclaw_siftguard_smoke.py --dry-run --output-dir runs/openclaw-smoke
```

The smoke harness exercises the same bounded tool boundary without requiring a
live model, API key, or raw ROCBA evidence.

## Reproducible Fallback

The direct CLI remains the reproducible fallback for every OpenClaw-requested
operation:

```bash
.venv/bin/python -m siftguard case prepare ...
.venv/bin/python -m siftguard agent run-case ...
```

Use CLI output when validating local reproducibility, but lead the final demo
with OpenClaw calling the bounded MCP/tool adapter.

## Safety Notes

- OpenClaw is orchestration, not forensic evidence.
- SIFTGuard deterministic outputs are the forensic validation record.
- No model output is evidence.
- No raw evidence is passed to OpenClaw or an LLM.
- No arbitrary shell execution is exposed by the SIFTGuard adapter.
- Evidence remains read-only; generated outputs stay under ignored paths.
- Memory analysis, browser history, cloud sync logs, network telemetry, and
  removable-device artifacts are not added by this workflow.
