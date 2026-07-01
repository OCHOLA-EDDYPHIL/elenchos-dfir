# Autonomy Example Bundle: `case-autonomy-demo`

A sanitized, committed run of the policy-gated autonomy loop
(`elenchos autonomy run`) over the synthetic `autonomy_demo` fixture. It uses **no
model, no network, and no real evidence** -- the `replay` provider replays
`decisions.jsonl`. Regenerate it with:

```bash
PYTHONPATH=src python scripts/generate_autonomy_example.py
```

or reproduce the run directly:

```bash
elenchos autonomy run \
  --case-id case_positive-control \
  --fixture tests/fixtures/positive_control/autonomy_demo.json \
  --output-dir runs/autonomy-demo \
  --provider replay \
  --decisions docs/examples/autonomy-runs/case-autonomy-demo/decisions.jsonl \
  --max-iterations 10
```

## Files

| File | What it shows |
|---|---|
| `decisions.jsonl` | The replay input: the bounded actions the provider proposes. |
| `autonomy_decisions.jsonl` | Each executed decision (hypothesis, expected/failure signal, `model_output_used_as_evidence: false`). |
| `state_observations.jsonl` | The deterministic `RunStateSummary` observed before each decision. |
| `plan_revisions.jsonl` | The evidence-driven plan change (verification failure -> self-correction). |
| `tool_executions.jsonl` | Per-step execution ledger, including denied proposals. |
| `self_correction_events.json` | The verifier-driven downgrade of the unsupported finding. |
| `trace_map.json` | Report claim -> finding -> event -> tool execution -> artifact; `all_supported_claims_resolved: true`. |
| `findings.json` | Final findings: one supported inferred claim + one downgraded `needs_review`. |
| `report.md` | Final narrative (supported claims only). |
| `policy_decisions.jsonl` | The policy gate's allow/deny record for every proposed action. |

## Redaction convention

Absolute paths are replaced with `$REPO_ROOT`, `$RUN_DIR`, and `$HOME`, matching
`docs/submission/log-excerpts`. Timestamps are from a fixed clock so the bundle is
stable across regenerations. This is **synthetic control data**, not a real case.

See [docs/autonomy-scorecard.md](../../../autonomy-scorecard.md) for the anchor-to-file
mapping.
