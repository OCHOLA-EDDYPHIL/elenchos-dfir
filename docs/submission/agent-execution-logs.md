# Agent Execution Logs

This page documents the real OpenClaw / Elenchos execution logs used for the
FIND EVIL Devpost submission. The excerpts in this package are sanitized and
small. Raw OpenClaw sessions, raw run directories, raw evidence, parser dumps,
provider logs, and private paths are not included.

Model output is not forensic evidence. Deterministic Elenchos outputs are the
forensic authority.

## Demonstrated Runs

| Track | Run path | Case ID |
| --- | --- | --- |
| ROCBA narrative case | `runs/case-20260615-133435` | `rocba-standard` |
| Caseless Windows disk image | `runs/caseless-windows-disk-20260615-145428` | `caseless-windows-disk` |

## Real Logs Found

ROCBA logs:

- `runs/case-20260615-133435/model_rationale.jsonl`
- `runs/case-20260615-133435/policy_decisions.jsonl`
- `runs/case-20260615-133435/orchestration_trace.json`
- `runs/case-20260615-133435/progress.jsonl`
- `runs/case-20260615-133435/openclaw-console.log`
- `runs/case-20260615-133435/run/audit.jsonl`
- `runs/case-20260615-133435/run/decision_trace.json`
- `runs/case-20260615-133435/run/orchestration_trace.json`
- `runs/case-20260615-133435/run/policy_decisions.jsonl`
- `runs/case-20260615-133435/run/progress.jsonl`
- `runs/case-20260615-133435/run/validation_summary.json`

Caseless logs:

- `runs/caseless-windows-disk-20260615-145428/model_rationale.jsonl`
- `runs/caseless-windows-disk-20260615-145428/policy_decisions.jsonl`
- `runs/caseless-windows-disk-20260615-145428/orchestration_trace.json`
- `runs/caseless-windows-disk-20260615-145428/openclaw-console.log`
- `runs/caseless-windows-disk-20260615-145428/run/audit.jsonl`
- `runs/caseless-windows-disk-20260615-145428/run/decision_trace.json`
- `runs/caseless-windows-disk-20260615-145428/run/orchestration_finalization.json`
- `runs/caseless-windows-disk-20260615-145428/run/orchestration_trace.json`
- `runs/caseless-windows-disk-20260615-145428/run/policy_decisions.jsonl`
- `runs/caseless-windows-disk-20260615-145428/run/progress.jsonl`
- `runs/caseless-windows-disk-20260615-145428/run/validation_summary.json`

OpenClaw console logs were found for both runs. They are not committed as
excerpts because the structured logs provide the useful traceability and the
console logs contain local OpenClaw configuration and gateway details.

## Sanitized Excerpts Committed

- `log-excerpts/rocba-model-rationale.sample.jsonl`
- `log-excerpts/rocba-policy-decisions.sample.jsonl`
- `log-excerpts/rocba-validation-summary.sample.json`
- `log-excerpts/caseless-model-rationale.sample.jsonl`
- `log-excerpts/caseless-policy-decisions.sample.jsonl`
- `log-excerpts/caseless-orchestration-finalization.sample.json`
- `log-excerpts/caseless-validation-summary.sample.json`

No ROCBA finalization excerpt is included because
`runs/case-20260615-133435/run/orchestration_finalization.json` was not present
in the local run outputs.

## What Each Log Shows

| Log | Purpose |
| --- | --- |
| `model_rationale.jsonl` | Timestamped operational model rationale for the next bounded action. This is not evidence. |
| `policy_decisions.jsonl` | Deterministic allowed/rejected decisions for proposed bounded actions. |
| `orchestration_trace.json` | Sequenced orchestration events joining rationale, policy, and tool actions. |
| `progress.jsonl` | Deterministic run progress such as run start, normalization, report generation, validation, and finalization. |
| `audit.jsonl` | Deterministic Elenchos tool execution events. |
| `decision_trace.json` | Finding and case-question traceability decisions. |
| `validation_summary.json` | Required-file checks, forbidden wording checks, claim-boundary checks, and validation status. |
| `orchestration_finalization.json` | Final terminal state for the live autonomy loop when captured. |

## Traceability Path

Judges can trace a reported conclusion through:

`report.md -> finding ID -> evidence reference -> normalized event -> parser/tool execution -> audit.jsonl`

The structured files used for this trace are:

- `report.md` for the analyst-facing finding summary.
- `findings.json` for finding IDs and evidence references.
- `normalized_events.json` for normalized parser observations.
- `decision_trace.json` and `case_questions.json` for case-question and finding relationships.
- `audit.jsonl` for deterministic tool execution records.
- `validation_summary.json` for final safety and traceability validation.

## Token Usage

OpenClaw fallback sessions were found from the console logs:

- ROCBA session: `$HOME/.openclaw/agents/main/sessions/gateway-fallback-84974697-93eb-4a49-b382-585bd4d24d5a.trajectory.jsonl`
- Caseless session: `$HOME/.openclaw/agents/main/sessions/gateway-fallback-2d7bb506-eb91-44dc-a690-11e566c85916.trajectory.jsonl`

The nonzero aggregate counts below are copied from local OpenClaw trajectory
`model.completed` usage records. They are not estimates.

| Track | Source | Input | Output | Cache read | Total |
| --- | --- | ---: | ---: | ---: | ---: |
| ROCBA | `$HOME/.openclaw/agents/main/sessions/gateway-fallback-84974697-93eb-4a49-b382-585bd4d24d5a.trajectory.jsonl`, line 41 | 921 | 113 | 51072 | 52106 |
| Caseless | `$HOME/.openclaw/agents/main/sessions/gateway-fallback-2d7bb506-eb91-44dc-a690-11e566c85916.trajectory.jsonl`, line 18 | 7568 | 368 | 22912 | 30848 |

The raw OpenClaw session JSONL also contained per-tool mirrored message usage
objects with zero values. Those zero-value tool mirrors are not used as the
aggregate usage totals.

