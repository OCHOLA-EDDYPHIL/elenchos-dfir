# Accuracy Report

## Status

Draft pending final run.

This report structure is submission-ready, but the results are not final. The
primary validation/demo run has not been completed with the full supported
artifact set, representative execution logs are not packaged yet, and no final
self-correction episode is recorded in this report. Issue #89 must remain open
until those outputs are available and reviewed.

## Environment

| Item | Value |
| --- | --- |
| Host OS | Ubuntu 24.04.4 LTS |
| SIFT version | not captured |
| Python version | 3.12.3 |
| Commit SHA | `0d28e81` |
| SIFTGuard MCP version | `0.1.0` |
| MFTECmd | `1.3.0+5eb8a7e63b5c2058be18d2784741f92cd1978879` |
| RECmd | `2.1.0+b9838adf98fae6c96dd617101f0323199b1574be` |
| AmcacheParser | `1.5.2+41484591de04144e1569eaad23e65cd719f8e154` |

Tool versions were captured from local command output during draft preparation.
The SIFT Workstation version itself was not captured.

## Case and dataset

| Item | Status |
| --- | --- |
| Case ID or sanitized local label | pending final run |
| Dataset source category | local Windows disk artifacts staged outside the repository |
| Artifact scope | `$MFT`, Registry `Run`/`RunOnce` keys from `NTUSER.DAT` and `SOFTWARE`, and `Amcache.hve` |
| Raw evidence committed | no |
| Evidence paths local/private | yes |
| Primary dataset status | incomplete for final report: `$MFT` and two registry hives are configured and present; configured `Amcache.hve` is not present |
| Secondary dataset status | not run |

The repository documents artifact classes and local staging rules in
`docs/dataset.md`. It does not publish raw evidence, private paths, generated
parser outputs, or local run logs.

## Test configuration

Commands actually run for this draft:

```bash
git status --short --branch
gh pr view 101 --json number,state,mergedAt,mergeCommit,url,title
python - <<'PY'
# sanitized local evidence availability check; private paths were not printed
PY
python - <<'PY'
# SIFT parser tool availability and version check
PY
```

Final primary validation/demo commands were not run for this draft because the
configured Amcache artifact is unavailable and no final generated run outputs
exist to summarize.

Configuration source:

- `.local/sift-validation/paths.env` exists locally.
- Private evidence paths were checked for availability but are not printed here.
- Enabled artifact classes for the final run remain `$MFT`, Registry
  `Run`/`RunOnce`, and `Amcache.hve`.

Determinism notes:

- Parser wrappers use argv-style command configuration and write generated
  output under ignored run directories.
- Correlation and validation are deterministic for the same normalized inputs.
- Tool output can vary with SIFT parser versions, input artifact quality, and
  missing or partial fields.

Known environment dependencies:

- Equivalent local evidence must be staged outside the repository.
- `MFTECmd`, `RECmd`, and `AmcacheParser` must be available in the SIFT/Linux
  environment.
- Generated outputs remain local unless sanitized examples are deliberately
  prepared for repository inclusion.

## Validation method

SIFTGuard MCP evaluates claims through a constrained analyst-assist workflow:

- Parser wrappers convert tool output into normalized parser observations.
- Normalized events feed correlation for drop, persistence, and execution
  relationships.
- Validation assigns findings to `confirmed`, `inferred`, `rejected`, or
  `needs_review`.
- Unsupported confirmed or inferred claims are blocked, downgraded, or marked
  `needs_review`.
- Final reports should be generated only from validated finding objects.
- Audit entries preserve tool execution context, status, timing, output paths,
  and error state for traceability.

Parser observations are not findings by themselves. Analyst review remains
required before using findings outside triage.

## Findings summary

No final findings recorded yet; pending primary validation run.

| Finding ID | Claim | Status | Evidence refs | Source artifacts | Notes |
| --- | --- | --- | --- | --- | --- |

## Status counts

| Status | Count |
| --- | --- |
| Total findings | pending final run |
| Confirmed | pending final run |
| Inferred | pending final run |
| Rejected | pending final run |
| Needs review | pending final run |

## False positives

Pending final run. No false-positive statement is made until recorded findings
have been reviewed.

| Finding ID | Claim | Why false positive | How detected | Corrective action |
| --- | --- | --- | --- | --- |

## Missed artifacts

Pending final run. Expected artifact review will be based on the staged dataset
manifest, parser output status, validation results, and analyst review notes.

| Expected artifact | Expected signal | Observed result | Explanation | Follow-up |
| --- | --- | --- | --- | --- |

## Unsupported or downgraded claims

Pending final run. The validation policy blocks or downgrades unsupported claims,
but no final primary-run unsupported or downgraded claim table is available yet.

| Claim | Where it appeared | Why unsupported | Final status | Mitigation |
| --- | --- | --- | --- | --- |

## Self-correction episodes

No final self-correction episode is recorded in this report yet; this remains
required for the final demo package.

The synthetic induced-failure test documents the expected correction mechanism:
an unsupported confirmed finding with missing evidence references is detected and
downgraded to `needs_review`. That test is not a substitute for final demo/run
evidence.

| Episode ID | Trigger | Initial state | Corrective action | Outcome | Log reference |
| --- | --- | --- | --- | --- | --- |

## Representative execution logs

Representative final logs are pending issue #90. Expected local generated files
for the final run include:

- `runs/<case-id>/agent-run/audit.jsonl`
- `runs/<case-id>/agent-run/findings.json`
- `runs/<case-id>/agent-run/agent_run.json`
- `runs/<case-id>/agent-run/report.md`

These paths are placeholders. Do not commit private logs, raw parser outputs,
private paths, or generated run directories unless sanitized examples are
explicitly prepared and reviewed.

## Secondary validation

Status: not run.

No secondary compatible artifact set was available during draft preparation. A
secondary run should remain limited to the same scope: `$MFT`, Registry
`Run`/`RunOnce` keys, and `Amcache.hve`. If secondary evidence remains
unavailable or incomplete, the final report should record that limitation
honestly rather than treating it as scope expansion.

## Reproducibility

The final run should be reproducible from documented local inputs and commands
when equivalent evidence and parser tooling are available:

- Stage raw evidence outside the repository using the layout in
  `docs/dataset.md`.
- Keep evidence read-only and generated outputs under ignored run directories.
- Run the README parser, correlation, and agent workflow commands against the
  staged artifacts.
- Preserve local `audit.jsonl`, `findings.json`, `agent_run.json`, and
  `report.md` for review.

Not committed:

- Raw evidence.
- Local evidence paths.
- Generated parser outputs.
- Local run logs.
- Private hostnames, usernames, credentials, or case paths.

## Limitations

- Windows disk artifacts only.
- Supported artifact focus is `$MFT`, Registry `Run`/`RunOnce` keys, and
  `Amcache.hve`.
- Memory forensics is out of scope.
- Packet, network, cloud, mobile, and remote endpoint triage are out of scope.
- Offensive operations are out of scope.
- SIFTGuard MCP is not legal evidence certification.
- Analyst review remains required.
- Secondary validation may be limited by available evidence.
- This draft does not claim final accuracy results.

## Finalization checklist

- [ ] Primary dataset run completed.
- [ ] Findings counts recorded.
- [ ] False positives reviewed.
- [ ] Missed artifacts reviewed.
- [ ] Unsupported claims reviewed.
- [ ] Self-correction episode recorded.
- [ ] Representative logs linked or packaged.
- [ ] Secondary validation recorded or explicitly marked unavailable.
- [ ] Report reviewed for private paths and sensitive values.
- [ ] Commit SHA recorded.
