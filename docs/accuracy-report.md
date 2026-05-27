# Accuracy Report

## Status

Draft pending final run.

This report structure is submission-ready, and primary parser validation has
been run against locally staged artifacts from one evidence image. The report is
still not final because final correlation/finding output, representative
execution-log packaging, and final self-correction evidence are not recorded
yet. Issue #89 must remain open until those outputs are available and reviewed.

## Environment

| Item | Value |
| --- | --- |
| Host OS | Ubuntu 24.04.4 LTS |
| SIFT version | not captured |
| Python version | 3.12.3 |
| Commit SHA used for parser validation | `03faf60` |
| SIFTGuard MCP version | `0.1.0` |
| MFTECmd | `1.3.0+5eb8a7e63b5c2058be18d2784741f92cd1978879` |
| RECmd | `2.1.0+b9838adf98fae6c96dd617101f0323199b1574be` |
| AmcacheParser | `1.5.2+41484591de04144e1569eaad23e65cd719f8e154` |

Tool versions were captured from local command output during draft preparation.
The SIFT Workstation version itself was not captured.

## Case and dataset

| Item | Status |
| --- | --- |
| Case ID or sanitized local label | `CASE-FINAL-PRIMARY` |
| Dataset source category | local Windows disk artifacts staged outside the repository |
| Artifact scope | `$MFT`, Registry `Run`/`RunOnce` keys from `NTUSER.DAT` and `SOFTWARE`, and `Amcache.hve` |
| Raw evidence committed | no |
| Evidence paths local/private | yes |
| Primary dataset status | parser validation completed with useful partial output |
| Secondary dataset status | inspected but incomplete for same-scope validation because `Amcache.hve` was not found |

The repository documents artifact classes and local staging rules in
`docs/dataset.md`. It does not publish raw evidence, private paths, generated
parser outputs, or local run logs.

## Test configuration

Representative commands actually run, shown with sanitized placeholders:

```bash
git status --short --branch
gh pr view 102 --json state,mergeable,isDraft,title,headRefName,baseRefName
gh pr merge 102 --squash --delete-branch
command -v ewfmount
command -v mmls
command -v fsstat
command -v MFTECmd
command -v RECmd
command -v AmcacheParser
sudo ewfmount <PRIMARY_EVIDENCE_IMAGE> <PRIMARY_EWF_MOUNT>
fsstat <PRIMARY_EWF_MOUNT>/ewf1
sudo mount -o ro,loop,show_sys_files,streams_interface=windows \
  <PRIMARY_EWF_MOUNT>/ewf1 <PRIMARY_NTFS_MOUNT>
```

Primary parser validation command, shown with sanitized local evidence
placeholders:

```bash
.venv/bin/python scripts/validate_sift_parsers.py \
  --case-id CASE-FINAL-PRIMARY \
  --runs-root runs \
  --evidence-root <STAGED_PRIMARY_ROOT> \
  --mft-path '<STAGED_PRIMARY_ROOT>/mft/$MFT' \
  --registry-hive-path <STAGED_PRIMARY_ROOT>/registry/SOFTWARE \
  --registry-hive-path <STAGED_PRIMARY_ROOT>/registry/NTUSER.DAT \
  --amcache-path <STAGED_PRIMARY_ROOT>/amcache/Amcache.hve \
  --summary-out runs/CASE-FINAL-PRIMARY/sift-parser-validation-summary.json
```

Primary parser validation exit code: `2`. This indicates useful partial parser
validation output: at least one parser produced events, but not every supplied
artifact fully succeeded.

Configuration source:

- Primary artifacts were staged outside the repository under a local evidence
  root.
- Private evidence paths and user-profile names are not printed here.
- Enabled artifact classes for the primary parser run were `$MFT`, Registry
  `Run`/`RunOnce`, and `Amcache.hve`.
- The primary image exposed direct NTFS through the EWF layer; no partition
  offset was required.
- Staged primary artifacts included `$MFT`, `SOFTWARE`, one user `NTUSER.DAT`,
  and `Amcache.hve`.

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

## Primary parser validation results

Primary parser validation used a same-image staged artifact set. The run is
useful for parser accuracy notes, but it is not a final finding/correlation
assessment.

| Parser | Artifact class | Status | Events | Warnings | Errors | Notes |
| --- | --- | --- | ---: | ---: | ---: | --- |
| `mftecmd` | `$MFT` | `success` | 947112 | 0 | 0 | Filesystem metadata observations were normalized. |
| `recmd` | `SOFTWARE` Run/RunOnce keys | `success` | 1 | 0 | 0 | Machine-level Run/RunOnce validation produced one normalized event. |
| `recmd` | user `NTUSER.DAT` Run/RunOnce keys | `failed` | 0 | 0 | 2 | The selected user hive did not contain the queried Run or RunOnce keys. |
| `amcacheparser` | `Amcache.hve` | `partial_success` | 128 | 1 | 0 | AmcacheParser produced events, with a dirty-hive / missing-transaction-log warning preserved. |

Audit summary:

- Audit ledger path: `runs/CASE-FINAL-PRIMARY/audit.jsonl`.
- Audit entry count: 6.
- Generated parser outputs remain local under `runs/CASE-FINAL-PRIMARY/` and
  are not committed.

## Findings summary

No final findings recorded yet; pending primary correlation/finding run.

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

Pending final findings run. No false-positive statement is made until recorded
findings have been reviewed.

| Finding ID | Claim | Why false positive | How detected | Corrective action |
| --- | --- | --- | --- | --- |

## Missed artifacts

Pending final findings run. Parser validation did show that the selected user
`NTUSER.DAT` did not produce Run/RunOnce events; that parser-level result should
be reviewed when final findings are produced.

| Expected artifact | Expected signal | Observed result | Explanation | Follow-up |
| --- | --- | --- | --- | --- |

## Unsupported or downgraded claims

Pending final findings run. The validation policy blocks or downgrades
unsupported claims, but no final primary-run unsupported or downgraded claim
table is available yet.

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

Representative final logs are pending issue #90. Primary parser validation
created local generated outputs, including:

- `runs/CASE-FINAL-PRIMARY/sift-parser-validation-summary.json`
- `runs/CASE-FINAL-PRIMARY/audit.jsonl`

Expected local generated files for the later final agent/finding run include:

- `runs/<case-id>/agent-run/audit.jsonl`
- `runs/<case-id>/agent-run/findings.json`
- `runs/<case-id>/agent-run/agent_run.json`
- `runs/<case-id>/agent-run/report.md`

These paths are placeholders. Do not commit private logs, raw parser outputs,
private paths, or generated run directories unless sanitized examples are
explicitly prepared and reviewed.

## Secondary validation

Status: inspected but not run.

A secondary local image was inspected for same-scope artifacts. `$MFT`,
`SOFTWARE`, and user hives were present, but `Amcache.hve` was not found.
Secondary validation was therefore not forced. A secondary run should remain
limited to the same scope: `$MFT`, Registry `Run`/`RunOnce` keys, and
`Amcache.hve`. If secondary evidence remains unavailable or incomplete, the
final report should record that limitation honestly rather than treating it as
scope expansion.

## Reproducibility

The final run should be reproducible from documented local inputs and commands
when equivalent evidence and parser tooling are available:

- Stage raw evidence outside the repository using the layout in
  `docs/dataset.md`.
- Keep evidence read-only and generated outputs under ignored run directories.
- Run the README parser, correlation, and agent workflow commands against the
  staged artifacts.
- Repeat the parser-validation command above for parser wrapper checks.
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

- [x] Primary parser validation run completed.
- [ ] Primary correlation/finding run completed.
- [ ] Findings counts recorded.
- [ ] False positives reviewed.
- [ ] Missed artifacts reviewed.
- [ ] Unsupported claims reviewed.
- [ ] Self-correction episode recorded.
- [ ] Representative logs linked or packaged.
- [ ] Secondary validation recorded or explicitly marked unavailable.
- [ ] Report reviewed for private paths and sensitive values.
- [ ] Commit SHA recorded.
