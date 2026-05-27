# Accuracy Report

## Status

Draft pending final accuracy review.

This report structure is submission-ready, and primary parser validation has
been run against locally staged artifacts from one evidence image. A bounded
one-go agent workflow also completed against the staged primary artifacts using
an explicit normalized-event cap for large-input triage. The report is still not
final because false-positive review, missed-artifact review, unsupported-claim
review, and final primary-run accuracy conclusions are not complete. Issue #89
must remain open until those outputs are reviewed.

## Environment

| Item | Value |
| --- | --- |
| Host OS | Ubuntu 24.04.4 LTS |
| SIFT version | not captured |
| Python version | 3.12.3 |
| Commit SHA used for parser validation | `03faf60` |
| Commit SHA used for one-go agent attempt | `99d9e25` |
| Commit SHA used for bounded one-go agent run | pending PR commit |
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
| Primary dataset status | parser validation completed with useful partial output; bounded one-go agent run completed with exit code `0` |
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

Initial unbounded primary one-go agent command, shown with sanitized
placeholders:

```bash
.venv/bin/python -m siftguard inventory <STAGED_PRIMARY_ROOT> \
  --manifest-out runs/case_staged-primary/manifest.json

.venv/bin/python -m siftguard agent run \
  --case-id case_staged-primary \
  --manifest runs/case_staged-primary/manifest.json \
  --output-dir runs/case_staged-primary/agent-run \
  --max-iterations 7
```

Primary one-go agent exit code: `137`. The run wrote partial audit and parser
wrapper log entries, completed inventory, and started parse, but it was killed
before `agent_run.json`, `findings.json`, `report.md`, or final verification
were produced. Local kernel logs showed the Python process was killed by the
OOM path at approximately 3.3 GB resident memory. This is recorded as incomplete
run evidence and motivated an explicit bounded triage run.

Completed bounded primary one-go agent command, shown with sanitized
placeholders:

```bash
.venv/bin/python -m siftguard agent run \
  --case-id case_staged-primary \
  --manifest runs/case_staged-primary/manifest.json \
  --output-dir runs/case_staged-primary/agent-run-bounded \
  --max-iterations 7 \
  --max-normalized-events 5000
```

Bounded primary one-go agent exit code: `0`. This run completed inventory,
parse, correlation, validation, report generation, and verification. The cap is
an explicit triage constraint, not an exhaustive full-`$MFT` analysis. The
generated metadata and warnings record that `max_normalized_events=5000` was
applied.

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

## Primary bounded one-go agent run

The constrained one-go agent workflow was run against the same staged primary
artifact classes. The completed run is useful final-run evidence for bounded
triage behavior, but the findings still require analyst accuracy review before
this report can be finalized.

| Item | Value |
| --- | --- |
| Manifest case id | `case_staged-primary` |
| Manifest artifact count | 4 |
| Agent exit code | `0` |
| Final agent status | `completed` |
| Step count | 6 |
| Completed phases | inventory, parse, correlate, validate, report, verify |
| Max normalized events | 5000 |
| Limit reached | yes |
| Normalized event count | 5000 |
| Timeline count | 1347 |
| Finding count | 1347 |
| Finding status counts | `needs_review`: 1347 |
| Audit entry count | 22 |
| Warning count | 6 |
| Error count | 0 |
| Correction count | 0 |

Sanitized parser contribution counts for the bounded run:

| Artifact class | Normalized events included |
| --- | ---: |
| `SOFTWARE` Run/RunOnce | 1 |
| `Amcache.hve` | 128 |
| `$MFT` | 4871 |
| user `NTUSER.DAT` Run/RunOnce | 0 |

The bounded run confirms that the constrained workflow can complete against the
primary staged artifact set in the SIFT VM. It also records that the user
`NTUSER.DAT` did not produce Run/RunOnce events and that the large `$MFT`
artifact was capped after the configured limit. No confirmed compromise claim is
made from these counts alone.

## Findings summary

The bounded primary run produced 1347 finding objects. All are currently
`needs_review`, so the report does not treat them as confirmed or inferred
without analyst review. The full private finding list remains local in
`findings.json` and is not committed.

| Finding ID | Claim | Status | Evidence refs | Source artifacts | Notes |
| --- | --- | --- | --- | --- | --- |
| local private findings | private evidence-derived timeline claims | `needs_review` | retained locally | `$MFT`, `SOFTWARE`, `Amcache.hve` | 1347 findings require review before final accuracy conclusions. |

## Status counts

| Status | Count |
| --- | --- |
| Total findings | 1347 |
| Confirmed | 0 |
| Inferred | 0 |
| Rejected | 0 |
| Needs review | 1347 |

## False positives

Pending analyst review of the 1347 `needs_review` findings. No false-positive
statement is made until recorded findings have been reviewed.

| Finding ID | Claim | Why false positive | How detected | Corrective action |
| --- | --- | --- | --- | --- |

## Missed artifacts

Pending analyst review. Parser validation and the bounded agent run did show
that the selected user `NTUSER.DAT` did not produce Run/RunOnce events; that
parser-level result should be reviewed before final missed-artifact conclusions
are made.

| Expected artifact | Expected signal | Observed result | Explanation | Follow-up |
| --- | --- | --- | --- | --- |

## Unsupported or downgraded claims

Pending analyst review of the bounded primary run. The validation policy marked
all 1347 bounded-run findings as `needs_review`; no confirmed or inferred
claims were emitted in the recorded run.

| Claim | Where it appeared | Why unsupported | Final status | Mitigation |
| --- | --- | --- | --- | --- |

## Self-correction episodes

No natural primary staged-evidence self-correction episode is recorded in this
report yet. The completed bounded primary run produced no correction records.
This remains required for final primary-run accuracy evidence if the final
package is expected to demonstrate correction on the primary evidence workflow
itself.

Synthetic induced self-correction evidence is documented in
`docs/execution-log-traceability.md`: an unsupported confirmed finding with
missing evidence references is detected, the inventory is rechecked, and the
finding is downgraded to `needs_review`. That evidence supports execution-log
packaging and demo preparation, but it is not a substitute for completed primary
evidence accuracy results.

| Episode ID | Trigger | Initial state | Corrective action | Outcome | Log reference |
| --- | --- | --- | --- | --- | --- |

## Representative execution logs

Representative execution-log documentation is available in
`docs/execution-log-traceability.md`. That document records sanitized summaries
for:

- The completed bounded primary staged-evidence one-go agent run.
- A successful synthetic constrained agent workflow.
- A synthetic induced self-correction workflow.

Primary parser validation created local generated outputs, including:

- `runs/CASE-FINAL-PRIMARY/sift-parser-validation-summary.json`
- `runs/CASE-FINAL-PRIMARY/audit.jsonl`

The completed bounded primary staged-evidence one-go agent run created local
outputs, including:

- `runs/case_staged-primary/manifest.json`
- `runs/case_staged-primary/agent-run-bounded/audit.jsonl`
- `runs/case_staged-primary/agent-run-bounded/findings.json`
- `runs/case_staged-primary/agent-run-bounded/agent_run.json`
- `runs/case_staged-primary/agent-run-bounded/normalized_events.json`
- `runs/case_staged-primary/agent-run-bounded/subject_timelines.json`
- `runs/case_staged-primary/agent-run-bounded/report.md`

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

The bounded primary run should be reproducible from documented local inputs and
commands when equivalent evidence and parser tooling are available:

- Stage raw evidence outside the repository using the layout in
  `docs/dataset.md`.
- Keep evidence read-only and generated outputs under ignored run directories.
- Run the README parser, correlation, and bounded agent workflow commands
  against the staged artifacts.
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
- The bounded primary run used `--max-normalized-events 5000` and is not an
  exhaustive full-`$MFT` analysis.
- This draft does not claim final accuracy results.

## Finalization checklist

- [x] Primary parser validation run completed.
- [x] Primary bounded correlation/finding run completed.
- [x] Findings counts recorded.
- [ ] False positives reviewed.
- [ ] Missed artifacts reviewed.
- [ ] Unsupported claims reviewed.
- [ ] Primary self-correction episode recorded, or final package explicitly uses
  synthetic induced correction evidence.
- [x] Representative logs linked or packaged in
  `docs/execution-log-traceability.md`.
- [ ] Secondary validation recorded or explicitly marked unavailable.
- [ ] Report reviewed for private paths and sensitive values.
- [ ] Commit SHA recorded.
