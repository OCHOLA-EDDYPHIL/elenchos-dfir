# Accuracy Report

## Status

Finalized for submission snapshot: resource-adaptive bounded triage +
controlled positive detection + audited self-correction.

This report records three separate validation cases. The controlled positive
and self-correction cases are synthetic fixtures that prove pipeline behavior.
The real staged primary case remains the local SIFT evidence result and is
reported as bounded triage, not exhaustive ground-truth recall. Controlled
fixtures are synthetic validation controls, not real compromise claims.

## Validation Method

SIFTGuard evaluates normalized Windows disk artifact observations through a
constrained workflow:

- Parser wrappers normalize `$MFT`, Registry `Run`/`RunOnce`, and Amcache
  observations.
- Correlation groups observations by subject path.
- Validation emits findings only when support rules justify them.
- Unsupported confirmed or inferred claims are downgraded or held for review.
- Audit logs preserve run steps, verifier results, and correction events.

Parser observations are not findings by themselves. Analyst review remains
required before using `needs_review` candidates as operational conclusions.

## Positive-Control Detection

The positive-control fixture is synthetic and sanitized. It models one coherent
subject with a file-created MFT observation, a Registry Run persistence value,
and an Amcache application observation for the same path.

Command:

```bash
rm -rf runs/case_positive-control
.venv/bin/python -m siftguard agent run-fixture \
  --case-id case_positive-control \
  --fixture tests/fixtures/positive_control/positive_chain.json \
  --output-dir runs/case_positive-control/agent-run \
  --max-iterations 7
```

Sanitized result:

| Item | Value |
| --- | --- |
| Input type | synthetic controlled positive fixture |
| Agent exit code | 0 |
| Agent status | `completed` |
| Step count | 6 |
| Input source | `synthetic_positive_control` |
| Normalized events | 6 |
| Total source events seen | 6 |
| Timelines | 2 |
| Findings | 1 |
| Finding status counts | `inferred`: 1 |
| Evidence categories | `$MFT`, Registry, Amcache |
| Correction count | 0 |
| Audit entries | 17 |

Conclusion: when the evidence contains a coherent drop / execution /
persistence chain, SIFTGuard emits one grouped supportable `inferred` finding.
The positive-control fixture emitted 1 inferred finding, and its evidence
categories were MFT, Registry, and Amcache. The result is not represented as
real compromise in the primary evidence.

## Real Primary Conservative Triage

The real staged primary run remains the conservative SIFT evidence result. It
uses resource-adaptive bounded triage to fit the constrained VM and refuses to
promote weak or incomplete evidence to confirmed or inferred findings.

Command shape:

```bash
.venv/bin/python -m siftguard agent run \
  --case-id case_staged-primary \
  --manifest runs/case_staged-primary/manifest.json \
  --output-dir runs/case_staged-primary/agent-run-final \
  --max-iterations 7 \
  --max-normalized-events 5000 \
  --event-selection-profile forensic-triage
```

Sanitized result:

| Item | Value |
| --- | --- |
| Agent exit code | 0 |
| Agent status | `completed` |
| Step count | 6 |
| Selection profile | `forensic-triage` |
| Max normalized events | 5000 |
| Normalized events written | 5000 |
| Total source events seen | 947241 |
| Timelines | 1347 |
| Findings | 128 |
| Finding status counts | `needs_review`: 128 |
| Confirmed / inferred / rejected | 0 / 0 / 0 |
| MFT-only findings | 0 |
| Correction count | 0 |
| Audit entries | 22 |

Coverage summary:

| Artifact class | Parser status | Selected events | Notes |
| --- | --- | ---: | --- |
| `SOFTWARE` Run/RunOnce | `success` | 1 | High-signal Registry event preserved. |
| `Amcache.hve` | `partial_success` | 128 | Dirty-hive / missing-transaction-log warning preserved. |
| `$MFT` | `partial_success`, bounded | 4871 | Deterministically selected under the 5000-event cap. |
| user `NTUSER.DAT` Run/RunOnce | `failed` for queried keys | 0 | Recorded as a coverage limitation, not fatal. |

Conclusion: incomplete or ambiguous real evidence produces bounded
`needs_review` triage. Ordinary MFT-only timelines remain in timeline and
coverage data instead of being inflated into findings. The real primary
evidence emitted 128 `needs_review` findings, 0 confirmed, 0 inferred, 0
rejected, and 0 MFT-only findings. It does not claim confirmed compromise.

## Self-Correction Control

The self-correction control is synthetic and sanitized. It introduces an
unsupported proposed `inferred` claim into an otherwise partial MFT + Amcache
fixture without Registry persistence support.
It is an internal verifier regression control, not the final OpenClaw demo
self-correction story. The final demo self-correction is the real ROCBA
theft/exfiltration evidence-gap posture revision documented in
`docs/demo/openclaw-gap-self-correction-runbook.md`.

Command:

```bash
rm -rf runs/case_self-correction-control
.venv/bin/python -m siftguard agent run-fixture \
  --case-id case_self-correction-control \
  --fixture tests/fixtures/positive_control/unsupported_claim.json \
  --output-dir runs/case_self-correction-control/agent-run \
  --max-iterations 7
```

Sanitized result:

| Item | Value |
| --- | --- |
| Input type | synthetic self-correction fixture |
| Agent exit code | 0 |
| Agent status | `completed` |
| Step count | 7 |
| Input source | `synthetic_self_correction_control` |
| Normalized events | 3 |
| Total source events seen | 3 |
| Timelines | 1 |
| Final findings | 2 |
| Final finding status counts | `needs_review`: 2 |
| Correction count | 2 |
| Downgrade action | `downgrade_finding` |
| Audit entries | 27 |
| Audit evidence | `fixture_induced_claim_written`, `verification_failed`, `correction_applied` |

Conclusion: when an unsupported stronger claim is introduced, the verifier
detects missing support, the self-correction path downgrades the claim to
`needs_review`, and the audit trail records the correction. The self-correction
control produced correction records and downgraded unsupported claims to
`needs_review`.

## False Positives And Unsupported Claims

Confirmed/inferred false positives in the real primary run: 0, because the real
primary run emitted no confirmed or inferred findings.

The positive-control fixture emitted one inferred finding, but that fixture is a
controlled pipeline validation case and is not counted as real-evidence
malware detection. The self-correction fixture ended with only `needs_review`
findings after the unsupported claim was downgraded.

Unsupported claims were handled as follows:

| Case | Unsupported condition | Final behavior |
| --- | --- | --- |
| Positive control | none | One `inferred` finding retained. |
| Real primary | incomplete or ambiguous support | 128 `needs_review`; 0 positive claims. |
| Self-correction control | induced inferred claim with missing support | Downgraded to `needs_review` with correction records. |

## Missed Artifacts And Recall Limits

No malware-level ground truth is available for the real primary evidence, so
full recall cannot be scored. The real primary run is a bounded triage result:
large MFT coverage is deterministic but not exhaustive, and secondary
same-scope validation remains incomplete because Amcache coverage was absent in
the inspected secondary image.

The controlled positive fixture proves that the current correlation and
validation engine can emit a supportable finding when the supported evidence
classes contain a coherent chain. It does not prove prevalence in the real
primary image.

## Representative Local Outputs

The following generated outputs were produced locally under ignored `runs/`
directories and are not committed:

- Positive-control `agent_run.json`, `audit.jsonl`, `coverage_summary.json`,
  `normalized_events.json`, `subject_timelines.json`, `findings.json`, and
  `report.md`.
- Self-correction-control outputs with correction records in `agent_run.json`
  and `correction_applied` events in `audit.jsonl`.
- Real primary resource-adaptive outputs with coverage and findings summaries.

Committed documentation contains only sanitized counts and command shapes.

## Limitations

- Windows disk artifacts only.
- Supported artifact focus is `$MFT`, Registry `Run`/`RunOnce`, and
  `Amcache.hve`.
- Memory forensics, packet/network forensics, cloud, mobile, and remote
  endpoint triage are out of scope.
- Controlled fixtures prove pipeline behavior, not real-world prevalence.
- The real primary run is bounded by `--max-normalized-events 5000` and
  `--event-selection-profile forensic-triage`; it is not exhaustive full-disk
  recall.
- `needs_review` findings are triage candidates, not positive claims.
- SIFTGuard MCP is a triage tool, not an adjudication substitute.

## Finalization Checklist

- [x] Positive-control fixture emitted one supportable inferred finding.
- [x] Real staged primary evidence remained conservative and bounded.
- [x] Self-correction-control fixture produced correction records and audit
  events.
- [x] False-positive conclusion recorded for confirmed/inferred real-evidence
  findings.
- [x] Missed-artifact and recall limitations recorded.
- [x] Raw evidence, private paths, generated runs, parser outputs, and private
  logs remain uncommitted.
