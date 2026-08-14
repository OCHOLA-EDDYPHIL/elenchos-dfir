# Archive Validation

Validation date: 2026-08-14

This document records the final local checks for the private archive branch. It
does not validate historical real-case accuracy: the original evidence and SIFT
workstation are no longer available.

## Environment

- Branch: `archive/final`
- Base experiment commit: `b3355a5`
- Python: 3.14.5
- Installation: editable package with development dependencies in repository
  `.venv`
- Raw evidence accessed: none
- SIFT tools executed: none

## Static and Automated Checks

```text
pytest: 586 passed, 3 skipped
ruff: All checks passed
mypy: Success, 95 source files
```

## Documented Synthetic Replay

The exact documented fixture identity completed in six decisions:

```text
case_id=case_positive-control
iterations=6
stopped_reason=provider_requested_stop
decision_count=6
plan_revision_count=1
self_correction_count=2
verification_status=passed
trace_map_all_supported_claims_resolved=True
```

This proves the committed synthetic control flow is reproducible. It is not a
blind evaluation or a real forensic result.

## Negative Replay Observation

Running the same fixture and decisions under a different case ID returned exit
code zero but produced:

```text
plan_revision_count=0
self_correction_count=0
verification_status=None
trace_map_all_supported_claims_resolved=False
```

The archive therefore records case-identity coupling and permissive terminal
success as unresolved control-plane defects. See `docs/REVIVAL.md`.

## Dry Adapter Smoke Test

The evidence-free OpenClaw adapter dry run completed:

```text
prepare_status=completed
run_status=completed
validation_status=pass
finding_status_counts={}
case_question_status_counts={'not_assessed': 4}
```

## Hygiene Checks

- No tracked raw-evidence extension or generated run/log directory was found.
- No common cloud/API token or private-key signature was found in tracked files.
- No developer home-directory path was found in tracked files.
- Existing `/mnt/evidence` references are documentation/test placeholders, not
  committed evidence.
- Git object verification completed; two pre-existing dangling commits were
  reported and are not reachable from archived refs.

## Interpretation Boundary

The archive supports only these claims:

- the Python package installs without SIFT;
- its unit/integration tests and static checks pass;
- the documented synthetic replay exercises plan revision and deterministic
  downgrade behavior; and
- the dry adapter can produce and validate an evidence-free bounded packet.

It does not support claims about detection accuracy, real incident conclusions,
artifact coverage, or successful operation against the deleted cases.
