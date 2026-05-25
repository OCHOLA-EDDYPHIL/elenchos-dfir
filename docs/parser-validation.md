# Parser Validation

## Scope

This page tracks M2 parser wrapper validation in the SIFT Workstation for the
MFTECmd, RECmd, and AmcacheParser wrappers. Parser outputs are normalized into
observational `ParserEvent` records only. This validation does not create
findings, perform correlation, or make maliciousness claims.

## Validation Environment

Validation was run locally inside the SIFT Workstation VM against staged copies
from a local extracted Windows C-drive E01 from the provided hackathon evidence
dataset. The E01 was exposed through EWF and mounted as a direct NTFS volume in
read-only mode; no partition offset was used.

- Date checked: 2026-05-25T20:37:16Z
- OS: Ubuntu 24.04.4 LTS
- Kernel: Linux 6.8.0 generic family
- Python: 3.12.3
- MFTECmd: on `PATH`, version `1.3.0+5eb8a7e63b5c2058be18d2784741f92cd1978879`
- RECmd: on `PATH`, version `2.1.0+b9838adf98fae6c96dd617101f0323199b1574be`
- AmcacheParser: on `PATH`, version `1.5.2+41484591de04144e1569eaad23e65cd719f8e154`

Hostnames, usernames, home directories, and private evidence paths are omitted
from committed documentation.

## Local Evidence Policy

Evidence is local-only and read-only. Raw evidence, generated parser outputs,
validation summaries, and validation audit ledgers are not committed.
Validation output stays under `runs/`, which is gitignored. Evidence paths are
redacted or replaced with placeholders in committed documentation.

## Commands

Set local paths through environment variables:

```bash
export SIFTGUARD_VALIDATION_EVIDENCE_ROOT="<LOCAL_EVIDENCE_ROOT>"
export SIFTGUARD_VALIDATION_MFT_PATH="<LOCAL_EVIDENCE_ROOT>/.../$MFT"
export SIFTGUARD_VALIDATION_REGISTRY_HIVE_PATHS="<LOCAL_EVIDENCE_ROOT>/.../NTUSER.DAT:<LOCAL_EVIDENCE_ROOT>/.../SOFTWARE"
export SIFTGUARD_VALIDATION_AMCACHE_PATH="<LOCAL_EVIDENCE_ROOT>/.../Amcache.hve"
```

Then run:

```bash
.venv/bin/python scripts/validate_sift_parsers.py \
  --case-id CASE-VALIDATION-M2 \
  --runs-root runs \
  --summary-out runs/CASE-VALIDATION-M2/sift-parser-validation-summary.json
```

Alternatively, place the same variables in `.local/sift-validation/paths.env`.
The `.local/` directory is ignored and must remain local-only.

## Results

Validation ran with staged artifacts under `<LOCAL_EVIDENCE_ROOT>`. The selected
user profile hive is redacted as `<REDACTED_USER_PROFILE>`.

| Artifact | Staged input | Status |
| --- | --- | --- |
| `$MFT` | `<LOCAL_EVIDENCE_ROOT>/mft/$MFT` | staged |
| SOFTWARE hive | `<LOCAL_EVIDENCE_ROOT>/registry/SOFTWARE` | staged |
| NTUSER.DAT hive | `<LOCAL_EVIDENCE_ROOT>/registry/NTUSER.DAT` from `<REDACTED_USER_PROFILE>` | staged |
| Amcache.hve | `<LOCAL_EVIDENCE_ROOT>/amcache/Amcache.hve` | blocked: not present in the mounted Windows C-drive image |

Parser wrapper results:

| Parser | Source tool | Input artifact class | Status | Normalized event count | Warnings | Errors |
| --- | --- | --- | --- | ---: | ---: | ---: |
| `mftecmd` | MFTECmd | `$MFT` | success | 690504 | 0 | 0 |
| `recmd` | RECmd | NTUSER.DAT Run/RunOnce keys | success | 2 | 0 | 0 |
| `recmd` | RECmd | SOFTWARE Run/RunOnce keys | success | 4 | 0 | 0 |
| `amcacheparser` | AmcacheParser | Amcache.hve | failed | 0 | 0 | 1 |

Validation output was written under `runs/CASE-VALIDATION-M2/`. The validation
summary was written to
`runs/CASE-VALIDATION-M2/sift-parser-validation-summary.json`. The audit ledger
was written to `runs/CASE-VALIDATION-M2/audit.jsonl` and contained 5 entries.

Issue #34 remains open because the local Windows 7 C-drive evidence did not
contain `Windows/AppCompat/Programs/Amcache.hve`, so the AmcacheParser wrapper
could not be run against a local Amcache artifact and did not generate normalized
Amcache events. The mounted image contained `RecentFileCache.bcf`, which is not
the Amcache.hve artifact required for this validation.

## Limitations

This validation used one Windows host image and disk artifacts only. Memory
artifacts were out of scope. MFT timestamps are filesystem metadata
observations. Run keys are autostart artifact observations; interpretation
belongs to later correlation work. Amcache observations, when available, do not
by themselves establish program execution. Parser output depends on the supplied
artifacts and tool behavior.
