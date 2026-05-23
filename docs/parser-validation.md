# Parser Validation

## Scope

This page tracks M2 parser wrapper validation in the SIFT Workstation for the
MFTECmd, RECmd, and AmcacheParser wrappers. Parser outputs are normalized into
observational `ParserEvent` records only. This validation does not create
findings, perform correlation, or make maliciousness claims.

## Validation Environment

Validation harness support was added for local SIFT runs. In this workspace,
the parser tools are available on `PATH`, but local test evidence paths were not
configured when this document was created.

- Date checked: 2026-05-23T20:13:25Z
- OS: Ubuntu 24.04.4 LTS
- Kernel: Linux 6.8.0 x86_64 family
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

Full wrapper validation did not run because local test evidence paths were not
configured through `SIFTGUARD_VALIDATION_*` variables or
`.local/sift-validation/paths.env`.

Current status:

- MFT wrapper: blocked pending local `$MFT` test artifact path
- Registry Run Key wrapper: blocked pending local `NTUSER.DAT` and/or
  `SOFTWARE` hive test artifact paths
- Amcache wrapper: blocked pending local `Amcache.hve` test artifact path
- Audit ledger validation: blocked until parser wrappers run against local test
  artifacts

Issue #34 should remain open until the wrappers are run in SIFT against local
test evidence, normalized events are generated, output appears under `runs/`,
and sanitized results are added here.

## Limitations

MFT timestamps are filesystem metadata observations. Run keys are autostart
artifact observations, not standalone proof of persistence. Amcache observations
do not alone prove execution. Parser output depends on the supplied artifacts
and tool behavior.
