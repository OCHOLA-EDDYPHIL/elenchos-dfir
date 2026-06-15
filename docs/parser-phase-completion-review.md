# Parser Workflow Review

## Scope

This review summarizes the parser workflow available in Elenchos. It covers
parser wrappers, normalization, CLI and MCP parser schemas, local SIFT
validation, failure visibility, gated integration tests, evidence handling, and
supporting documentation.

Parser events are observational records. They do not independently prove
maliciousness, execution certainty, persistence, compromise, theft, or
exfiltration.

## Capability Checklist

| Area | Evidence | Status |
| --- | --- | --- |
| Parser tooling matrix | `docs/parser-tooling-matrix.md` | Complete |
| MFTECmd wrapper | Wrapper, normalization tests, and SIFT validation | Complete |
| RECmd Run Key wrapper | Wrapper, normalization tests, and SIFT validation | Complete |
| AmcacheParser wrapper | Wrapper, normalization tests, and SIFT validation | Complete |
| Parser CLI commands | `parse-mft`, `parse-registry-runkeys`, `parse-amcache` | Complete |
| MCP parser schemas | Typed parser tool descriptors | Complete |
| Failure visibility | Missing command, nonzero exit, malformed output, warnings, errors, and audit metadata | Complete |
| Gated SIFT integration tests | `tests/integration/test_sift_parser_wrappers.py` | Complete |
| Parser validation report | `docs/parser-validation.md` | Complete |
| Dataset and evidence handling docs | `docs/dataset.md` | Complete |
| Limitations docs | `docs/limitations.md` | Complete |
| Evidence safety | Raw evidence and generated parser output remain untracked | Complete |

## Validation Summary

Sanitized SIFT validation results are recorded in
`docs/parser-validation.md`.

| Parser | Source tool | Input artifact class | Status | Normalized event count | Warnings | Errors |
| --- | --- | --- | --- | ---: | ---: | ---: |
| `mftecmd` | MFTECmd | `$MFT` | success | 690504 | 0 | 0 |
| `recmd` | RECmd | NTUSER.DAT Run/RunOnce keys | success | 2 | 0 | 0 |
| `recmd` | RECmd | SOFTWARE Run/RunOnce keys | success | 4 | 0 | 0 |
| `amcacheparser` | AmcacheParser | Amcache.hve | partial_success | 128 | 1 | 0 |

Validation uses local provided evidence and SIFT tooling. Raw evidence,
generated parser outputs, and audit ledgers remain local-only and uncommitted.

## Quality Gates

The parser workflow is covered by:

```bash
git diff --check
.venv/bin/python -m pytest
.venv/bin/python -m ruff check .
.venv/bin/python -m mypy src
env -u ELENCHOS_RUN_SIFT_INTEGRATION .venv/bin/python -m pytest tests/integration -vv
```

Integration tests are skipped unless local SIFT evidence and parser tools are
configured explicitly.

## Evidence Safety Check

Safety checks verify that raw evidence, `.local/`, `runs/`, parser outputs, and
audit ledgers are not tracked.

```bash
git ls-files | grep -E '(^runs/|^\.local/|\.E01$|\.Ex01$|\.raw$|\.001$|\.7z$|\.zip$|\.qcow2$|\.ova$|\.vmdk$|\.vmem$|Amcache\.hve$|NTUSER\.DAT$|UsrClass\.dat$|SYSTEM$|SOFTWARE$|SAM$|SECURITY$|\$MFT$)'
```

Local untracked files under `runs/` and `.local/` may exist from validation and
research runs. They remain outside version control.

## Risks

- Parser validation uses selected local evidence subsets, not exhaustive
  enterprise coverage.
- Parser output depends on MFTECmd, RECmd, AmcacheParser, and input artifact
  quality.
- Dirty hives, incomplete artifacts, or parser-specific output shapes may
  produce `partial_success` and warnings.
- Parser events require correlation, validation, and analyst review before
  they support reportable findings.
- Additional parser families must preserve the same boundaries: constrained
  tools, no arbitrary shell execution, read-only evidence, generated outputs,
  validation, and auditability.
