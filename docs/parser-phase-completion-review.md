# Parser Workflow Completion Review

## Scope

This review covers the parser workflow available in SIFTGuard MCP. It
verifies parser wrappers, normalization, CLI and MCP parser schemas, local SIFT
validation, failure visibility, gated integration tests, evidence handling, and
supporting documentation.

This review does not add parser behavior, artifact types, parser execution
features, or new evidence analysis.

## Completion Checklist

| Area | Evidence | Status |
| --- | --- | --- |
| Parser tooling matrix | Issue #14 and PR #38 | Complete |
| MFT wrapper | Issues #22 and #23; PR #40; wrapper, normalization tests, and SIFT validation | Complete |
| Registry Run Key wrapper | Issues #24 and #25; PR #41; wrapper, normalization tests, and SIFT validation | Complete |
| Amcache wrapper | Issues #26 and #27; PR #42; wrapper, normalization tests, and SIFT validation | Complete |
| Parser CLI commands | Issue #30; PR #43; `parse-mft`, `parse-registry-runkeys`, `parse-amcache` | Complete |
| MCP parser schemas | Issue #31; PR #43; typed parser tool descriptors | Complete |
| Failure visibility | Issue #32; PR #48; missing command, nonzero exit, malformed output, warnings/errors, audit metadata | Complete |
| Gated SIFT integration tests | Issue #29; PR #48; `tests/integration/test_sift_parser_wrappers.py` | Complete |
| SIFT validation report | Issue #34; PRs #45 and #46; `docs/parser-validation.md` | Complete |
| Parser workflow documentation | Issue #35; PR #47; README and `docs/` parser workflow docs | Complete |
| Dataset and evidence handling docs | `docs/dataset.md` | Complete |
| Limitations docs | `docs/limitations.md` | Complete |
| Quality gates | `pytest`, `ruff`, `mypy`, `git diff --check` | Complete |
| Evidence safety | No evidence or generated parser output tracked | Complete |

## Merged PR Trail

| PR | Summary |
| --- | --- |
| #38 | Parser tooling matrix |
| #39 | Parser contracts and synthetic fixture strategy |
| #40 | MFTECmd wrapper and MFT normalization |
| #41 | RECmd Run Key wrapper and normalization |
| #42 | AmcacheParser wrapper and normalization |
| #43 | Parser CLI commands and MCP parser schemas |
| #45 | SIFT validation results for MFT and Registry Run Keys |
| #46 | Amcache SIFT validation results |
| #47 | Parser workflow documentation |
| #48 | Gated integration tests and failure visibility coverage |

## Validation Summary

Sanitized SIFT validation results are recorded in `docs/parser-validation.md`.

| Parser | Source tool | Input artifact class | Status | Normalized event count | Warnings | Errors |
| --- | --- | --- | --- | ---: | ---: | ---: |
| `mftecmd` | MFTECmd | `$MFT` | success | 690504 | 0 | 0 |
| `recmd` | RECmd | NTUSER.DAT Run/RunOnce keys | success | 2 | 0 | 0 |
| `recmd` | RECmd | SOFTWARE Run/RunOnce keys | success | 4 | 0 | 0 |
| `amcacheparser` | AmcacheParser | Amcache.hve | partial_success | 128 | 1 | 0 |

Validation used local provided evidence and SIFT tooling. Raw evidence,
generated parser outputs, and audit ledgers remain local-only and uncommitted.
Parser events are observational records, not final incident conclusions.

## Quality Gate Results

Recorded on 2026-05-26 UTC from the SIFTGuard MCP repository.

| Gate | Result |
| --- | --- |
| `git diff --check` | passed |
| `.venv/bin/python -m pytest` | 170 passed, 3 skipped |
| `.venv/bin/python -m ruff check .` | passed |
| `.venv/bin/python -m mypy src` | passed; no issues in 39 source files |
| `env -u SIFTGUARD_RUN_SIFT_INTEGRATION .venv/bin/python -m pytest tests/integration -vv` | 3 skipped by default |

## Evidence Safety Check

Safety checks verified:

- No raw evidence is tracked.
- No `.local/` files are tracked.
- No `runs/` files are tracked.
- No parser outputs or audit ledgers are tracked.
- Validation paths are redacted in committed docs.

The tracked-file safety grep returned no tracked evidence or generated output:

```bash
git ls-files | grep -E '(^runs/|^\.local/|\.E01$|\.Ex01$|\.raw$|\.001$|\.7z$|\.zip$|\.qcow2$|\.ova$|\.vmdk$|\.vmem$|Amcache\.hve$|NTUSER\.DAT$|UsrClass\.dat$|SYSTEM$|SOFTWARE$|SAM$|SECURITY$|\$MFT$)'
```

Local untracked files under `runs/` and `.local/` may exist from validation and
research runs. They remain outside version control.

## Open Risks And Follow-Up Work

- Parser validation used selected local evidence subsets, not exhaustive
  enterprise coverage.
- Parser output depends on MFTECmd, RECmd, AmcacheParser, and input artifact
  quality.
- Dirty hives, incomplete artifacts, or parser-specific output shapes may
  produce `partial_success` and warnings.
- Parser events do not independently prove maliciousness, execution,
  persistence, or compromise.
- Future analysis and reporting layers must preserve claim-to-evidence links.
- Future MCP runtime wiring must keep the same safety boundaries: constrained
  tools, no arbitrary shell execution, local evidence read-only, and auditable
  outputs.
- Demo assets and final submission packaging remain separate follow-up work.

## Decision

Parser workflow completion criteria are satisfied by the verified issue closure
state, passing quality gates, documented SIFT validation, evidence safety
checks, and recorded open risks in this review.

The repository is ready to proceed to subsequent work after issue #36 closes.
