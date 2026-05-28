# Dataset and Evidence Handling

## Purpose

This document explains the supported evidence inputs, local staging layout,
validation scope, expected demo observations, and evidence safety rules for the
submission-ready SIFTGuard MCP workflow. It does not publish raw evidence,
private local paths, or private evidence hashes.

## Supported Dataset Scope

SIFTGuard MCP is scoped to Windows disk-artifact triage. The final supported
artifact classes are:

- `$MFT` for filesystem metadata and file timeline observations.
- Registry `Run` and `RunOnce` keys from `NTUSER.DAT` and `SOFTWARE` for
  persistence observations.
- `Amcache.hve` for application execution or application metadata observations.

The correlation focus is a drop / persistence / execution narrative built from
normalized observations. Parser observations do not become findings until the
correlation and validation workflow evaluates them.

## Required Local Artifact Layout

Use a local evidence root outside the repository. The paths below are examples;
use equivalent local paths that match the same filenames and artifact classes.

```text
<LOCAL_EVIDENCE_ROOT>/
  mft/$MFT
  registry/NTUSER.DAT
  registry/SOFTWARE
  amcache/Amcache.hve
```

Raw artifacts must remain outside the repository and should be mounted or staged
read-only. Generated outputs should go under `runs/` or another ignored
generated-output directory such as `outputs/`, `analysis/`, or
`reports/generated/`.

The evidence inventory records metadata such as artifact identifiers, relative
paths, sizes, SHA256 hashes, and artifact classifications. Keep that metadata
local unless it has been reviewed for sanitized documentation.

Manifest artifacts may include optional `source_image_id` and
`source_image_label` fields when one run combines staged artifacts from more
than one local image. These labels are for coverage accounting only. Do not mix
artifacts from different hosts into a single incident narrative unless that
relationship is independently supported.

## Local Config

The parser validation harness can read local paths from an ignored `.local`
file. These variable names match `scripts/validate_sift_parsers.py`.

```bash
mkdir -p .local/sift-validation

cat > .local/sift-validation/paths.env <<'EOF'
SIFTGUARD_VALIDATION_EVIDENCE_ROOT=<LOCAL_EVIDENCE_ROOT>
SIFTGUARD_VALIDATION_MFT_PATH=<LOCAL_EVIDENCE_ROOT>/mft/$MFT
SIFTGUARD_VALIDATION_REGISTRY_HIVE_PATHS=<LOCAL_EVIDENCE_ROOT>/registry/NTUSER.DAT:<LOCAL_EVIDENCE_ROOT>/registry/SOFTWARE
SIFTGUARD_VALIDATION_AMCACHE_PATH=<LOCAL_EVIDENCE_ROOT>/amcache/Amcache.hve
EOF
```

Do not commit `.local/`. Machine-specific evidence paths, mounted volume paths,
case names, hostnames, usernames, and private source locations must remain local.

## Demo Dataset

The final demo should use locally staged artifacts matching the supported layout.
The repository documents the artifact classes and workflow, not private local
evidence.

The demo case should contain enough activity to show:

- File creation or drop evidence from `$MFT`.
- Persistence evidence from Registry `Run` or `RunOnce` keys.
- Execution or application metadata evidence from `Amcache.hve` where available.
- Validation or correction behavior when a claim is unsupported, incomplete, or
  contradicted.

Do not claim a specific malware name, timestamp, indicator, or finding unless it
is backed by committed sanitized fixtures or reviewed public documentation.

## Secondary Validation

If suitable evidence is available before final submission, run one additional
compatible artifact set through the same workflow. Keep the validation scope to
the same artifact classes: `$MFT`, Registry `Run`/`RunOnce` keys, and
`Amcache.hve`.

The purpose is reproducibility checking: confirm parser behavior, correlation
behavior, output structure, and traceability outside the primary demo case. This
is not scope expansion. If secondary evidence is unavailable or incomplete,
record that honestly in the accuracy report; it is not a blocker by itself.
For example, a secondary image without `Amcache.hve` can still contribute MFT
or Registry coverage. Missing optional artifacts should be recorded in coverage
metadata as skipped or unavailable, not treated as failure for the whole image.

## Expected Generated Outputs

A local run may generate:

- Evidence manifest or inventory JSON.
- Parser outputs under `runs/`.
- `coverage_summary.json` for artifact coverage, parser status, bounded
  selection counts, skipped/unavailable artifacts, and limitations.
- Normalized parser events.
- `findings.json`.
- Audit JSONL, commonly `audit.jsonl`.
- `agent_run.json` when the constrained agent workflow is used.
- Markdown report, commonly `report.md`.

These outputs should normally remain uncommitted. Commit only intentionally
sanitized examples that have been reviewed for private paths, hostnames,
usernames, secrets, raw evidence content, and sensitive case data.

## Hash Policy

- Hash raw or staged artifacts locally when needed.
- Use checksums locally for evidence integrity and reproducibility.
- Do not publish hashes that reveal private evidence provenance unless the
  report is intentionally sanitized.
- Parser outputs include output hashes for generated files where appropriate.

## Large-File Handling

Do not commit raw evidence, evidence archives, VM images, disk images, parser
CSVs from private evidence, generated run directories, or private validation
outputs.

Keep large downloads outside the repository. Document source and acquisition
steps without embedding sensitive private URLs. Use `.local/` for
machine-specific paths and keep generated runs under ignored output roots.

Examples of forbidden repository content:

- `*.E01`
- `*.raw`
- `*.vmdk`
- `*.qcow2`
- `Amcache.hve`
- `NTUSER.DAT`
- `SOFTWARE`
- `$MFT`
- Private parser CSVs
- Private `runs/` outputs

## Test-Scope Matrix

| Artifact | Purpose | Required path | Expected observation | Limitation |
| --- | --- | --- | --- | --- |
| `$MFT` | Filesystem metadata and file timeline triage. | `<LOCAL_EVIDENCE_ROOT>/mft/$MFT` | File records, paths, metadata, and parser-reported timestamps that may support drop observations. | Filesystem metadata alone does not prove maliciousness or execution. |
| `NTUSER.DAT` | User-level autostart persistence triage. | `<LOCAL_EVIDENCE_ROOT>/registry/NTUSER.DAT` | `HKCU` `Run` and `RunOnce` values that may support persistence observations. | Run key presence requires analyst interpretation and may be benign. |
| `SOFTWARE` | Machine-level autostart persistence triage. | `<LOCAL_EVIDENCE_ROOT>/registry/SOFTWARE` | `HKLM` `Run` and `RunOnce` values that may support persistence observations. | Machine-level autostarts can be normal software behavior. |
| `Amcache.hve` | Application execution or application metadata triage. | `<LOCAL_EVIDENCE_ROOT>/amcache/Amcache.hve` | Program names, paths, hashes, and timestamps where the parser reports them. | Amcache observations do not by themselves establish execution certainty. |

## Unsupported Evidence Types

The final submission scope does not include:

- Memory images, unless separately documented in a future scope.
- Packet captures or network traffic analysis.
- Cloud logs or cloud incident response.
- Remote endpoint triage.
- Mobile artifacts.
- Broad SIFT tool automation.
- Offensive actions.
- Legal evidence certification.

SIFTGuard MCP is analyst-assist triage tooling. Analyst review remains required
for interpretation, reporting decisions, and any use outside local evaluation.
