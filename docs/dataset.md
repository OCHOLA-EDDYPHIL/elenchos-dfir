# Dataset and Evidence Handling

## Scope

This page describes local evidence selection for parser validation and demo
runs. Raw evidence is not stored in Git, and committed documentation uses
placeholders instead of private local paths.

## Required Artifact Types

- `$MFT`: filesystem metadata observations, including names, paths, record
  metadata, and parser-reported timestamps.
- Registry hives:
  - `NTUSER.DAT` for user-level `Run` and `RunOnce` keys.
  - `SOFTWARE` for machine-level `Run` and `RunOnce` keys.
- `Amcache.hve`: application compatibility cache observations.

## Why These Artifacts Are Included

These artifacts provide breadth across filesystem metadata, registry autostart
locations, and application metadata. They are sufficient to validate parser
wrapper mechanics. They do not, by themselves, establish a complete
incident narrative.

## Local Staging Layout

Use a local evidence root outside the repository:

```text
<LOCAL_EVIDENCE_ROOT>/
  mft/$MFT
  registry/NTUSER.DAT
  registry/SOFTWARE
  amcache/Amcache.hve
```

## Local Config

The validation harness can read local paths from an ignored `.local` file:

```bash
mkdir -p .local/sift-validation

cat > .local/sift-validation/paths.env <<'EOF'
SIFTGUARD_VALIDATION_EVIDENCE_ROOT=<LOCAL_EVIDENCE_ROOT>
SIFTGUARD_VALIDATION_MFT_PATH=<LOCAL_EVIDENCE_ROOT>/mft/$MFT
SIFTGUARD_VALIDATION_REGISTRY_HIVE_PATHS=<LOCAL_EVIDENCE_ROOT>/registry/NTUSER.DAT:<LOCAL_EVIDENCE_ROOT>/registry/SOFTWARE
SIFTGUARD_VALIDATION_AMCACHE_PATH=<LOCAL_EVIDENCE_ROOT>/amcache/Amcache.hve
EOF
```

Do not commit `.local/`.

## Hash Policy

- Hash raw or staged artifacts locally when needed.
- Do not commit hashes if they reveal private evidence provenance unless the
  report is intentionally sanitized.
- Parser outputs include output hashes for generated files where appropriate.
- Evidence hash verification remains local-only unless a sanitized report
  requires it.

## Git Safety

Do not commit evidence, `.local/`, `runs/`, parser outputs, audit ledgers, VM
files, or disk images.

Examples of forbidden repository content:

- `*.E01`
- `*.raw`
- `*.vmdk`
- `*.qcow2`
- `Amcache.hve`
- `NTUSER.DAT`
- `SOFTWARE`
- `$MFT`

## Demo Dataset Note

The demo can use locally staged artifacts from the provided FIND EVIL evidence
dataset. The repository documents artifact classes and workflow, not private
local evidence paths.
