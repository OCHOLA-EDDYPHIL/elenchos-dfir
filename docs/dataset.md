# Dataset Notes (Placeholder)

## Policy
- Evidence is not stored in Git.
- Official FIND EVIL starter case data is handled locally only.
- Evidence paths are expected to remain under local `cases/` directories, which are gitignored.

## Expected local layout
- `cases/official/raw/`
- `cases/official/selected/`
- `runs/case_demo_001/`

## Dataset source
- Placeholder: add official source link or source note once evidence is acquired.

## Artifact selection policy
- Keep raw source untouched in `cases/official/raw/`.
- Copy only minimum required artifacts into `cases/official/selected/` for deterministic runs.
- Track why each selected artifact is included.

## Hash recording policy
- Record SHA256 for each selected artifact in the manifest.
- Recompute hashes at run start for integrity checks.

## Fields to complete once evidence is acquired
- Case name:
- Source URL or official source note:
- Downloaded files:
- Selected artifacts:
- SHA256 hashes:
- Known ground truth:
- Assumptions:
