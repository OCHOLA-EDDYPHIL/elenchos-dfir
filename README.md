# SIFTGuard MCP

Constrained autonomous DFIR workflow foundation for SANS SIFT Workstation.

## What this project is
- A minimal, testable Python foundation for deterministic DFIR orchestration.
- A scaffold for MCP typed tools, audit trails, provenance checks, and reproducible reporting.
- A hackathon-ready starting point for FIND EVIL / Protocol SIFT.

## What this project is not
- Not a full autonomous agent yet.
- Not a claim of forensic soundness, court admissibility, or evidentiary reliability.
- Not an offensive tooling framework.

## MVP scope
- Read-only evidence handling semantics.
- Deterministic artifact inventory + hashing + manifesting.
- JSONL execution ledger for traceable tool actions.
- Typed stubs for parser wrappers and MCP tool surface.

## Architecture summary
- CLI and future MCP entrypoints invoke constrained modules.
- Evidence module inventories artifacts and computes SHA256.
- Policy module enforces command/path restrictions.
- Runner module records deterministic execution events.
- Validation/reporting scaffolds enforce traceability of findings.

## Supported artifacts planned
- `$MFT`
- Registry Run Keys
- `Amcache.hve`

## Quick start (local development)
```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## CLI usage
```bash
python -m siftguard --version
python -m siftguard hash /path/to/artifact
python -m siftguard inventory /path/to/case --manifest-out /path/to/manifest.json
python -m siftguard audit-read /path/to/execution_ledger.jsonl
```

## Test command
```bash
python -m pytest
```

## Expected local directories
- `cases/` for local case data (gitignored)
- `runs/` for run outputs (gitignored)
- `docs/` for reproducible project documentation

## Evidence safety rules
- Evidence files are never committed to Git.
- Treat case inputs as read-only.
- Keep outputs in `runs/` and outside evidence roots.
- Never commit secrets (`.env`, auth configs, private endpoints).

## Current status
- Repository and package foundation initialized.
- M1 includes evidence inventory/manifesting, JSONL audit ledger, and a hardened safe subprocess runner.
- Parser wrappers and MCP runtime remain intentionally scaffolded/incomplete.

## Devpost submission checklist
- [ ] Make repository public before final Devpost submission.
- [ ] Publish reproducible demo steps.
- [ ] Include accuracy report and limitations.
- [ ] Verify no evidence/secrets are committed.

## License
MIT (see `LICENSE`).
