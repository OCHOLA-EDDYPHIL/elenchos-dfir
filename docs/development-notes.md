# Development Notes

## How to work safely
- Keep evidence read-only.
- Write outputs only under `runs/`.
- Never commit case data, VM images, or secrets.
- Prefer deterministic, testable functions with explicit I/O.

## M1 implementation notes
- Evidence inventory recursively scans case roots, classifies known artifact types, hashes files, and emits deterministic artifact IDs.
- Manifest schema is dataclass-based and written/read as deterministic JSON with UTC `Z` timestamps.
- Audit ledger is append-only JSONL with stable keys and explicit status values (`success`, `failed`, `denied`).
- Subprocess execution is guarded by command and path policy:
- Commands are denylisted for destructive/network/escalation executables and shell metacharacter patterns.
- Output files are constrained to `runs/` and blocked from evidence roots.
- Future parser wrappers must use the same runner + audit pattern to preserve provenance.

## How to add a parser wrapper
- Add parser module under `src/siftguard/parser/`.
- Declare parser name and expected artifact type constants.
- Implement wrapper function that accepts explicit input/output paths.
- Emit audit events and preserve parser stdout/stderr hashes.
- Add unit tests with synthetic fixtures (no real evidence in repo).

## How to add an MCP tool
- Define request/response schema in `mcp_server/schemas.py`.
- Add tool handler in `mcp_server/server.py` without arbitrary shell passthrough.
- Route into domain module (evidence/parser/correlation/validation/reporting).
- Update README/docs and add end-to-end tests.

## How to add validation rules
- Extend `validation/provenance.py` with explicit rule function.
- Keep rules deterministic and explain failure reasons.
- Add tests for positive and negative paths.

## How to update docs when user-facing behavior changes
- Update `README.md` quick start and CLI usage.
- Update architecture/dataflow docs if boundaries changed.
- Update demo script and accuracy template if outputs changed.
