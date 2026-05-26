# Development Notes

## Parser Wrapper Contract

Parser wrappers return `ParserResult` and emit normalized `ParserEvent`
observations. Generated files are stored under:

```text
runs/<case_id>/parser_outputs/<artifact_id>/<parser_name>/
runs/<case_id>/logs/
runs/<case_id>/normalized/
```

Wrappers must record execution through the safe runner and JSONL ledger. They
must not write to evidence roots.

## Adding a Parser Wrapper

When adding a new parser wrapper:

1. Define the expected artifact type and parser name.
2. Add command configuration and safe path resolution if needed.
3. Build commands as argv tuples or lists, without shell strings.
4. Use the safe runner for parser execution.
5. Normalize parser output into `ParserEvent` observations.
6. Preserve output file paths and hashes in `ParserResult`.
7. Add synthetic fixtures only.
8. Add fake-runner unit tests that do not require the real parser tool.
9. Add a SIFT validation plan for local real-tool testing.

## Testing Expectations

Run these before opening a PR:

```bash
.venv/bin/python -m pytest
.venv/bin/python -m ruff check .
.venv/bin/python -m mypy src
git diff --check
```

## Evidence Safety for Developers

- Unit tests use synthetic fixtures.
- Real evidence validation is manual, local, and SIFT-only.
- Do not commit `runs/`, `.local/`, evidence, parser outputs, or audit ledgers.
- Do not commit VM images, disk images, memory images, archives, or secrets.
- Use placeholders in docs instead of private paths.

## Parser Validation Checklist

- Tool version captured.
- Local evidence path configured outside the repo.
- Outputs written under `runs/`.
- Audit ledger generated.
- Normalized events generated.
- Warnings, errors, and limitations documented.
- Safety grep performed for private paths and overclaim language.
