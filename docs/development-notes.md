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
3. Represent commands as argv tuples or lists, without shell strings.
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

## Local SIFT Integration Tests

Parser integration tests are local-only and skipped by default. Enable them only
when SIFT parser tools and local staged evidence artifacts are available:

```bash
export SIFTGUARD_RUN_SIFT_INTEGRATION=1
export SIFTGUARD_TEST_MFT_PATH="<LOCAL_EVIDENCE_ROOT>/mft/$MFT"
export SIFTGUARD_TEST_NTUSER_HIVE="<LOCAL_EVIDENCE_ROOT>/registry/NTUSER.DAT"
export SIFTGUARD_TEST_SOFTWARE_HIVE="<LOCAL_EVIDENCE_ROOT>/registry/SOFTWARE"
export SIFTGUARD_TEST_AMCACHE_PATH="<LOCAL_EVIDENCE_ROOT>/amcache/Amcache.hve"

.venv/bin/python -m pytest tests/integration
```

When the gate is enabled, missing environment variables fail with clear
messages. The tests write generated parser output to pytest temporary
directories and do not require or commit evidence artifacts.

## Parser Failure Visibility

Parser failures must be visible to callers. Missing parser commands return
`skipped` or `failed` results with clear errors. Nonzero parser exits are not
converted to clean success. Malformed parser output must preserve warnings or
errors in `ParserResult`, and any usable rows may still be returned as
observational events.

The audit ledger records command execution metadata, including argv, exit code,
duration, stdout/stderr paths, stdout/stderr hashes when files exist, and final
runner status. Warnings and errors describe parser or data quality conditions;
they are not incident conclusions.

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
