# Parser Contracts

## Purpose

Parser wrappers must return shared contracts before any artifact-specific
wrapper logic runs. These contracts describe observations extracted
from parser output and wrapper-level execution results. They do not perform
correlation, create findings, or make investigative conclusions.

## ParserEvent

`ParserEvent` represents one normalized observation from parser output. It keeps
the source artifact identity, parser identity, timestamp context when available,
evidence references, and a `RawRecordRef` back to the parser row or record.
Stable raw record references may use values such as `csv:mft.csv:1842`,
`json:amcache.json:/entries/12`, or `text:runkeys.txt:44`.

`ParserEvent` is not a finding. It must not make investigative conclusions.
A future analysis layer owns finding and claim validation.

## ParserResult

`ParserResult` represents the result a future parser wrapper returns. It records
parser identity, source artifact identity, argv-style command, output files,
output hashes, audit event IDs, normalized events, warnings, errors, timing, and
status.

Supported wrapper statuses are `success`, `partial_success`, `skipped`, and
`failed`. A missing parser command must be visible as `skipped` or `failed`
instead of being hidden.

## Output Paths

Parser outputs use this convention:

```text
runs/<case_id>/parser_outputs/<artifact_id>/<parser_name>/
runs/<case_id>/logs/
runs/<case_id>/normalized/
```

Path helpers reject empty identifiers, traversal, absolute identifier values,
path separators, null bytes, newlines, and shell metacharacters.

## Command Configuration

Parser commands are represented as argv tuples only. Command configuration never
accepts arbitrary shell strings, never uses shell execution, and does not split
shell-like command text.

Default parser command names are:

- `mftecmd`: `MFTECmd`
- `recmd`: `RECmd`
- `amcacheparser`: `AmcacheParser`

Local executable overrides may be supplied through:

- `SIFTGUARD_MFT_PARSER`
- `SIFTGUARD_REGISTRY_PARSER`
- `SIFTGUARD_AMCACHE_PARSER`

Overrides are validated as a single executable argv element. Shell metacharacters
such as `;`, `&`, `|`, redirection, backticks, and `$` are rejected.

## Fixture Policy

Parser fixtures under `tests/fixtures/parser_outputs/` are synthetic only. They
are not real evidence, not generated parser output from case data, and not
complete documentation of every real parser column.

Wrapper code, parser normalization, parser CLI commands, and MCP parser schemas
are available in the parser workflow. Correlation and findings are handled by
the analysis workflow.

## MFT Parser Wrapper

The MFT wrapper uses the verified `MFTECmd` command configuration for supplied
`$MFT` artifact paths. It writes the parser CSV to
`runs/<case_id>/parser_outputs/<artifact_id>/mftecmd/mftecmd.csv` and writes
stdout/stderr logs under `runs/<case_id>/logs/`.

MFT normalization emits observational `ParserEvent` records such as
`file_record`, `file_created`, `file_modified`, and `file_accessed`. These events
preserve parser-reported paths, timestamps, evidence references, and raw row
references. They do not create findings or interpret activity.

Unit tests use synthetic MFTECmd-style CSV fixtures and fake runner injection.
SIFT validation against the real tool is summarized in
`docs/parser-validation.md`.

## Registry Run Key Parser Wrapper

The Registry Run Key wrapper uses the verified `RECmd` command configuration for
supplied `SOFTWARE` and `NTUSER.DAT` hive artifact paths. It runs direct `--kn`
lookups for `Run` and `RunOnce` targets, writes CSV outputs to
`runs/<case_id>/parser_outputs/<artifact_id>/recmd/`, and writes stdout/stderr
logs under `runs/<case_id>/logs/`.

Registry normalization emits observational `ParserEvent` records with
`event_type="registry_run_key"`. These events preserve key paths, value names,
value data, hive labels, timestamps when present, evidence references, and raw
row references. They do not create findings.

Unit tests use synthetic RECmd-style CSV fixtures and fake runner injection.
SIFT validation against the real tool is summarized in
`docs/parser-validation.md`.

## Registry User-Activity Parser Wrapper

The Registry user-activity wrapper reuses the RECmd command configuration for
each prepared profile `NTUSER.DAT` hive. It runs bounded direct lookups for UserAssist,
RecentDocs, OpenSavePidlMRU, LastVisitedPidlMRU, and TypedPaths, writes parser
CSV/JSON outputs under `runs/<case_id>/parser_outputs/<artifact_id>/recmd/`,
and records missing-key, parser-unavailable, parser-error, decode-error, and
no-row conditions as structured coverage gaps.

Normalization emits observational `ParserEvent` records with
`artifact_family="registry_user_activity"` and typed event names such as
`registry_userassist_program_use` and `registry_recent_document_candidate`.
These events preserve the prepared artifact id, source id, Registry key/value
context, decoded target where available, timestamp kind, evidence reference,
sanitized `profile_id` where available,
raw row reference, and parser status. They produce analyst review candidates;
they do not prove theft, transfer, exfiltration, compromise, or malware
execution by themselves.

## Amcache Parser Wrapper

The Amcache wrapper uses the verified `AmcacheParser` command configuration for
supplied `Amcache.hve` artifact paths. It writes the parser CSV to
`runs/<case_id>/parser_outputs/<artifact_id>/amcacheparser/amcache.csv` and
writes stdout/stderr logs under `runs/<case_id>/logs/`.

Amcache normalization emits observational `ParserEvent` records with
`event_type="amcache_execution"`. These events preserve parser-reported program
names, paths, hashes, timestamps when present, evidence references, and raw row
references. They do not create findings or interpret activity.

Unit tests use synthetic AmcacheParser-style CSV fixtures and fake runner
injection. SIFT validation against the real tool is summarized in
`docs/parser-validation.md`.

## Parser CLI And MCP Schemas

The CLI exposes constrained parser wrapper commands:

- `elenchos parse-mft`
- `elenchos parse-registry-runkeys`
- `elenchos parse-amcache`

Parser CLI commands emit `ParserResult` JSON to stdout by default. When
`--json-out` is used, the result JSON path must resolve under `runs_root` and
must not resolve inside `evidence_root`.

MCP parser tool schemas are defined for `parse_mft`, `parse_registry_runkeys`,
and `parse_amcache`. They describe constrained parser wrappers, not arbitrary
process execution. The OpenClaw-facing runtime path is the bounded
MCP/tool-adapter workflow documented in `docs/openclaw-mcp-workflow.md`.
Parser interfaces do not generate findings.
