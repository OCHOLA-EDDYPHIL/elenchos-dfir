# Parser Tooling Matrix

## Purpose

This is the verified SIFT Workstation parser tooling matrix for M2. Parser wrapper
implementation must follow this document unless a later verified SIFT run updates
the matrix.

This document covers only `$MFT`, Registry Run Keys from `SOFTWARE` and
`NTUSER.DAT` hives, and `Amcache.hve`. It does not perform correlation, construct
an attack narrative, prove maliciousness, or claim forensic soundness or court
admissibility.

## Verification Environment

- Date verified: 2026-05-23 UTC.
- OS: Ubuntu 24.04.4 LTS (Noble Numbat).
- Kernel family: Linux 6.8.0 generic x86_64.
- SIFT indicators: SIFT apt preference/source files were present under `/etc`,
  and SIFT forensic tools were present under `/opt`, `/usr/local/bin`, and
  `/usr/share`.
- Python: 3.12.3 at `/usr/bin/python3`.
- .NET: SDK 9.0.116 and runtime/host 9.0.15 at `/usr/bin/dotnet`.
- Perl: 5.38.2 at `/usr/bin/perl`.
- Mono: not found on `PATH`.

Hostnames, usernames, private home paths, evidence paths, case names, and secrets
are intentionally omitted.

## Summary Matrix

| Artifact | Parser target | Selected tool | Verified command/path | Runtime | Version/help evidence | Input artifact | Output format | Output location convention | Failure behavior | M2 implementation decision |
|---|---|---|---|---|---|---|---|---|---|---|
| `$MFT` | NTFS master file table | MFTECmd | `/usr/local/bin/MFTECmd` -> `dotnet /opt/zimmermantools/MFTECmd.dll` | .NET | `--version` returned `1.3.0+5eb8a7e63b5c2058be18d2784741f92cd1978879`; help reports `MFTECmd version 1.3.0.0` | `$MFT` file via `-f` | CSV selected; JSON and bodyfile are also supported | `runs/<case_id>/parsers/mft/` | Missing and invalid input returned exit code `0` with error text on stdout | Use MFTECmd for issue #22 |
| Registry Run Keys from `SOFTWARE` | `HKLM\Software\Microsoft\Windows\CurrentVersion\Run` and `RunOnce` | RECmd | `/usr/local/bin/RECmd` -> `dotnet /opt/zimmermantools/RECmd/RECmd.dll` | .NET | `--version` returned `2.1.0+b9838adf98fae6c96dd617101f0323199b1574be`; help reports `RECmd version 2.1.0.0` | `SOFTWARE` hive via `-f` | CSV selected; JSON supported for `--kn` | `runs/<case_id>/parsers/registry_runkeys/software/` | Missing and invalid input returned exit code `0` with error text on stdout | Use RECmd direct key lookups for issue #24 |
| Registry Run Keys from `NTUSER.DAT` | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` and `RunOnce` | RECmd | `/usr/local/bin/RECmd` -> `dotnet /opt/zimmermantools/RECmd/RECmd.dll` | .NET | Same verified RECmd version/help evidence as above | `NTUSER.DAT` hive via `-f` | CSV selected; JSON supported for `--kn` | `runs/<case_id>/parsers/registry_runkeys/ntuser/` | Missing and invalid input returned exit code `0` with error text on stdout | Use RECmd direct key lookups for issue #24 |
| `Amcache.hve` | Windows Amcache hive | AmcacheParser | `/usr/local/bin/AmcacheParser` -> `dotnet /opt/zimmermantools/AmcacheParser.dll` | .NET | `--version` returned `1.5.2+41484591de04144e1569eaad23e65cd719f8e154`; help reports `AmcacheParser version 1.5.2.0` | `Amcache.hve` via `-f` | CSV selected; installed help does not advertise JSON output | `runs/<case_id>/parsers/amcache/` | Missing and invalid input returned exit code `0` with error text on stdout | Use AmcacheParser for issue #26 |

## `$MFT` Parser Tooling

Discovered candidates:

- `MFTECmd` was found on `PATH` at `/usr/local/bin/MFTECmd` and selected.
- `MFTECmd.exe` and `MFTECmd.dll` were present under `/opt/zimmermantools`, but
  the verified Linux invocation is the `/usr/local/bin/MFTECmd` wrapper.
- `log2timeline.py` was found but is a broad timeline processor, not the primary
  narrow M2 `$MFT` wrapper.
- Sleuth Kit tools such as `fls`, `icat`, `mmls`, and `fsstat` were found but
  are supporting filesystem tools, not the selected `$MFT` parser wrapper.

Invocation style:

- `/usr/local/bin/MFTECmd` is a Bash wrapper that invokes
  `dotnet /opt/zimmermantools/MFTECmd.dll`.
- Required input flag: `-f <path-to-$MFT>`.
- Supported output flags from installed help: `--csv <dir>`, `--json <dir>`,
  and `--body <dir>` with `--bdl`.
- M2 should use CSV output first because it is structured and directly supported.

Expected command template:

```bash
MFTECmd -f "$MFT_PATH" --csv "$RUNS_ROOT/parsers/mft/" --csvf mft.csv
```

Failure behavior:

- Missing input path: exit code `0`; stdout says the file was not found.
- Invalid synthetic input file: exit code `0`; stdout reports unknown file type.
- Missing output directory with invalid input: exit code `0`; the invalid input
  failed before output creation, and the missing directory was not created.

Limitations:

- No real evidence was parsed during this research PR.
- Valid `$MFT` output columns and file creation behavior must be confirmed with
  later synthetic fixtures during wrapper implementation.
- Wrappers must create the output directory before invocation and must not rely
  on exit code alone.

Implementation recommendation for issue #22:

- Resolve `MFTECmd` through configuration or environment override, defaulting to
  `PATH`.
- Execute through the M1 safe runner without `shell=True`.
- Preserve stdout/stderr under `runs/<case_id>/logs/`.
- Treat parser error text or missing expected CSV output as failure even when the
  process exit code is `0`.

## Registry Run Key Parser Tooling

Discovered candidates:

- `RECmd` was found on `PATH` at `/usr/local/bin/RECmd` and selected.
- RegRipper `rip.pl` was found at `/usr/local/bin/rip.pl` with `run` and
  `run_tln` plugins, but it writes primarily to stdout and also returned exit
  code `0` for invalid synthetic input while emitting plugin errors on stderr.
- `regipy` was not installed as a command or importable Python package.
- `log2timeline.py` and `psort.py` were found but are broad timeline tools.

Invocation style:

- `/usr/local/bin/RECmd` is a Bash wrapper that invokes
  `dotnet /opt/zimmermantools/RECmd/RECmd.dll`.
- Required hive input flag: `-f <hive>`.
- Selected direct lookup flag: `--kn <key-path>`.
- Output flags from installed help: `--csv <dir>`, optional `--csvf <file>`, and
  `--json <dir>` for `--kn`.
- `--nl` should be used for M2 wrappers so missing transaction logs do not abort
  parsing of available hives.

Batch/plugin files:

- No batch file is required for the selected M2 method.
- Verified RECmd batch examples exist under
  `/opt/zimmermantools/RECmd/BatchExamples/`.
- `SoftwareASEPs.reb` includes `Microsoft\Windows\CurrentVersion\Run` and
  `Runonce` entries for the `SOFTWARE` hive.
- `RECmd_Batch_MC.reb` includes `Software\Microsoft\Windows\CurrentVersion\Run`
  and `RunOnce` entries for the `NTUSER` hive.
- These batch files are broader than M2 Run/RunOnce scope, so direct `--kn`
  lookups are preferred unless fixture testing shows a batch file is required.
- Do not use RECmd `--sync` in wrappers; it downloads batch files and is outside
  the verified local-tooling gate.

Supported hives and target keys:

- `SOFTWARE` hive:
  - `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`
  - `HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `NTUSER.DAT` hive:
  - `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
  - `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce`

For RECmd, the `SOFTWARE` hive key path omits the `HKLM\Software` mount prefix
because the hive root is `HKLM\Software`. The `NTUSER.DAT` hive key path keeps
the `Software\...` prefix because the hive root is `HKCU`.

Expected command templates:

```bash
RECmd -f "$SOFTWARE_HIVE" --kn 'Microsoft\Windows\CurrentVersion\Run' --csv "$RUNS_ROOT/parsers/registry_runkeys/software/" --csvf software-run.csv --nl
RECmd -f "$SOFTWARE_HIVE" --kn 'Microsoft\Windows\CurrentVersion\RunOnce' --csv "$RUNS_ROOT/parsers/registry_runkeys/software/" --csvf software-runonce.csv --nl
RECmd -f "$NTUSER_HIVE" --kn 'Software\Microsoft\Windows\CurrentVersion\Run' --csv "$RUNS_ROOT/parsers/registry_runkeys/ntuser/" --csvf ntuser-run.csv --nl
RECmd -f "$NTUSER_HIVE" --kn 'Software\Microsoft\Windows\CurrentVersion\RunOnce' --csv "$RUNS_ROOT/parsers/registry_runkeys/ntuser/" --csvf ntuser-runonce.csv --nl
```

Failure behavior:

- Missing hive path: exit code `0`; stdout says the file does not exist.
- Invalid synthetic hive: exit code `0`; stdout reports a bad Registry hive
  signature.
- Missing output directory with invalid input: exit code `0`; the invalid input
  failed before output creation, and the missing directory was not created.

Limitations:

- No real registry hive was parsed during this research PR.
- Exact RECmd CSV columns and generated file naming must be confirmed with later
  synthetic fixtures.
- Transaction log handling policy should be finalized during wrapper contract
  work.

Implementation recommendation for issue #24:

- Use RECmd direct `--kn` lookups for the four M2 Run/RunOnce targets.
- Run one command per hive/key target so audit entries remain narrow and
  deterministic.
- Resolve `RECmd` through configuration or environment override, defaulting to
  `PATH`.
- Execute through the M1 safe runner without `shell=True`.
- Preserve stdout/stderr and treat missing expected CSV output or bad-signature
  text as failure even when the process exit code is `0`.

## Amcache Parser Tooling

Discovered candidates:

- `AmcacheParser` was found on `PATH` at `/usr/local/bin/AmcacheParser` and
  selected.
- RegRipper `rip.pl` includes `amcache` and `amcache_tln` plugins, but it is not
  selected because the dedicated AmcacheParser tool is available and the
  RegRipper plugin returned exit code `0` with stderr errors for invalid input.
- `log2timeline.py` was found but is a broad timeline processor, not the primary
  narrow M2 Amcache wrapper.

Invocation style:

- `/usr/local/bin/AmcacheParser` is a Bash wrapper that invokes
  `dotnet /opt/zimmermantools/AmcacheParser.dll`.
- Required input flag: `-f <Amcache.hve>`.
- Required output flag from installed help: `--csv <dir>`.
- Installed help does not advertise JSON output for this tool.

Expected command template:

```bash
AmcacheParser -f "$AMCACHE_HIVE" --csv "$RUNS_ROOT/parsers/amcache/" --csvf amcache.csv
```

Failure behavior:

- Missing input path: exit code `0`; stdout says the file was not found.
- Invalid synthetic hive: exit code `0`; stdout reports a bad Registry hive
  signature and stack trace text.
- Missing output directory with invalid input: exit code `0`; the invalid input
  failed before output creation, and the missing directory was not created.

Limitations:

- No real `Amcache.hve` was parsed during this research PR.
- Exact CSV columns and generated file naming must be confirmed with later
  synthetic fixtures.
- Wrappers must create the output directory before invocation and must not rely
  on exit code alone.

Implementation recommendation for issue #26:

- Resolve `AmcacheParser` through configuration or environment override,
  defaulting to `PATH`.
- Execute through the M1 safe runner without `shell=True`.
- Preserve stdout/stderr under `runs/<case_id>/logs/`.
- Treat bad-signature text, stack trace text, or missing expected CSV output as
  failure even when the process exit code is `0`.

## Supporting Tools Not Selected

- `rip.pl`: installed RegRipper CLI, useful as a fallback/reference for registry
  and Amcache plugins, but not selected because RECmd and AmcacheParser are more
  specific for M2 structured wrapper output.
- `log2timeline.py`: installed plaso timeline tool, version `20260119`, but not
  selected because M2 needs narrow artifact parser wrappers.
- `psort.py`: installed plaso post-processing tool, version `20260119`, but not
  selected because it depends on broader plaso timeline workflows.
- `fls`, `icat`, `mmls`, and `fsstat`: installed Sleuth Kit tools, useful for
  filesystem/image support but not primary parsers for the three M2 artifacts.
- `ewfmount` and `xmount`: installed image mounting/conversion support, not
  parser wrappers for M2 artifacts.
- `fiwalk`: installed filesystem metadata extraction support, not selected for
  the narrow M2 parser wrappers.
- `EvtxECmd`: installed at `/usr/local/bin/EvtxECmd`, but EVTX parsing is future
  reference only and outside this M2 scope.
- `regipy`: not found as a command or importable Python package in this VM.
- `mono`: not found on `PATH`; not required for the selected .NET wrapper scripts.

## Failure Behavior Summary

| Tool | Missing input | Invalid input | Missing output directory | Exit code behavior | stderr/stdout behavior | Wrapper requirement |
|---|---|---|---|---|---|---|
| MFTECmd | stdout says file not found | stdout says unknown file type | Not created when invalid input failed first | Returned `0` for tested failures | Errors were on stdout; stderr empty | Parse stdout and expected output files; do not rely on exit code alone |
| RECmd | stdout says file does not exist | stdout says bad Registry hive signature | Not created when invalid input failed first | Returned `0` for tested failures | Errors were on stdout; stderr empty in tested failures | Parse stdout and expected output files; one audited command per hive/key |
| AmcacheParser | stdout says file not found | stdout says bad Registry hive signature and emits stack trace text | Not created when invalid input failed first | Returned `0` for tested failures | Errors were on stdout; stderr empty in tested failures | Parse stdout and expected output files; treat stack traces as parser failure |
| RegRipper `rip.pl` | Plugin banner on stdout and plugin error on stderr | Plugin banner on stdout and plugin error on stderr | Not applicable; stdout-oriented tool | Returned `0` for tested failures | stderr contained plugin errors | Keep as fallback/reference; selected wrappers should prefer RECmd/AmcacheParser |

Future parser wrappers must map nonzero exits to failed parser results. Absent
parser commands must become skipped or failed parser results with clear reasons.
Malformed or absent parser output must produce warnings or failure status,
depending on the parser contract. stdout/stderr paths must be preserved under
`runs/`, and the audit ledger must capture command, exit code, duration,
stdout/stderr paths, and hashes where applicable.

## M2 Implementation Decisions

- `$MFT` wrapper should use `MFTECmd`.
- Registry Run Key wrapper should use `RECmd` direct `--kn` lookups for
  `SOFTWARE` and `NTUSER.DAT` Run/RunOnce keys.
- Amcache wrapper should use `AmcacheParser`.
- Parser command resolution should be configurable through environment or local
  config, not hardcoded to private paths.
- Parser output paths must remain under:
  - `runs/<case_id>/parsers/<parser_name>/`
  - `runs/<case_id>/logs/`
  - `runs/<case_id>/normalized/`

## Open Assumptions

- This PR did not parse real evidence or generated fixture hives.
- Exact output columns and generated filenames remain pending synthetic fixture
  tests during wrapper implementation.
- Missing-output-directory behavior with valid artifacts remains pending fixture
  tests; wrappers should create output directories before invoking tools.
- RECmd batch/plugin selection remains direct `--kn` by default; broader RECmd
  batch examples are future reference only.
- Transaction log policy for dirty registry hives should be finalized during
  parser contract work.

## Evidence Safety

- Raw local discovery logs remain under `runs/tool_research/`.
- `runs/` is gitignored.
- No raw evidence is committed.
- No generated parser output is committed.
- Private paths, usernames, hostnames, evidence names, case names, and secrets
  are omitted or generalized.
- This document contains sanitized command templates only.
