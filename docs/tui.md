# Elenchos Case Console

`elenchos tui` provides the analyst-facing terminal console for a case run. The
console accepts a high-level case prompt, launches OpenClaw, and watches
generated Elenchos artifacts under a run directory.

The console displays:

- live rationale from `model_rationale.jsonl`
- policy gate decisions from `policy_decisions.jsonl`
- run status from `run_job.json` and `progress.jsonl`
- validation status from `validation_summary.json`
- finding and case-question counts from generated JSON outputs
- final summary and claim-boundary wording from generated Elenchos artifacts

The TUI does not inspect raw evidence. Model rationale and TUI text are not
forensic evidence. Deterministic Elenchos outputs remain the evidence authority.

Start a new case console run:

```bash
elenchos tui --source-root /mnt/evidence/rocba --case-id rocba-demo
```

Watch an existing generated run:

```bash
elenchos tui --watch-only --output-dir runs/<case>
```

Use one-shot text mode for non-interactive checks:

```bash
elenchos tui --watch-only --output-dir runs/<case> --once
```

The default prompt tells OpenClaw to use only bounded Elenchos tools, keep raw
evidence read-only, use the `prepared_manifest_path` produced by `prepare_case`,
and finish with supported findings, unsupported gaps, claim boundary, and trace
paths.

Generated files read by the console include:

- `model_rationale.jsonl`
- `policy_decisions.jsonl`
- `run_job.json`
- `progress.jsonl`
- `report.md`
- `findings.json`
- `case_questions.json`
- `gap_analysis.json`
- `validation_summary.json`

When the selected output directory is under an ignored generated-output root,
the console may write `case_console_transcript.md`. That transcript mirrors the
TUI-visible rationale and policy stream and is not forensic evidence.
