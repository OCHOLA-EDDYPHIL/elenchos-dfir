# Elenchos Case Console

`elenchos tui` provides the analyst-facing terminal console for a case run. The
normal analyst workflow is to start the console with no flags, type a natural
language case request, and let Elenchos create the generated run context.

```bash
elenchos tui
```

Inside the console:

```text
Elenchos> Triage the ROCBA case and tell me what happened.
```

After the analyst submits a prompt, the console creates a generated run
directory under `runs/`, wraps the analyst request with Elenchos safety and
output constraints, launches OpenClaw, and watches generated Elenchos artifacts
under that run directory.

The console displays:

- live rationale from `model_rationale.jsonl`
- policy gate decisions from `policy_decisions.jsonl`
- run status from `run_job.json` and `progress.jsonl`
- validation status from `validation_summary.json`
- finding and case-question counts from generated JSON outputs
- final summary and claim-boundary wording from generated Elenchos artifacts

The TUI does not inspect raw evidence. Model rationale and TUI text are not
forensic evidence. Deterministic Elenchos outputs remain the evidence authority.

CLI flags are advanced/debug options. For example, an operator can provide a
source root or case identifier explicitly:

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

Elenchos wraps the analyst prompt with runtime constraints: use only bounded
Elenchos tools, keep raw evidence read-only, use the exact generated output
directory, write generated outputs only under that directory, use the
`prepared_manifest_path` produced by `prepare_case`, show live rationale and
policy gate progress through generated artifacts, and finish with supported
findings, unsupported gaps, claim boundary, and trace paths.

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
- `run_context.json`

When the selected output directory is under an ignored generated-output root,
the console may write `case_console_transcript.md`. That transcript mirrors the
TUI-visible rationale and policy stream and is not forensic evidence.

This behavior belongs in the repository runtime and guidance, not in `.skills`:
`AGENTS.md` carries repo-level agent/developer guidance, the TUI runtime wraps
analyst prompts with safety/output constraints, the MCP/tool policy enforces
hard boundaries, and generated JSONL artifacts provide auditability.
