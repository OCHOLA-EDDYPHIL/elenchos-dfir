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
- policy gate decisions from `policy_decisions.jsonl`; adjacent duplicate
  visible decisions are collapsed in the display only, while the raw JSONL audit
  file remains complete
- run status from `run_job.json` and `progress.jsonl`
- validation status from `validation_summary.json`
- finding and case-question counts from generated JSON outputs
- self-correction status when deterministic Elenchos artifacts record
  unsupported claim/tool-path correction
- final summary and claim-boundary wording from generated Elenchos artifacts

The TUI does not inspect raw evidence. Model rationale and TUI text are not
forensic evidence. Deterministic Elenchos outputs remain the evidence authority.
Model rationale is not self-correction. Self-correction means an unsupported or
invalid claim/tool path was detected and downgraded or recovered in generated
trace artifacts.

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

The prompt editor is designed for immediate analyst input. The
`--refresh-seconds` option controls how often the console rereads generated
Elenchos artifacts; it does not control typing latency.

Elenchos wraps the analyst prompt with runtime constraints: use only bounded
Elenchos tools, keep raw evidence read-only, use the exact generated output
directory, write generated outputs only under that directory, use the
`prepared_manifest_path` produced by `prepare_case`, show live rationale and
policy gate progress through generated artifacts, and finish with supported
findings, unsupported gaps, claim boundary, and trace paths.

Generated files read by the console include:

- `model_rationale.jsonl`
- `policy_decisions.jsonl`
- `self_correction_events.json`
- `self_correction_events.jsonl`
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

`prepare_case` may take time on large evidence sets. The adapter keeps parser
execution bounded, but case preparation has a long configurable timeout and
writes `prepare_case` progress records so the console can show activity instead
of looking frozen.

Synthetic self-correction smoke check:

```bash
.venv/bin/python scripts/self_correction_smoke.py
```

The smoke uses controlled fixture data only. It does not require ROCBA evidence,
SIFT parsers, or OpenClaw credentials.

This behavior belongs in the repository runtime and guidance, not in `.skills`:
`AGENTS.md` carries repo-level agent/developer guidance, the TUI runtime wraps
analyst prompts with safety/output constraints, the MCP/tool policy enforces
hard boundaries, and generated JSONL artifacts provide auditability.
