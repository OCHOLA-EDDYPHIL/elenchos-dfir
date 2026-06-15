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

The UI is keyboard-driven and prompt-first. The main screen uses compact
panes for the analyst prompt, live rationale, policy gate, self-correction,
run status, and final summary or claim-boundary/log output. Wide terminals use
a two-column middle layout; narrow terminals stack the panes.

Keyboard controls:

- `Tab` / `Shift-Tab` or left/right: change focused pane
- up/down or `k`/`j`: scroll the focused pane
- `PgUp` / `PgDn`: page the focused pane
- `Home` / `End`: jump within the focused pane
- `r`: refresh generated artifacts
- `q`: quit

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

Colors and borders are cosmetic only. Color terminals use muted pane borders,
one active-pane accent, and textual status badges. No-color terminals,
`NO_COLOR`, `TERM=dumb`, and ASCII borders via `ELENCHOS_TUI_ASCII=1` remain
readable because statuses are rendered as text labels such as `PASS`, `FAIL`,
`ALLOWED`, `REJECTED`, `OBSERVED`, and `PENDING`.

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

Before recording or demonstrating an OpenClaw run, configure an explicit plugin
allowlist through `plugins.allow`. Disable or explicitly exclude non-required
non-bundled plugins unless they are part of the active runtime path. The runtime
path should use bounded Elenchos tools only.
`scripts/demo_elenchos_preflight.py` reports this as a non-fatal warning so the
operator can remediate local OpenClaw configuration before recording.

The prompt editor is designed for immediate analyst input. The
`--refresh-seconds` option controls how often the console rereads generated
Elenchos artifacts; it does not control typing latency. Typing uses a short
input poll interval and does not reread generated files, create the output
directory, or write `run_context.json` until the prompt is submitted.

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

The policy gate pane may collapse adjacent repeated visible policy messages for
readability. The raw `policy_decisions.jsonl` audit file is not deduplicated or
rewritten. Self-correction is shown only when generated self-correction
artifacts contain events. While a run or validation is still pending, or before
the self-correction artifacts have been checked, the console displays
`PENDING`. It displays `NONE` only after the run and validation are complete and
the checked self-correction artifacts contain no events.

`prepare_case` may take time on large evidence sets. It does not use a short
artificial adapter timeout by default; set
`ELENCHOS_PREPARE_TIMEOUT_SECONDS` in constrained environments when a prepare
runtime cap is required. Parser execution remains separately bounded, and
prepare writes `prepare_case` progress records so the console can show activity
instead of looking frozen.

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
