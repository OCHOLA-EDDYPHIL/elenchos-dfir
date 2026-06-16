# Devpost Submission Checklist

## Execution Logs

- Agent execution log documentation: `docs/submission/agent-execution-logs.md`
- Sanitized log excerpts: `docs/submission/log-excerpts/`
- ROCBA run path documented: `runs/case-20260615-133435`
- Caseless run path documented: `runs/caseless-windows-disk-20260615-145428`
- OpenClaw trajectory token usage documented from local aggregate records.

## Safety Checks

- Do not commit raw evidence.
- Do not commit full `runs/` directories.
- Do not commit raw OpenClaw session logs.
- Do not commit parser dumps.
- Keep excerpts small and sanitized.
- Redact absolute local paths to `$REPO_ROOT`, `$RUN_DIR`, `$EVIDENCE_ROOT`, or `$HOME`.

## Manual Items

- Confirm the final repository URL in the Devpost form.
- Confirm the Vimeo demo link in the Devpost form.

