# Sanitized Log Excerpts

These files are small excerpts from real generated Elenchos logs. They are
intended to show execution traceability without committing raw evidence, raw
OpenClaw sessions, parser dumps, private paths, or provider logs.

Included excerpts:

- `rocba-model-rationale.sample.jsonl`
- `rocba-policy-decisions.sample.jsonl`
- `rocba-validation-summary.sample.json`
- `caseless-model-rationale.sample.jsonl`
- `caseless-policy-decisions.sample.jsonl`
- `caseless-orchestration-finalization.sample.json`
- `caseless-validation-summary.sample.json`

No ROCBA finalization excerpt is included because the local ROCBA run did not
contain a real `orchestration_finalization.json` artifact.

Token usage is documented in `../agent-execution-logs.md` as aggregate counts
from local OpenClaw trajectory files. Raw OpenClaw trajectory and session files
are not included here.

Redaction convention:

- `$REPO_ROOT` replaces absolute repository paths.
- `$RUN_DIR` replaces run-directory paths where useful.
- `$EVIDENCE_ROOT` replaces local evidence roots.
- `$HOME` replaces home-directory paths.

