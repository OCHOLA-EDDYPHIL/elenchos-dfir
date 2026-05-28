# FIND EVIL Devpost Submission Compliance Checklist

## Purpose

Use this checklist before final Devpost submission to confirm that the
repository, documentation, demo, audit trail, and release snapshot are
submission-ready. SIFTGuard MCP is triage / analyst-assist validation tooling.
It is not external evidence certification and does not turn parser observations
into proof of compromise by itself.

## Final Release Record

| Item | Final value |
| --- | --- |
| Release tag | `<pending>` |
| Commit hash | `<pending>` |
| Devpost project URL | `<pending>` |
| Public demo video URL | `<pending>` |
| Reviewer | `<pending>` |
| Review date | `<pending>` |

## Required Submission Checks

| Check | Pass/fail requirement | Repo evidence | Final state |
| --- | --- | --- | --- |
| Public repository readiness | Repository is public, source is available, and final Devpost links target the intended branch, commit, or tag. | GitHub repository and final release record above. | `[ ]` |
| License visibility | MIT or Apache 2.0 license is visible at repository root. | `LICENSE`, `README.md#license`. | `[ ]` |
| README setup path | README includes clean local setup commands and the expected development checks. | `README.md#quick-start-local-development`. | `[ ]` |
| Local run instructions | README documents parser, correlation, validation, and agent workflow run paths using local evidence placeholders. | `README.md#parser-workflow`, `README.md#correlation-and-validation-workflow`, `README.md#agent-workflow`. | `[ ]` |
| SIFT/Linux terminal compatibility | Submission path runs from a Linux/SIFT-compatible terminal and uses documented SIFT parser tooling. | `README.md`, `docs/parser-tooling-matrix.md`, `docs/parser-validation.md`. | `[ ]` |
| Agentic runtime explanation | Agent runtime is documented as plan, execute, verify, correct, report, with OpenClaw as constrained orchestration over SIFTGuard commands. | `docs/agent-workflow.md`, `docs/openclaw.md`, `docs/openclaw-agent-workflow.md`. | `[ ]` |
| Protocol SIFT / MCP integration explanation | Typed MCP/schema boundaries and SIFT tool integration are described without exposing arbitrary shell execution. | `docs/architecture.md`, `docs/parser-contracts.md`, `docs/security-boundaries.md`. | `[ ]` |
| Self-correction demonstration | Demo and logs show at least one detected failure, downgrade, retry, or correction with the result recorded. | `docs/demo.md`, `docs/demo-script.md`, `docs/agent-workflow.md`, generated local run logs. | `[ ]` |
| Accuracy validation | Accuracy report records confirmed, inferred, rejected, and needs-review findings, plus false positives, misses, and unsupported claims. | `docs/accuracy-report.md`, `docs/parser-validation.md`. | `[ ]` |
| Secondary dataset validation | If suitable secondary evidence is available, repeat validation and record false positives, missed artifacts, and unsupported claims; lack of suitable secondary evidence is noted but not a blocker. | `docs/accuracy-report.md`, final checklist notes. | `[ ]` |
| Structured investigative narrative | Final report distinguishes observations, validated findings, inferences, rejected claims, and analyst-review items. | Generated `report.md` under local `runs/`, `docs/agent-workflow.md`, `docs/limitations.md`. | `[ ]` |
| Architecture diagram | Final architecture diagram shows agent, typed MCP/tool layer, SIFT tools, evidence inputs, audit ledger, validation, and reports. | `docs/architecture.md`. | `[ ]` |
| Evidence dataset documentation | Dataset docs identify staged artifact classes, local path placeholders, raw evidence policy, and expected demo scope. | `docs/dataset.md`. | `[ ]` |
| Accuracy report | Final accuracy report is completed for the demo case and does not claim perfection. | `docs/accuracy-report.md`. | `[ ]` |
| Structured execution logs | Sanitized log examples or regeneration instructions show timestamps, tool sequence, status, duration, outputs, and errors. | Local `runs/` outputs, `docs/parser-validation.md`, final execution-log package. | `[ ]` |
| Demo video length | Public demo video is under five minutes. | Devpost video link or final release record above. | `[ ]` |
| Live terminal execution | Demo video shows live terminal execution, not slides, including self-correction and final output review. | Public demo video. | `[ ]` |
| Evidence integrity and read-only handling | Raw evidence stays outside the repository, mounted or staged read-only, with generated outputs written under ignored paths. | `README.md#evidence-safety-summary`, `docs/dataset.md`, `docs/security-boundaries.md`. | `[ ]` |
| Finding traceability | Every final finding traces to evidence references and a specific tool execution or validated pipeline step. | Generated `findings.json`, `audit.jsonl`, `agent_run.json`, `report.md`. | `[ ]` |
| Secret and private data hygiene | No secrets, private evidence, generated raw parser outputs, private paths, hostnames, usernames, tokens, VM files, or disk images are committed. | `.gitignore`, `docs/dataset.md`, final hygiene gate output. | `[ ]` |
| Third-party tool/license notes | Third-party SIFT tools, Python dependencies, and runtime assumptions are documented; no incompatible third-party assets are committed. | `pyproject.toml`, `docs/parser-tooling-matrix.md`, `docs/openclaw.md`. | `[ ]` |
| AI-assisted development compliance | Final write-up notes that the work is original/substantially new for the event and that AI-assisted work was reviewed by the maintainer. | Devpost write-up draft and final submission notes. | `[ ]` |
| Final hygiene gates | `git diff --check`, tests, Ruff, Mypy, link checks if available, and secret/evidence review have been run and recorded. | Issue #94 output and final release record. | `[ ]` |

## Evaluation Criteria Mapping

| Evaluation criterion | Evaluation target | Where this repo demonstrates it | Remaining final check |
| --- | --- | --- | --- |
| Autonomous execution quality | The agent plans, executes constrained steps, verifies outputs, handles failures, and records self-correction without broad shell authority. | `docs/agent-workflow.md`, `docs/openclaw-agent-workflow.md`, generated `agent_run.json`, generated `audit.jsonl`. | Demo video and packaged logs show one successful path and one self-correction path. |
| IR accuracy | Findings are evidence-backed, unsupported claims are rejected or downgraded, and false positives / missed artifacts are recorded honestly. | `docs/accuracy-report.md`, `docs/parser-validation.md`, generated `findings.json`, generated `report.md`. | Complete final accuracy report for the demo case; add secondary dataset notes if suitable evidence is available. |
| Breadth/depth of analysis | Depth stays focused on Windows disk artifacts instead of shallow expansion into unsupported domains. | `docs/dataset.md`, `docs/parser-tooling-matrix.md`, `docs/limitations.md`. | Confirm final docs keep scope to MFT, Registry Run Keys, and Amcache. |
| Constraint implementation | Guardrails are architectural: typed schemas, constrained argv execution, evidence-root boundaries, and local-only generated outputs. | `docs/architecture.md`, `docs/security-boundaries.md`, `docs/parser-contracts.md`. | Confirm README and demo avoid broad shell or unsupported tool claims. |
| Audit trail quality | Each finding can be traced from report to finding object, evidence reference, tool execution, and audit log entry. | Generated `audit.jsonl`, `findings.json`, `report.md`, `docs/agent-workflow.md`. | Package sanitized logs or regeneration instructions and verify each final finding maps to a log entry. |
| Usability/documentation | A practitioner can install, stage evidence, run the workflow, understand outputs, and see limitations without guessing. | `README.md`, `docs/dataset.md`, `docs/demo-script.md`, `docs/limitations.md`. | Review README links, final checklist, and demo script before release. |

## Final Go/No-Go Checklist

- [ ] README reviewed.
- [ ] Architecture diagram linked.
- [ ] Dataset documentation complete.
- [ ] Accuracy report complete.
- [ ] Execution logs packaged and sanitized.
- [ ] Demo script complete.
- [ ] Demo video recorded and public.
- [ ] Repo hygiene gate passed.
- [ ] Release tag created.
- [ ] Devpost write-up ready.
- [ ] Public repo visibility confirmed.

## Final Hygiene Commands

Run these from the repository root before final submission and paste the output
into the release hygiene issue:

```bash
git status --short
git diff --check
.venv/bin/python -m pytest
.venv/bin/python -m ruff check .
.venv/bin/python -m mypy src
```

If a command fails because local dependencies or SIFT tooling are unavailable,
record the exact failure and do not mark that gate as passed.
