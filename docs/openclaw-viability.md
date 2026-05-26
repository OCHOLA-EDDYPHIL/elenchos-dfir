# OpenClaw Runtime Viability

## Purpose

This spike evaluates OpenClaw as the M4 runtime path for locally initiating
constrained SIFTGuard agent workflows. OpenClaw is preferred for M4 because
Claude Code subscription access is not assumed, but runtime-specific
integration must not begin until the local runtime path is proven.

## Decision

**blocked**

OpenClaw is viable in principle for a local CLI-driven spike path, but this
environment cannot prove it yet:

- `openclaw` is not installed on `PATH`.
- Local Node.js is `v18.19.1`, below the documented OpenClaw requirement.
- No model provider credential is available or should be committed.
- `siftguard agent run` does not exist until the deterministic runner issue is
  implemented.

Proceed with deterministic Python agent work independently. Revisit OpenClaw
integration only after OpenClaw is installed with a supported Node runtime and a
model provider credential is available outside the repository.

## Environment Assumptions

- OS / SIFT compatibility: OpenClaw documents Linux support, so a SIFT
  Workstation VM or Linux host is a plausible target environment.
- Node.js: OpenClaw documents Node 24 as recommended and Node 22.19+ as
  supported. The local environment currently has Node `v18.19.1`, so it does
  not meet that requirement.
- Runtime: OpenClaw setup uses `openclaw onboard` or equivalent setup commands
  to configure the local runtime, workspace, Gateway, and provider settings.
- Model provider: OpenClaw onboarding requires a model provider credential such
  as an Anthropic, OpenAI, Google, or equivalent provider API key. Credentials
  must stay outside git.
- Network: installation, package download, and provider-backed model calls
  require network access unless a future local provider path is configured.
- Demo path: the intended SIFTGuard demo path is local-only and should not
  require Discord, Slack, Telegram, WhatsApp, or any other remote messaging
  channel.

Reference documentation:

- <https://docs.openclaw.ai/install>
- <https://docs.openclaw.ai/start/getting-started>
- <https://docs.openclaw.ai/cli/agent>
- <https://docs.openclaw.ai/tools/exec>
- <https://docs.openclaw.ai/tools/exec-approvals>

## Install Notes

Safe setup target for a Linux/SIFT-compatible host:

```bash
node --version
npm --version
```

If Node is below the documented requirement, install a supported Node version
outside the repository first. Then install OpenClaw by following the official
installer or npm path from the OpenClaw install documentation.

Example command shape, not executed in this spike:

```bash
npm install -g openclaw@latest
openclaw onboard
openclaw gateway status
```

Do not commit OpenClaw configuration, credentials, shell history, provider
tokens, local transcripts, or account-specific output.

## Minimal Local Test

The smallest safe local test for a future environment is:

```bash
openclaw --version
openclaw agent --local "In this repository, run only a controlled help check: .venv/bin/python -m siftguard --help"
```

Expected proof points:

- OpenClaw starts successfully.
- OpenClaw can run a local prompt against the repository or a controlled local
  task.
- OpenClaw can be instructed to use constrained SIFTGuard CLI entrypoints.
- OpenClaw can invoke `.venv/bin/python -m siftguard --help` as a controlled
  non-evidence command.

Local result for this spike:

- `openclaw` was not available on `PATH`.
- Node was `v18.19.1`, below the documented requirement.
- `.venv/bin/python -m siftguard --help` works as the current constrained
  SIFTGuard command surface.
- The future `siftguard agent run` command is not available until the
  deterministic runner issue is implemented.

Because OpenClaw could not be started locally, this spike did not prove local
prompt execution or OpenClaw command invocation.

## Intended M4 Integration Pattern

OpenClaw should initiate or supervise constrained SIFTGuard entrypoints, not raw
forensic shell commands.

Desired future shape:

```text
OpenClaw prompt
  -> constrained local command/tool
  -> siftguard agent run
  -> AgentRun JSON
  -> audit JSONL
  -> findings/report outputs
```

OpenClaw may be useful as an operator-facing runtime once the deterministic
agent runner exists. The Python runner must remain independently useful so M4
does not depend on OpenClaw availability.

## Security Boundary

- OpenClaw prompts must not include raw evidence contents.
- OpenClaw should not receive direct raw evidence paths as its primary context.
- OpenClaw must not be the broad forensic shell interface.
- The submitted forensic interface should be constrained SIFTGuard commands.
- Evidence stays read-only.
- Generated outputs stay under ignored run paths such as `runs/`.
- OpenClaw transcripts, session state, and provider responses stay
  ignored/local-only unless deliberately sanitized.
- Provider credentials, tokens, API keys, shell history, account identifiers,
  and local private paths must not be committed.

OpenClaw documents an `exec` tool that can run shell commands in the workspace.
That is a mutating host surface. Exec approvals and allowlists are useful
guardrails, but SIFTGuard should still constrain the forensic workflow through
typed local entrypoints rather than granting broad shell authority.

## Risks

- Host filesystem access: OpenClaw tools may be able to read or modify files
  allowed by the host or sandbox.
- Evidence write risk: a poorly constrained prompt or command could write to
  evidence paths if the host exposes them writable.
- Prompt injection: repository, transcript, or generated-output text could
  influence the runtime toward unsafe commands.
- Provider/API availability: a model provider credential and network access are
  required for the normal OpenClaw path.
- Model hallucination: the model may claim a SIFTGuard step ran or succeeded
  when it did not.
- Transcript leakage: transcripts may contain prompts, paths, provider details,
  or case context if not kept local and sanitized.
- Arbitrary shell misuse: OpenClaw `exec` is powerful enough to run broad host
  commands unless constrained by policy, allowlists, and SIFTGuard design.

## Outcome

**Blocked until prerequisites are available.**

OpenClaw remains a reasonable candidate for M4, but this repository should not
start OpenClaw integration yet. The immediate path is:

1. Implement the deterministic `siftguard agent run` workflow independently.
2. Install OpenClaw in a Linux/SIFT-compatible environment with Node 24 or
   Node 22.19+.
3. Configure a provider credential outside the repository.
4. Prove OpenClaw can run a local prompt and invoke only constrained SIFTGuard
   commands.
5. Proceed to integration only after those proof points pass.
