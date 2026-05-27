# OpenClaw Runtime Viability

## Scope

This spike evaluates OpenClaw as the M4 runtime path for locally initiating
constrained SIFTGuard agent workflows. It is a runtime viability proof only.
It does not implement verifier logic, self-correction policy, OpenClaw adapter
code, or new SIFTGuard features.

The intended M4 integration target remains the deterministic local runner:

```text
OpenClaw prompt
  -> constrained local command/tool
  -> siftguard agent run
  -> AgentRun JSON
  -> audit JSONL
  -> findings/report outputs
```

## Environment

- Runtime host: SIFT Workstation/dev VM class environment.
- OS family: Ubuntu 24.04 LTS.
- System Node before this proof: `v18.19.1`, below OpenClaw's documented
  supported runtime range.
- OpenClaw local-prefix Node after install: `v22.22.0`.
- npm under local-prefix Node: `10.9.4`.
- OpenClaw version after install: `OpenClaw 2026.5.22 (a374c3a)`.
- Python gate environment: project `.venv` using the existing repository test
  setup.

Reference documentation used:

- <https://docs.openclaw.ai/install>
- <https://docs.openclaw.ai/install/node>
- <https://docs.openclaw.ai/cli/models>
- <https://docs.openclaw.ai/gateway>

## Install Result

**Installed with local-prefix/user-level scope.**

- Installer: official `install-cli.sh`, saved and inspected before execution.
- Install prefix: user-level OpenClaw prefix.
- Runtime installed by the OpenClaw installer: Node `v22.22.0`.
- Shell startup was updated to prepend OpenClaw's local-prefix Node and
  OpenClaw CLI directories for future shells.
- No repository-local install was used.
- No `sudo` was used.
- No system Node upgrade was performed.
- No OpenClaw state, installer logs, transcripts, or runtime output files are
  committed.

## Auth Result

**Provider auth is proven for OpenClaw.**

- OpenAI/Codex browser OAuth and device-code auth were used as the explicit
  last-resort OpenClaw auth path authorized by the maintainer.
- Auth was performed through OpenClaw's own `openai-codex` provider flow.
- ChatGPT/OpenAI browser auth was used only for OpenClaw, not for Codex CLI.
- Existing enterprise Codex/Azure OpenAI setup outside this repository was
  preserved and not inspected, printed, copied, imported, or modified.
- Existing Codex CLI config metadata hash stayed unchanged.
- The shell startup file changed only because the maintainer requested a
  permanent OpenClaw PATH update.
- OpenClaw default model was set to `openai/gpt-5.5` in OpenClaw-owned
  user-level config.
- OpenClaw config validation passed after auth and workspace configuration.
- The model smoke authenticated successfully through OpenClaw and returned the
  expected phrase.
- No credentials, API keys, provider tokens, account identifiers, device codes,
  private endpoints, or OAuth material are committed.

## Smoke Results

| Check | Result |
| --- | --- |
| `openclaw --version` | passed |
| local-prefix `node -v` | passed: `v22.22.0` |
| `openclaw doctor --fix` | passed |
| `openclaw config validate` | passed |
| `openclaw models status` | passed as a status command |
| `openclaw models list --provider openai-codex` | bounded timeout; non-critical because model execution passed |
| `openclaw infer model run ... openai/gpt-5.5 ...` | passed; returned `openclaw-smoke-ok` |
| ad-hoc loopback gateway `status --require-rpc` | passed after loopback start |
| `.venv/bin/python -m siftguard --help` | passed |
| `.venv/bin/python -m siftguard agent run --help` | passed |
| OpenClaw-controlled `siftguard agent run --help` invocation | passed; OpenClaw reported command exit code `0` |

The gateway smoke used an ad-hoc loopback process on the local host and stopped
it after the check. No daemon install or remote messaging channel was required
for this proof. The OpenClaw-controlled SIFTGuard invocation used a local agent
session and constrained task text that instructed OpenClaw to run only the
SIFTGuard help command and avoid evidence or secrets.

## Security And Evidence Safety

- No real evidence files were touched.
- No parser outputs were generated or committed.
- No OpenClaw transcripts, gateway logs, installer logs, or runtime state files
  were committed.
- No credentials, tokens, device codes, OAuth material, private endpoints,
  account identifiers, hostnames, usernames, shell history, or private paths are
  committed.
- Smoke outputs were kept under a temporary directory outside the repository.
- The OpenClaw gateway check was loopback/ad-hoc only.
- OpenClaw must not receive raw evidence contents or direct raw evidence prompts.
- OpenClaw must not become the broad forensic shell interface.
- The submitted forensic workflow should remain constrained to SIFTGuard
  commands such as `siftguard agent run`.
- OpenClaw remains a runtime orchestrator over constrained SIFTGuard commands,
  not the forensic engine.

## Final Viability Classification

**ready-for-integration**

OpenClaw is now installed locally with a supported local-prefix Node runtime,
the OpenClaw config validates, the ad-hoc loopback gateway can satisfy the
`--require-rpc` status check, and the constrained SIFTGuard agent command is
visible through CLI help.

The runtime is ready for a later integration issue because OpenClaw auth,
provider-backed model execution, gateway RPC status, direct SIFTGuard CLI help,
and OpenClaw-controlled invocation of the constrained SIFTGuard help command all
passed without committing evidence, credentials, transcripts, runtime state, or
private paths.

## Next Recommended Issue

Proceed to #65, `Add verification checks for agent outputs`, before runtime
adapter work. OpenClaw integration should wait until the deterministic verifier
and self-correction policy are in place, then use OpenClaw only to initiate or
supervise constrained SIFTGuard commands.
