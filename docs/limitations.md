# Limitations

## Scope Limitations

- Parser validation covers parser mechanics, not complete incident response.
- Correlation and finding support is intentionally narrow: drop, persistence,
  and execution signals from the supported Windows disk artifacts.
- Memory forensics is out of scope for the parser workflow.
- Validation used local evidence subsets, not exhaustive enterprise coverage.

## Artifact Interpretation Limits

### `$MFT`

MFT parsing can show filesystem metadata observations such as names, paths,
timestamps, and record metadata. It cannot alone establish user intent,
maliciousness, or compromise.

### Registry Run Keys

Run Key parsing can show autostart registry values. These observations can
support later analysis, but they cannot alone establish malicious persistence.

### Amcache

Amcache parsing can show application compatibility cache observations. These
observations can support later application presence or activity analysis, but
they cannot alone establish execution, user action, or maliciousness.

## Tool Behavior Limits

- Output depends on MFTECmd, RECmd, AmcacheParser behavior, and input artifact
  quality.
- Dirty hives, missing fields, and parser-specific output shapes can produce
  `partial_success`.
- Parser warnings should be preserved, not hidden.
- Large raw artifacts can exceed available VM memory if every normalized event
  is loaded for one run. The documented final demo path uses
  `--max-normalized-events` with `--event-selection-profile forensic-triage`;
  bounded outputs are reproducible but are not exhaustive full-artifact
  analysis.
- Resource-adaptive triage prioritizes available Registry and Amcache events,
  then selects high-volume MFT observations by deterministic path, anchor-time,
  and fill rules. The selection policy is coverage triage, not a malware
  detection rule.
- Ordinary single-source MFT timelines remain timeline and coverage evidence.
  They are not findings unless correlation or validation rules create a
  supportable candidate.
- The agent planner is deterministic and uses fixed workflow phases; it is not
  a free-form LLM planning surface.
- Markdown is the human-readable report. Machine-readable outputs are workflow
  artifacts such as `findings.json`, `agent_run.json`, and `audit.jsonl`, not a
  separate standalone JSON report renderer.
- The active permission policy is a minimal declaration of read-only evidence
  posture, output-path constraints, and no arbitrary shell as the agent
  interface. It should not be described as comprehensive sandboxing.

## Evidence and Reproducibility Limits

- Raw evidence is local-only and not committed.
- Private paths are redacted from committed docs.
- Validation can be repeated only by users with equivalent local evidence and
  SIFT tooling.
