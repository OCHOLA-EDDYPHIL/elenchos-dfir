# Limitations

## Scope Limitations

- Parser validation covers parser mechanics, not complete incident response.
- The correlation and finding layer is future work.
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

## Evidence and Reproducibility Limits

- Raw evidence is local-only and not committed.
- Private paths are redacted from committed docs.
- Validation can be repeated only by users with equivalent local evidence and
  SIFT tooling.
