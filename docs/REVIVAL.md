# Revival Conditions

Elenchos should remain archived until every prerequisite below is available.

## Required Inputs

- A reproducible SIFT workstation, container, or equivalent forensic runtime.
- Legally usable, publishable evidence with documented ground truth.
- A sealed holdout not exposed to runtime prompts or casebooks.
- Time for independent clean-room reproduction.
- A concrete user or competition whose acceptance criteria justify the work.

If any item is absent, do not make new forensic-accuracy or real-case autonomy
claims.

## Current vNext Status

The `vnext/claude-code-autonomy` work is an experimental control-plane and audit
prototype. Its committed demonstration is a synthetic replay, not a blind
forensic evaluation.

Known gaps to resolve before describing it as adaptive autonomy:

- Provider prompts and runtime state do not consistently expose the same
  bounded action vocabulary.
- Prior action names are available to the provider, but complete typed outcomes,
  verifier failures, coverage gaps, and retry budgets are not.
- The example replay scripts the expected verification and correction sequence.
- The documented replay is coupled to the fixture's expected case identity; a
  mismatched case ID can stop with exit code zero despite no correction,
  `verification_status=None`, and an unresolved trace map.
- Some autonomy actions are recorded through aliases rather than their exact
  semantics.
- Terminal stop is not universally conditioned on completed validation.
- Trace-map resolution can accept weak, hash-free joins rather than exact
  artifact-to-execution-to-event-to-claim provenance.
- Provider failures, iteration exhaustion, resume, idempotency, case locking,
  and circuit breaking need production semantics.
- Casebook and forensic event-selection options are not fully propagated through
  the autonomy path.
- No blind benchmark runner or gold-label schema exists.

## Proposed Product Wedge

Build a proof-carrying claim layer rather than expanding parser breadth first.
The required provenance chain is:

```text
report claim
-> finding id
-> exact normalized event ids
-> exact parser execution id and output rows
-> prepared artifact id and SHA-256
-> source manifest and run-integrity manifest
```

The verifier must test semantic predicates for each supported claim type. The
existence of a citation or tool-call ID is not sufficient.

## Minimum Revival Gates

The project may leave experimental status only when all of these pass:

- zero unsupported `confirmed` or `inferred` findings;
- 100% exact provenance resolution for supported claims;
- 100% safe halt on unrecoverable or policy-rejected actions;
- repeatable recovery from parser failure, missing output, unsupported elevated
  finding, and report/trace mismatch;
- independently reviewed accuracy results on a sealed evidence suite;
- a fresh-machine install and one-command verifier;
- one under-five-minute live demo showing failure, revised action, recovery,
  re-verification, and claim-to-artifact drill-down.

## Historical Boundaries

- `main` and tag `v0.0.1` are the judged FIND EVIL snapshot.
- Commit `b3355a5` and this archive branch are post-submission work.
- The deleted case evidence is not recoverable from Git history.
- Synthetic fixtures demonstrate control-flow mechanics, not real-world
  prevalence, detection accuracy, or incident conclusions.
