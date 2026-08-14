# FIND EVIL Postmortem

## Status

Elenchos was submitted to the 2026 FIND EVIL hackathon but was not one of the
five finalists announced on 2026-08-13. The judged source snapshot is `v0.0.1`
at commit `06d4c56`. The autonomy work at and after commit `b3355a5` was
post-submission and must not be presented as part of the judged entry.

The project is archived as an experimental mechanism proof. The original SIFT
workstation and case evidence have been removed, so the historical real-case
results cannot be reproduced locally. Synthetic replay demonstrates software
behavior only; it is not evidence of real-world forensic accuracy.

Primary result source:
[official finalist announcement](https://findevil.devpost.com/updates/45839-announcing-find-evil-hackathon-finalists).

## Bottom Line

Elenchos contained credible engineering: bounded tools, deterministic policy
gates, conservative claim states, model/evidence separation, validation, and a
large automated test suite. It was not finalist-competitive because the public
submission proved restraint much more strongly than it proved autonomous
forensic competence.

The decisive gaps were:

- no independently useful accuracy benchmark;
- no convincing real failure-to-replan-to-recovery sequence;
- a narrow Windows disk-artifact scope;
- an incomplete public report-to-tool-to-artifact trace bundle;
- a deterministic fixed-phase planner in the judged version;
- avoidable packaging problems, including placeholder instructions and a dead
  repository URL in the video description; and
- no single memorable differentiator that was both demonstrated and measured.

## What the Finalists Did Differently

The finalists were not flawless. Their headline performance metrics were
entrant-authored and scope-specific. They nevertheless made autonomy, failure,
correction, scale, and traceability substantially easier for judges to see.

| Finalist | Judge-visible strength | Important qualification |
| --- | --- | --- |
| [Camel](https://github.com/allisterb/Camel) | A memorable code-writing sandbox, polished analyst UI, and a rich real-case command/execution trace | Caller-supplied evidence IDs were logged but not semantically validated; the demo mostly toured completed outputs |
| [FindEvil](https://github.com/marlyocat/findevil) | A sharp Linux niche, 45 typed tools, 29 scenarios, extensive security tests, and a simple 98.6%-recall story | Metrics were first-party; free-form confirmed claims could carry weak citations; the audited dependency range later selected an incompatible MCP version |
| [Mulder](https://github.com/calebevans/mulder) | Obvious breadth and scale across memory, disk, network, mobile, and logs, plus an Alternative Narrative phase | Citation IDs were checked for existence rather than semantic support; benchmark denominators and public tool-call totals were not fully reconcilable |
| [Protocol SIFT++](https://github.com/tupils1/protocol-siftpp) | A narrow, legible Investigator-to-Skeptic loop, visible rootkit retraction, tamper checks, and a proof-oriented demo | Coverage was limited to nine Windows-memory views; citations used the latest matching tool execution; the local hash chain lacked an external anchor |
| [TRUDI](https://github.com/nebulae/trudi) | The clearest correction story, separate director/reviewer roles, multiple large public traces, ground-truth comparisons, and finding gates | Setup was complex, one oversight gate failed open on internal error, and a committed case retained an attribution error when review calls failed |

The organizer reported that 90 incident responders performed 1,775 evaluations,
including path traversal, command injection, evidence-alteration attempts, and
retesting on unseen evidence. Selection therefore reflected more than polished
Devpost copy.

## Reusable Selection Signals

Across the five finalists, the strongest common signals were:

1. One differentiator that a judge could repeat in one sentence.
2. A visible unexpected result followed by a changed action and corrected
   conclusion.
3. Inspectable execution artifacts rather than prose claims or short excerpts.
4. Guardrails that were deliberately attacked and whose failures were reported.
5. A numeric accuracy, scale, or coverage story with disclosed limitations.
6. A demo centered on the proof moment rather than an architecture tour.
7. Submission material that linked every judging criterion directly to an
   artifact.

## What Elenchos Got Right

- The model was not treated as forensic evidence.
- Finding status changes belonged to deterministic code.
- Raw evidence and generated outputs had separate path boundaries.
- The public limitations were unusually candid.
- The policy vocabulary and claim states encouraged conservative reporting.
- The codebase was extensively tested and statically checked.

These are worth preserving. They are necessary controls, but the competition
showed that controls alone are not a compelling investigation.

## Future Hackathon Playbook

### Before entering

- Retain the required runtime, test data, and credentials through the full
  judging period.
- Convert every judging criterion into an executable acceptance test.
- Choose one measurable wedge; do not enter with a collection of generic agent
  features.
- Reject a project concept that cannot produce a credible five-minute live
  proof using redistributable or judge-accessible data.

### Build proof first

- Write the demo scenario before the architecture.
- Use a sealed holdout containing positives, negatives, ambiguity, malformed
  input, and guardrail attacks.
- Preserve pre- and post-correction outputs so blanket downgrading cannot
  masquerade as accuracy.
- Require a real unexpected tool result to cause a changed plan, another tool
  execution, and a different final conclusion.
- Bind every report claim to an exact tool call, output record, artifact ID, and
  artifact hash.

### Package for judging

- Commit the accuracy report, dataset documentation, complete sanitized trace,
  architecture overview, and run instructions to the judged branch.
- Make one command reproduce the no-secret demo or verifier.
- Test from a fresh account or clean machine.
- Check every link, image, video, repository field, and hidden form answer.
- Freeze the judged commit and submission text at least 48 hours before the
  deadline.

## Strongest Rainy-Day Direction

If Elenchos is revived, its defensible wedge should be **proof-carrying DFIR
findings**: a deterministic verifier that checks whether the cited tool output
semantically entails each claim and resolves the full chain from report text to
artifact hash.

This targets a real weakness found across all five finalists. It is narrower and
more credible than attempting to compete on parser count or broad incident
response coverage.

## Publication and Privacy Note

Making the repository private does not revoke copies already cloned while it was
public, cached pages, or the MIT license grant attached to published versions.
The archive therefore preserves provenance rather than attempting to erase the
project's publication history.
