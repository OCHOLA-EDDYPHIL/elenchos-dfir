# Model Rationale Boundary

Model rationale is operational explanation. It explains why an OpenClaw-style
agent proposes a bounded Elenchos action. It is not forensic evidence, does not
modify findings, and cannot change finding or case-question statuses.

Deterministic Elenchos outputs remain the forensic authority:

- `findings.json` records finding statuses.
- `case_questions.json` records case-question statuses.
- `decision_trace.json` records deterministic pipeline decisions.
- `gap_analysis.json` and `self_correction_events.json` record deterministic
  claim-boundary outputs.
- `validate_run_outputs` checks generated outputs and claim safety.

`model_rationale.jsonl` may explain workflow choices such as preparing a case,
starting a run, polling progress, validating outputs, or emitting a claim
boundary. It must not claim confirmed compromise, theft, exfiltration, malware,
memory findings, attribution, or final incident conclusions unless deterministic
Elenchos outputs already support the claim and validation passes.

Allowed examples:

```text
[model-rationale] The prepared manifest exists and no run output is present. The next safe bounded action is start_case_run.
[model-rationale] The run is still active. I will poll generated progress instead of starting a duplicate run.
```

Rejected or unsafe examples:

```text
inspect_raw_evidence
arbitrary_shell
claim_confirmed_exfiltration
upgrade_finding_status
```

The policy gate records deterministic allow/reject decisions in
`policy_decisions.jsonl`. It rejects model-supplied shell, command, executable,
argv, script, raw-evidence-path, and evidence-write-path fields. It also rejects
actions that would weaken read-only evidence boundaries or use model rationale
to upgrade unsupported findings.

Raw evidence is never sent to or inspected by the model through the autonomy
layer. The model observes generated Elenchos summaries and trace files only.
