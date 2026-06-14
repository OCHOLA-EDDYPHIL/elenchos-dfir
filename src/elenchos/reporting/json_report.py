"""Reporting boundary for standalone JSON report requests.

Markdown is the human-readable report surface. Machine-readable outputs are
emitted as workflow artifacts such as `findings.json`, `agent_run.json`, and
`audit.jsonl`; there is no separate standalone JSON report renderer in the
final submission surface.
"""


def generate_json_report(*args: object, **kwargs: object) -> None:
    raise RuntimeError(
        "Standalone JSON report rendering is outside the final report surface; "
        "use findings.json, agent_run.json, and audit.jsonl for machine-readable outputs, "
        "and report.md for the human-readable report."
    )
