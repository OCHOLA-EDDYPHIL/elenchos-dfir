from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from siftguard.audit.execution_ledger import read_events
from siftguard.cli import main

POSITIVE_FIXTURE = Path("tests/fixtures/positive_control/positive_chain.json")
SELF_CORRECTION_FIXTURE = Path("tests/fixtures/positive_control/unsupported_claim.json")


def _load(output_dir: Path, name: str) -> dict:
    return json.loads((output_dir / name).read_text(encoding="utf-8"))


def _finding_status_counts(findings: list[dict]) -> dict[str, int]:
    return dict(Counter(finding.get("status") for finding in findings))


def _evidence_sources(findings: list[dict]) -> set[str]:
    return {
        ref["source"]
        for finding in findings
        for ref in finding.get("evidence_refs", [])
        if "source" in ref
    }


def test_positive_control_fixture_emits_one_grouped_inferred_finding(tmp_path: Path):
    output_dir = tmp_path / "runs" / "case_positive-control" / "agent-run"

    exit_code = main(
        [
            "agent",
            "run-fixture",
            "--case-id",
            "case_positive-control",
            "--fixture",
            str(POSITIVE_FIXTURE),
            "--output-dir",
            str(output_dir),
            "--max-iterations",
            "7",
        ]
    )

    assert exit_code == 0
    agent_run = _load(output_dir, "agent_run.json")
    coverage = _load(output_dir, "coverage_summary.json")
    timelines = _load(output_dir, "subject_timelines.json")
    findings_payload = _load(output_dir, "findings.json")
    findings = findings_payload["findings"]
    report = (output_dir / "report.md").read_text(encoding="utf-8")
    audit = read_events(output_dir / "audit.jsonl")

    assert agent_run["status"] == "completed"
    assert agent_run["input_source"] == "synthetic_positive_control"
    assert agent_run["corrections"] == []
    assert coverage["input_source"] == "synthetic_positive_control"
    assert coverage["fixture_id"] == "positive_chain"
    assert timelines["timeline_count"] == 2
    assert findings_payload["finding_count"] == 1
    assert _finding_status_counts(findings) == {"inferred": 1}
    assert _evidence_sources(findings) == {"mft", "registry", "amcache"}
    assert len(findings[0]["evidence_refs"]) >= 3
    assert "drop, execution, and persistence observations" in findings[0]["claim"]
    assert "## Inferred Findings" in report
    assert findings[0]["finding_id"] in report
    assert any(event["action"] == "fixture_input_loaded" for event in audit)


def test_self_correction_fixture_downgrades_unsupported_induced_claim(tmp_path: Path):
    output_dir = tmp_path / "runs" / "case_self-correction-control" / "agent-run"

    exit_code = main(
        [
            "agent",
            "run-fixture",
            "--case-id",
            "case_self-correction-control",
            "--fixture",
            str(SELF_CORRECTION_FIXTURE),
            "--output-dir",
            str(output_dir),
            "--max-iterations",
            "7",
        ]
    )

    assert exit_code == 0
    agent_run = _load(output_dir, "agent_run.json")
    findings_payload = _load(output_dir, "findings.json")
    findings = findings_payload["findings"]
    report = (output_dir / "report.md").read_text(encoding="utf-8")
    audit = read_events(output_dir / "audit.jsonl")
    induced = next(
        finding
        for finding in findings
        if finding["finding_id"] == "F-SYN-UNSUPPORTED-PERSISTENCE"
    )

    assert agent_run["status"] == "completed"
    assert agent_run["input_source"] == "synthetic_self_correction_control"
    assert len(agent_run["corrections"]) >= 1
    assert any(
        correction["action"] == "downgrade_finding"
        and correction["trigger"] == "unsupported_finding"
        for correction in agent_run["corrections"]
    )
    assert induced["status"] == "needs_review"
    assert _finding_status_counts(findings) == {"needs_review": 2}
    assert "## Inferred Findings\n- No inferred findings." in report
    assert "F-SYN-UNSUPPORTED-PERSISTENCE" in report
    assert "Status: `needs_review`" in report
    assert any(event["action"] == "fixture_induced_claim_written" for event in audit)
    assert any(
        event["action"] == "correction_applied"
        and event["correction_action"] == "downgrade_finding"
        for event in audit
    )


def test_fixture_cli_rejects_case_id_mismatch(tmp_path: Path, capsys):
    exit_code = main(
        [
            "agent",
            "run-fixture",
            "--case-id",
            "case_wrong",
            "--fixture",
            str(POSITIVE_FIXTURE),
            "--output-dir",
            str(tmp_path / "runs" / "case_wrong" / "agent-run"),
            "--max-iterations",
            "7",
        ]
    )

    assert exit_code == 1
    assert "does not match requested case_id" in capsys.readouterr().err
