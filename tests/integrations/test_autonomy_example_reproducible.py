"""Public reproducibility: the committed example bundle regenerates from public
inputs (the committed fixture + decisions JSONL) with no model/provider key.
"""

from __future__ import annotations

import json
from pathlib import Path

from elenchos.autonomy import AutonomySupervisor
from elenchos.autonomy.providers import ReplayDecisionProvider

FIXTURE = Path("tests/fixtures/positive_control/autonomy_demo.json")
DECISIONS = Path("docs/examples/autonomy-runs/case-autonomy-demo/decisions.jsonl")
CASE_ID = "case_positive-control"


def test_committed_replay_inputs_reproduce_a_clean_traceable_run(tmp_path: Path):
    provider = ReplayDecisionProvider.from_jsonl(DECISIONS)
    result = AutonomySupervisor(
        case_id=CASE_ID,
        output_dir=tmp_path / "runs" / "autonomy-demo",
        provider=provider,
        fixture_path=FIXTURE,
        max_iterations=10,
    ).run()

    assert result.verification_status == "passed"
    assert result.plan_revision_count >= 1
    assert result.self_correction_count >= 1

    ard = Path(result.agent_run_dir)
    trace = json.loads((ard / "trace_map.json").read_text())
    assert trace["all_supported_claims_resolved"] is True
    assert trace["supported_claim_count"] >= 1
