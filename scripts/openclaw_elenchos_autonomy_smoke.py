#!/usr/bin/env python
from __future__ import annotations

import json
import tempfile
from pathlib import Path

from elenchos.integrations.tool_adapter import dispatch_tool


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_fixture(output_dir: Path) -> Path:
    case_root = output_dir.parent
    case_prep = case_root / "prep" / "case_prep.json"
    artifact = case_prep.parent / "extracted" / "mft" / "$MFT"
    artifact.parent.mkdir(parents=True, exist_ok=True)
    artifact.write_bytes(b"synthetic mft")
    _write_json(
        case_prep,
        {
            "case_id": "CASE-AUTONOMY-SMOKE",
            "coverage_gaps": [],
            "prepared_artifacts": [
                {
                    "artifact_id": "prep_mft",
                    "artifact_type": "mft",
                    "parser_eligible": True,
                    "path": "extracted/mft/$MFT",
                    "source_id": "src_smoke",
                    "status": "available",
                }
            ],
            "sources": [
                {
                    "analysis_scope": "primary",
                    "display_name": "synthetic.E01",
                    "kind": "ewf_e01",
                    "role": "disk_image",
                    "source_id": "src_smoke",
                    "status": "available",
                }
            ],
            "warnings": [],
        },
    )
    _write_json(
        output_dir / "agent_run.json",
        {"case_id": "CASE-AUTONOMY-SMOKE", "status": "completed"},
    )
    _write_json(
        output_dir / "findings.json",
        {
            "case_id": "CASE-AUTONOMY-SMOKE",
            "findings": [{"finding_id": "f1", "status": "needs_review"}],
        },
    )
    _write_json(
        output_dir / "case_questions.json",
        {
            "case_id": "CASE-AUTONOMY-SMOKE",
            "questions": [
                {
                    "question_id": "q_theft",
                    "question": "Was theft supported?",
                    "status": "not_assessed",
                    "reason": "not supported by current generated scope",
                    "gaps": ["no transfer or exfiltration artifacts"],
                }
            ],
            "status_counts": {"not_assessed": 1},
        },
    )
    _write_json(
        output_dir / "gap_analysis.json",
        {
            "case_id": "CASE-AUTONOMY-SMOKE",
            "claim_boundaries": [
                {
                    "claim_area": "theft/exfiltration",
                    "final_wording": (
                        "Elenchos did not find sufficient support for a theft or "
                        "exfiltration conclusion within the submitted artifact scope."
                    ),
                    "scope_boundary": (
                        "The current generated scope does not support a theft or "
                        "exfiltration conclusion."
                    ),
                    "recommended_next_artifacts": ["network telemetry"],
                    "status": "not_assessed",
                }
            ],
        },
    )
    (output_dir / "report.md").write_text("# Smoke report\n", encoding="utf-8")
    return case_prep


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="elenchos-autonomy-") as tmp:
        output_dir = Path(tmp) / "runs" / "autonomy-smoke" / "agent-run"
        prepared_manifest_path = _write_fixture(output_dir)
        state = dispatch_tool("inspect_run_state", {"output_dir": str(output_dir)})
        visible = (
            "[model-rationale] The generated run contains needs_review findings and "
            "not_assessed theft/exfiltration questions. The next safe bounded action "
            "is start_case_run with the prepared manifest path."
        )
        print(visible)
        rationale = dispatch_tool(
            "record_model_rationale",
            {
                "output_dir": str(output_dir),
                "phase": "validation",
                "visible_message": visible,
                "proposed_action": "start_case_run",
                "rationale_summary": (
                    "Generated state exposes a prepared manifest path for bounded run handoff."
                ),
                "basis_files": state["basis_files"],
                "observed_state": state,
                "forbidden_claims_avoided": [
                    "confirmed theft",
                    "confirmed exfiltration",
                    "confirmed compromise",
                ],
                "confidence": "medium",
            },
        )
        allowed = dispatch_tool(
            "evaluate_action_policy",
            {
                "output_dir": str(output_dir),
                "proposed_action": "start_case_run",
                "action_args": {
                    "output_dir": str(output_dir),
                    "prepared_manifest_path": str(prepared_manifest_path),
                },
                "rationale_id": rationale["rationale_id"],
            },
        )
        rejected = dispatch_tool(
            "evaluate_action_policy",
            {
                "output_dir": str(output_dir),
                "proposed_action": "inspect_raw_evidence",
                "action_args": {"raw_evidence_path": "/mnt/evidence/rocba/source.E01"},
                "rationale_id": rationale["rationale_id"],
            },
        )
        wrong_manifest = output_dir / "run_integrity_manifest.json"
        wrong_manifest.write_text("{}\n", encoding="utf-8")
        wrong_manifest_result = dispatch_tool(
            "evaluate_action_policy",
            {
                "output_dir": str(output_dir),
                "proposed_action": "start_case_run",
                "action_args": {
                    "output_dir": str(output_dir),
                    "prepared_manifest_path": str(wrong_manifest),
                },
                "rationale_id": rationale["rationale_id"],
            },
        )
        print(allowed["visible_policy_message"])
        print(rejected["visible_policy_message"])
        print(wrong_manifest_result["visible_policy_message"])
        assert allowed["decision"] == "allowed"
        assert rejected["decision"] == "rejected"
        assert wrong_manifest_result["decision"] == "rejected"
        assert state["prepared_manifest_path"].endswith("prep/case_prep.json")
        assert (output_dir / "model_rationale.jsonl").is_file()
        assert (output_dir / "policy_decisions.jsonl").is_file()
        print(f"model_rationale={output_dir / 'model_rationale.jsonl'}")
        print(f"policy_decisions={output_dir / 'policy_decisions.jsonl'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
