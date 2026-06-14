#!/usr/bin/env python
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

from elenchos.integrations.tool_adapter import (
    dispatch_tool,
    get_tool_definitions,
)
from elenchos.validation.integrity import write_integrity_manifest

CASE_ID_DEFAULT = "CASE-OPENCLAW-ELENCHOS-SMOKE"
SMOKE_FINAL_WORDING = (
    "Elenchos did not find sufficient support for the configured claim "
    "conclusion within the submitted artifact scope."
)
SMOKE_SCOPE_BOUNDARY = (
    "The current artifact scope does not support the configured claim "
    "conclusion; additional directly supporting artifacts would be required."
)
SMOKE_RECOMMENDED_NEXT_ARTIFACTS = [
    "browser history",
    "cloud sync logs",
    "network telemetry",
    "removable-device artifacts",
    "memory analysis",
]


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _arg_after(argv: list[str], name: str) -> str:
    try:
        return argv[argv.index(name) + 1]
    except (ValueError, IndexError) as exc:
        raise ValueError(f"missing expected argv option {name}") from exc


def _fake_prepare(argv: list[str]) -> subprocess.CompletedProcess[str]:
    case_id = _arg_after(argv, "--case-id")
    output_dir = Path(_arg_after(argv, "--output-dir")).resolve()
    source_root = Path(_arg_after(argv, "--source-root")).resolve()
    source_manifest_out = Path(_arg_after(argv, "--source-manifest-out")).resolve()
    case_prep = output_dir / "case_prep.json"
    source_manifest = output_dir / "source_manifest.json"
    source_image_manifest = output_dir / "source_image_manifest.json"
    extraction_audit = output_dir / "extraction_audit.jsonl"
    prepared_mft = output_dir / "extracted" / "mft" / "$MFT"

    output_dir.mkdir(parents=True, exist_ok=True)
    prepared_mft.parent.mkdir(parents=True, exist_ok=True)
    prepared_mft.write_bytes(b"synthetic mft")
    source_root.mkdir(parents=True, exist_ok=True)
    (source_root / "synthetic.E01").write_bytes(b"synthetic smoke source marker")
    sources: list[dict[str, object]] = [
        {
            "analysis_scope": "primary",
            "display_name": "synthetic.E01",
            "hash_status": "not_requested",
            "kind": "ewf_e01",
            "local_path": str(source_root / "synthetic.E01"),
            "role": "disk_image",
            "sanitized_path": "synthetic.E01",
            "sha256": None,
            "size_bytes": 29,
            "source_id": "src_openclaw_smoke",
            "source_ref": "synthetic.E01",
            "status": "available",
        }
    ]
    source_manifest_payload: dict[str, object] = {
        "case_id": case_id,
        "created_at": "2026-01-01T00:00:00Z",
        "schema_version": 1,
        "source_count": 1,
        "source_root": str(source_root),
        "source_set_id": "srcset_openclaw_smoke",
        "sources": sources,
    }
    _write_json(source_manifest_out, source_manifest_payload)
    sanitized_manifest = dict(source_manifest_payload)
    sanitized_manifest.pop("source_root", None)
    sanitized_manifest["sources"] = [
        {key: value for key, value in row.items() if key != "local_path"}
        for row in sources
    ]
    _write_json(source_manifest, sanitized_manifest)
    _write_json(source_image_manifest, sanitized_manifest)
    _write_json(output_dir / "warnings.json", {"case_id": case_id, "warnings": []})
    _write_json(
        case_prep,
        {
            "case_id": case_id,
            "coverage_gaps": [],
            "created_at": "2026-01-01T00:00:00Z",
            "output_dir": "runs/openclaw-smoke/case-prep",
            "prepared_artifacts": [
                {
                    "artifact_id": "prep_mft",
                    "artifact_type": "mft",
                    "parser_eligible": True,
                    "path": "extracted/mft/$MFT",
                    "source_id": "src_openclaw_smoke",
                    "status": "available",
                }
            ],
            "schema_version": 1,
            "source_set_id": "srcset_openclaw_smoke",
            "sources": sources,
            "status": "completed",
            "warnings": [],
        },
    )
    extraction_audit.write_text(
        json.dumps(
            {
                "case_id": case_id,
                "event_id": "event_000001",
                "event_type": "case_prepare_completed",
                "status": "completed",
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    stdout = "\n".join(
        [
            f"case_id={case_id}",
            "status=completed",
            "sources=1",
            "prepared_artifacts=1",
            "coverage_gaps=0",
            f"output_dir={output_dir}",
            f"case_prep={case_prep}",
            f"source_manifest={source_manifest}",
            f"local_source_manifest={source_manifest_out}",
            f"extraction_audit={extraction_audit}",
        ]
    )
    return subprocess.CompletedProcess(argv, 0, stdout + "\n", "")


def _fake_run_case(argv: list[str]) -> subprocess.CompletedProcess[str]:
    case_id = _arg_after(argv, "--case-id")
    output_dir = Path(_arg_after(argv, "--output-dir")).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    _write_json(
        output_dir / "agent_run.json",
        {
            "case_id": case_id,
            "input_source": "openclaw_smoke_fixture",
            "output_refs": {
                "agent_run": "agent_run.json",
                "audit": "audit.jsonl",
                "case_questions": "case_questions.json",
                "decision_trace": "decision_trace.json",
                "findings": "findings.json",
                "gap_analysis": "gap_analysis.json",
                "normalized_events": "normalized_events.json",
                "performance_summary": "performance_summary.json",
                "report": "report.md",
                "self_correction_events": "self_correction_events.json",
            },
            "status": "completed",
        },
    )
    (output_dir / "audit.jsonl").write_text(
        json.dumps(
            {
                "case_id": case_id,
                "event_type": "run_case_completed",
                "status": "completed",
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    _write_json(
        output_dir / "coverage_summary.json",
        {
            "case_id": case_id,
            "limitations": ["synthetic smoke fixture; no raw evidence assessed"],
            "normalized_events_written": 2,
            "per_artifact": [
                {
                    "artifact_id": "synthetic-amcache",
                    "artifact_type": "amcache",
                    "parser_status": "success",
                },
                {
                    "artifact_id": "synthetic-ntuser",
                    "artifact_type": "recentdocs",
                    "parser_status": "success",
                },
            ],
        },
    )
    _write_json(
        output_dir / "normalized_events.json",
        {
            "case_id": case_id,
            "event_count": 2,
            "events": [
                {
                    "artifact_family": "amcache",
                    "artifact_id": "synthetic-amcache",
                    "artifact_type": "amcache",
                    "event_id": "evt_amcache_smoke",
                    "event_type": "amcache_execution",
                    "parser_name": "amcacheparser",
                },
                {
                    "artifact_family": "registry_user_activity",
                    "artifact_id": "synthetic-ntuser",
                    "artifact_type": "recentdocs",
                    "event_id": "evt_recentdocs_smoke",
                    "event_type": "registry_recent_document_candidate",
                    "parser_name": "recmd",
                },
            ],
        },
    )
    _write_json(
        output_dir / "findings.json",
        {"case_id": case_id, "finding_count": 0, "findings": [], "validation_results": []},
    )
    questions = [
        {
            "evidence_classes_checked": [],
            "gaps": ["unsupported by current synthetic smoke scope"],
            "linked_evidence_refs": [],
            "linked_finding_ids": [],
            "question": question,
            "question_id": question_id,
            "reason": "not supported by current artifact scope",
            "status": "not_assessed",
        }
        for question_id, question in (
            ("q_claim_subject", "What claim subject was supported?"),
            ("q_claim_transfer", "What transfer path was supported?"),
            ("q_claim_method", "What method was supported?"),
            ("q_out_of_scope_context", "What did out-of-scope context show?"),
        )
    ]
    _write_json(
        output_dir / "case_questions.json",
        {
            "case_id": case_id,
            "questions": questions,
            "status_counts": {"not_assessed": len(questions)},
        },
    )
    _write_json(
        output_dir / "decision_trace.json",
        {"case_id": case_id, "decisions": [{"decision_id": "openclaw_smoke"}]},
    )
    _write_json(
        output_dir / "gap_analysis.json",
        {
            "case_id": case_id,
            "claim_boundaries": [
                {
                    "claim_area": "configured claim",
                    "final_wording": SMOKE_FINAL_WORDING,
                    "scope_boundary": SMOKE_SCOPE_BOUNDARY,
                    "status": "not_assessed",
                }
            ],
            "status_counts": {"not_assessed": len(questions)},
            "unsupported_questions": [row["question_id"] for row in questions],
        },
    )
    _write_json(
        output_dir / "self_correction_events.json",
        {
            "case_id": case_id,
            "created_at": "2026-01-01T00:00:00Z",
            "event_count": 1,
            "events": [
                {
                    "correction": (
                        "The final posture follows the configured claim-boundary "
                        "wording instead of promoting an unsupported conclusion."
                    ),
                    "event_id": "claim-boundary-001",
                    "final_wording": SMOKE_FINAL_WORDING,
                    "human_intervention": False,
                    "initial_investigative_pressure": (
                        "The case asks whether a configured claim can be supported "
                        "from submitted artifacts."
                    ),
                    "model_output_used_as_evidence": False,
                    "phase": "claim_validation",
                    "problem_detected": (
                        "Configured claim-boundary conditions were met by generated "
                        "case-question statuses."
                    ),
                    "raw_evidence_sent_to_model": False,
                    "recommended_next_artifacts": SMOKE_RECOMMENDED_NEXT_ARTIFACTS,
                    "scope_boundary": SMOKE_SCOPE_BOUNDARY,
                    "source_question_ids": [
                        "q_claim_subject",
                        "q_claim_transfer",
                        "q_claim_method",
                        "q_out_of_scope_context",
                    ],
                }
            ],
            "mode": "claim_boundary_self_correction",
            "notes": [
                (
                    "Events are generated by deterministic Elenchos validation from "
                    "casebook claim-boundary metadata and case-question statuses; "
                    "OpenClaw may use them to revise narrative posture."
                )
            ],
        },
    )
    _write_json(
        output_dir / "performance_summary.json",
        {"case_id": case_id, "mode": "openclaw_smoke", "run_status": "completed"},
    )
    (output_dir / "report.md").write_text(
        "# Elenchos OpenClaw Smoke Report\n\n"
        "Synthetic generated outputs validate the bounded adapter path.\n"
        f"{SMOKE_FINAL_WORDING}\n"
        f"{SMOKE_SCOPE_BOUNDARY}\n"
        "Unsupported memory questions remain not_assessed.\n",
        encoding="utf-8",
    )
    write_integrity_manifest(output_dir)
    stdout = "\n".join(
        [
            f"case_id={case_id}",
            "status=completed",
            "steps=1",
            f"output_dir={output_dir}",
            f"agent_run={output_dir / 'agent_run.json'}",
            f"audit={output_dir / 'audit.jsonl'}",
            f"case_questions={output_dir / 'case_questions.json'}",
            f"decision_trace={output_dir / 'decision_trace.json'}",
            f"gap_analysis={output_dir / 'gap_analysis.json'}",
            f"self_correction_events={output_dir / 'self_correction_events.json'}",
            f"performance_summary={output_dir / 'performance_summary.json'}",
        ]
    )
    return subprocess.CompletedProcess(argv, 0, stdout + "\n", "")


def _dry_run_command_runner(
    argv: list[str],
    timeout_seconds: int,
) -> subprocess.CompletedProcess[str]:
    del timeout_seconds
    if argv[1:5] == ["-m", "elenchos", "case", "prepare"]:
        return _fake_prepare(argv)
    if argv[1:5] == ["-m", "elenchos", "agent", "run-case"]:
        return _fake_run_case(argv)
    return subprocess.CompletedProcess(argv, 2, "", "unsupported smoke command\n")


def _command_probe(command: str, args: list[str]) -> dict[str, object]:
    executable = shutil.which(command)
    result: dict[str, object] = {
        "command": command,
        "available": executable is not None,
        "path": executable,
    }
    if executable is None:
        return result
    try:
        completed = subprocess.run(
            [executable, *args],
            cwd=_repo_root(),
            text=True,
            capture_output=True,
            check=False,
            timeout=10,
        )
    except subprocess.TimeoutExpired:
        result["status"] = "timed_out"
        return result
    result["status"] = "completed"
    result["returncode"] = completed.returncode
    result["stdout_first_line"] = completed.stdout.splitlines()[0] if completed.stdout else ""
    result["stderr_first_line"] = completed.stderr.splitlines()[0] if completed.stderr else ""
    return result


def _copy_operation_traces(run_root: Path) -> None:
    trace_dir = run_root / "openclaw-trace"
    trace_dir.mkdir(parents=True, exist_ok=True)
    copies = {
        run_root / "case-prep" / "openclaw-trace" / "prepare_case.stdout": trace_dir
        / "prepare_case.stdout",
        run_root / "case-prep" / "openclaw-trace" / "prepare_case.stderr": trace_dir
        / "prepare_case.stderr",
        run_root / "agent-run" / "openclaw-trace" / "run_case.stdout": trace_dir
        / "run_case.stdout",
        run_root / "agent-run" / "openclaw-trace" / "run_case.stderr": trace_dir
        / "run_case.stderr",
    }
    for source, destination in copies.items():
        if source.exists():
            shutil.copyfile(source, destination)


def run_dry_smoke(run_root: Path, case_id: str) -> dict[str, object]:
    run_root = run_root.resolve()
    source_root = run_root / "synthetic-source"
    prepare_result = dispatch_tool(
        "prepare_case",
        {
            "case_id": case_id,
            "source_root": str(source_root),
            "source_manifest_out": str(run_root / "source-manifest.json"),
            "output_dir": str(run_root / "case-prep"),
            "timeout_seconds": 60,
        },
        command_runner=_dry_run_command_runner,
    )
    run_result = dispatch_tool(
        "run_case",
        {
            "artifact_manifest": str(run_root / "case-prep" / "case_prep.json"),
            "case_id": case_id,
            "event_selection_profile": "forensic-triage",
            "max_iterations": 10,
            "max_normalized_events": 5000,
            "output_dir": str(run_root / "agent-run"),
            "timeout_seconds": 60,
        },
        command_runner=_dry_run_command_runner,
    )
    summary = dispatch_tool("summarize_run", {"output_dir": str(run_root / "agent-run")})
    validation = dispatch_tool("validate_run_outputs", {"output_dir": str(run_root / "agent-run")})
    _copy_operation_traces(run_root)
    payload = {
        "case_id": case_id,
        "mode": "dry-run",
        "openclaw": {
            "which_openclaw": _command_probe("openclaw", ["--version"]),
            "which_claw": _command_probe("claw", ["--version"]),
        },
        "tool_count": len(get_tool_definitions()),
        "prepare_case": prepare_result,
        "run_case": run_result,
        "summary": summary,
        "validation": validation,
    }
    _write_json(run_root / "openclaw-trace" / "summary.json", payload)
    return payload


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Elenchos OpenClaw adapter smoke harness")
    parser.add_argument("--dry-run", action="store_true", help="Run deterministic fixture mode")
    parser.add_argument(
        "--output-dir",
        default="runs/openclaw-smoke",
        help="Ignored generated output directory for smoke artifacts",
    )
    parser.add_argument("--case-id", default=CASE_ID_DEFAULT)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.dry_run:
        print(
            "Only --dry-run mode is supported without local evidence/provider config.",
            file=sys.stderr,
        )
        return 2
    payload = run_dry_smoke(Path(args.output_dir), args.case_id)
    validation = payload["validation"]
    if not isinstance(validation, dict) or validation.get("validation_status") != "pass":
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 1
    summary = payload["summary"]
    prepare_case_result = payload["prepare_case"]
    run_case_result = payload["run_case"]
    if not isinstance(summary, dict):
        raise TypeError("summary payload is malformed")
    if not isinstance(prepare_case_result, dict):
        raise TypeError("prepare_case payload is malformed")
    if not isinstance(run_case_result, dict):
        raise TypeError("run_case payload is malformed")
    print(f"case_id={payload['case_id']}")
    print("mode=dry-run")
    print(f"prepare_status={prepare_case_result['status']}")
    print(f"run_status={run_case_result['status']}")
    print(f"validation_status={validation['validation_status']}")
    print(f"finding_status_counts={summary['finding_status_counts']}")
    print(f"case_question_status_counts={summary['case_question_status_counts']}")
    print(f"summary={Path(args.output_dir) / 'openclaw-trace' / 'summary.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
