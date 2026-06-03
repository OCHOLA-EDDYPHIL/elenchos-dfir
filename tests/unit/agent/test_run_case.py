from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from siftguard.agent.audit import append_agent_audit_event
from siftguard.agent.models import AgentRun, AgentRunStatus, AgentState
from siftguard.agent.planner import build_default_agent_plan
from siftguard.agent.run_case import CASEBOOK_YAML_REJECTION, run_case_workflow
from siftguard.audit.execution_ledger import read_events
from siftguard.cli import main
from siftguard.evidence.manifest import read_manifest
from siftguard.parser.result import ParserResult

CASE_ID = "rocba-standard"
FIXED_TIME = "2026-01-01T00:00:00Z"


def fixed_clock() -> str:
    return FIXED_TIME


def _write(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)


def write_case_prep(
    tmp_path: Path,
    *,
    case_id: str = CASE_ID,
    include_gap: bool = True,
    include_local_paths: bool = True,
) -> tuple[Path, Path, Path]:
    source_root = tmp_path / "evidence" / "rocba"
    source_root.mkdir(parents=True)
    case_prep_dir = tmp_path / "runs" / case_id / "case-prep"

    _write(case_prep_dir / "extracted" / "mft" / "$MFT", b"mft")
    _write(case_prep_dir / "extracted" / "registry" / "SOFTWARE", b"software")
    _write(case_prep_dir / "extracted" / "amcache" / "Amcache.hve", b"amcache")

    disk_source: dict[str, Any] = {
        "analysis_scope": "primary",
        "display_name": "rocba-cdrive.e01",
        "hash_status": "not_requested",
        "kind": "ewf_e01",
        "role": "disk_image",
        "sanitized_path": "rocba-cdrive.e01",
        "sha256": None,
        "size_bytes": 10,
        "source_id": "src_disk",
        "source_ref": "rocba-cdrive.e01",
        "status": "available",
    }
    memory_source: dict[str, Any] = {
        "analysis_scope": "out_of_scope_for_final_submission",
        "display_name": "Rocba-Memory.raw",
        "hash_status": "not_requested",
        "kind": "raw",
        "role": "memory_image",
        "sanitized_path": "memory/Rocba-Memory.raw",
        "sha256": None,
        "size_bytes": 20,
        "source_id": "src_memory",
        "source_ref": "memory/Rocba-Memory.raw",
        "status": "staged_not_analyzed",
    }
    if include_local_paths:
        disk_source["local_path"] = str(source_root / "rocba-cdrive.e01")
        memory_source["local_path"] = str(source_root / "memory" / "Rocba-Memory.raw")

    prepared_artifacts = [
        {
            "artifact_id": "prep_mft",
            "artifact_type": "mft",
            "extraction_method": "fixture",
            "hash_status": "computed",
            "parser_eligible": True,
            "path": "extracted/mft/$MFT",
            "sha256": "a" * 64,
            "source_id": "src_disk",
            "source_role": "disk_image",
            "status": "available",
            "warnings": [],
        },
        {
            "artifact_id": "prep_software",
            "artifact_type": "registry_hive",
            "extraction_method": "fixture",
            "hash_status": "computed",
            "parser_eligible": True,
            "path": "extracted/registry/SOFTWARE",
            "sha256": "b" * 64,
            "source_id": "src_disk",
            "source_role": "disk_image",
            "status": "available",
            "warnings": [],
        },
        {
            "artifact_id": "prep_amcache",
            "artifact_type": "amcache_hive",
            "extraction_method": "fixture",
            "hash_status": "computed",
            "parser_eligible": True,
            "path": "extracted/amcache/Amcache.hve",
            "sha256": "c" * 64,
            "source_id": "src_disk",
            "source_role": "disk_image",
            "status": "available",
            "warnings": [],
        },
        {
            "artifact_id": "prep_ntuser",
            "artifact_type": "registry_hive",
            "extraction_method": "fixture",
            "hash_status": "skipped",
            "parser_eligible": True,
            "path": "extracted/registry/NTUSER.DAT",
            "sha256": None,
            "source_id": "src_disk",
            "source_role": "disk_image",
            "status": "missing",
            "warnings": [],
        },
    ]
    coverage_gaps = (
        [
            {
                "artifact_type": "registry_hive",
                "gap_id": "gap_ntuser",
                "impact": "NTUSER.DAT coverage is unavailable.",
                "reason": "not_found",
                "recommended_next_step": "Confirm NTUSER.DAT absence manually.",
                "source_id": "src_disk",
            }
        ]
        if include_gap
        else []
    )
    payload = {
        "case_id": case_id,
        "coverage_gaps": coverage_gaps,
        "created_at": FIXED_TIME,
        "output_dir": f"runs/{case_id}/case-prep",
        "prepared_artifacts": prepared_artifacts,
        "source_set_id": "srcset_rocba",
        "sources": [disk_source, memory_source],
        "status": "partial_success" if include_gap else "completed",
        "warnings": ["Rocba-Memory.raw: memory source inventoried only"],
    }
    path = case_prep_dir / "case_prep.json"
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    return path, case_prep_dir, source_root


def write_casebook(tmp_path: Path, *, case_id: str = CASE_ID) -> Path:
    path = tmp_path / "casebook.json"
    path.write_text(
        json.dumps(
            {
                "case_id": case_id,
                "display_name": "ROCBA Standard Forensic Case",
                "case_questions": [
                    {
                        "id": "q1",
                        "question": "Was there suspicious program presence?",
                        "supported_by_scope": "partial",
                    }
                ],
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    return path


def write_user_activity_casebook(tmp_path: Path, *, case_id: str = CASE_ID) -> Path:
    path = tmp_path / "user-activity-casebook.json"
    path.write_text(
        json.dumps(
            {
                "case_id": case_id,
                "display_name": "Synthetic User Activity Case",
                "analysis_windows": [
                    {
                        "id": "window",
                        "start": "2020-11-13T00:00:00+00:00",
                        "end": "2020-11-14T00:00:00+00:00",
                        "description": "synthetic activity window",
                    }
                ],
                "case_questions": [
                    {
                        "id": "q_when_activity",
                        "question": "When did relevant activity occur?",
                        "supported_by_scope": "partial",
                        "evidence_classes": ["registry_user_activity", "mft"],
                        "status_policy": "case_window_activity",
                    },
                    {
                        "id": "q_what_was_stolen",
                        "question": "What was stolen?",
                        "supported_by_scope": False,
                        "expected_status": "not_assessed",
                        "gap_reason": "Candidate user activity does not prove theft.",
                    },
                    {
                        "id": "q_where_transferred",
                        "question": "Where was it transferred to?",
                        "supported_by_scope": False,
                        "expected_status": "not_assessed",
                        "gap_reason": "Candidate user activity does not prove transfer.",
                    },
                    {
                        "id": "q_how_stolen",
                        "question": "How was it stolen?",
                        "supported_by_scope": False,
                        "expected_status": "not_assessed",
                        "gap_reason": "Candidate user activity does not prove method.",
                    },
                    {
                        "id": "q_memory",
                        "question": "What did memory show?",
                        "supported_by_scope": False,
                        "expected_status": "not_assessed",
                        "gap_reason": "Memory is out of scope.",
                    },
                ],
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    return path


def mark_ntuser_available(case_prep_path: Path) -> None:
    payload = json.loads(case_prep_path.read_text(encoding="utf-8"))
    _write(case_prep_path.parent / "extracted" / "registry" / "NTUSER.DAT", b"ntuser")
    for artifact in payload["prepared_artifacts"]:
        if artifact["artifact_id"] != "prep_ntuser":
            continue
        artifact["status"] = "available"
        artifact["hash_status"] = "computed"
        artifact["sha256"] = "d" * 64
    payload["coverage_gaps"] = []
    case_prep_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True),
        encoding="utf-8",
    )


def add_ntuser_scope_warning(case_prep_path: Path) -> None:
    payload = json.loads(case_prep_path.read_text(encoding="utf-8"))
    for artifact in payload["prepared_artifacts"]:
        if artifact["artifact_id"] != "prep_ntuser":
            continue
        artifact["warnings"] = ["multiple NTUSER.DAT candidates found; extracted first"]
    case_prep_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True),
        encoding="utf-8",
    )


def replace_with_profile_ntuser_artifacts(case_prep_path: Path) -> None:
    payload = json.loads(case_prep_path.read_text(encoding="utf-8"))
    profile_artifacts = []
    for index, profile_id in enumerate(("profile-0001", "profile-0002"), start=1):
        relative_path = f"extracted/registry/profiles/{profile_id}/NTUSER.DAT"
        _write(case_prep_path.parent / relative_path, f"ntuser-{index}".encode("utf-8"))
        profile_artifacts.append(
            {
                "artifact_id": f"prep_ntuser_{profile_id.replace('-', '_')}",
                "artifact_type": "registry_hive",
                "extraction_method": f"fixture_copy:Users/{profile_id}/NTUSER.DAT",
                "hash_status": "computed",
                "parser_eligible": True,
                "path": relative_path,
                "profile_display_name": profile_id,
                "profile_id": profile_id,
                "registry_hive_type": "ntuser",
                "sanitized_profile_hint": profile_id,
                "sha256": str(index) * 64,
                "source_candidate_ref": f"Users/{profile_id}/NTUSER.DAT",
                "source_id": "src_disk",
                "source_role": "disk_image",
                "status": "available",
                "warnings": [],
            }
        )
    payload["prepared_artifacts"] = [
        artifact
        for artifact in payload["prepared_artifacts"]
        if artifact["artifact_id"] != "prep_ntuser"
    ] + profile_artifacts
    payload["coverage_gaps"] = []
    payload["status"] = "completed"
    case_prep_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True),
        encoding="utf-8",
    )


def fake_workflow_runner(**kwargs) -> AgentRun:
    case_id = kwargs["case_id"]
    manifest_path = kwargs["manifest_path"]
    output_dir = kwargs["output_dir"]
    output_dir.mkdir(parents=True, exist_ok=True)
    manifest = read_manifest(manifest_path)
    audit_path = output_dir / "audit.jsonl"
    for event in kwargs.get("audit_prelude_events") or []:
        append_agent_audit_event(
            audit_path,
            event_type=event["event_type"],
            case_id=case_id,
            run_id=f"run_{case_id}",
            status=event.get("status", "completed"),
            extra=event.get("extra"),
            clock=kwargs.get("clock", fixed_clock),
        )
    append_agent_audit_event(
        audit_path,
        event_type="agent_run_started",
        case_id=case_id,
        run_id=f"run_{case_id}",
        status="running",
        clock=kwargs.get("clock", fixed_clock),
    )
    (output_dir / "normalized_events.json").write_text(
        json.dumps({"case_id": case_id, "event_count": 0, "events": []}),
        encoding="utf-8",
    )
    (output_dir / "subject_timelines.json").write_text(
        json.dumps({"case_id": case_id, "timeline_count": 0, "timelines": []}),
        encoding="utf-8",
    )
    (output_dir / "findings.json").write_text(
        json.dumps(
            {
                "case_id": case_id,
                "finding_count": 0,
                "findings": [],
                "validation_results": [],
            }
        ),
        encoding="utf-8",
    )
    (output_dir / "coverage_summary.json").write_text(
        json.dumps(
            {
                "case_id": case_id,
                "normalized_events_written": 0,
                "per_artifact": [
                    {
                        "artifact_id": artifact.artifact_id,
                        "artifact_type": artifact.artifact_type,
                        "parser_status": "success",
                        "source_image_id": artifact.source_image_id,
                        "source_image_label": artifact.source_image_label,
                    }
                    for artifact in manifest.artifacts
                ],
            }
        ),
        encoding="utf-8",
    )
    (output_dir / "report.md").write_text("# Case Report\n", encoding="utf-8")
    plan = build_default_agent_plan(case_id, created_at=FIXED_TIME)
    run = AgentRun(
        run_id=f"run_{case_id}",
        case_id=case_id,
        status=AgentRunStatus.COMPLETED,
        plan=plan,
        state=AgentState(case_id=case_id, final_status=AgentRunStatus.COMPLETED),
        started_at=FIXED_TIME,
        completed_at=FIXED_TIME,
        max_iterations=kwargs["max_iterations"],
        max_normalized_events=kwargs.get("max_normalized_events"),
        event_selection_profile=kwargs.get("event_selection_profile", "first-n"),
        input_source=kwargs.get("input_source"),
        output_refs={
            "agent_run": "agent_run.json",
            "audit": "audit.jsonl",
            "coverage_summary": "coverage_summary.json",
            "normalized_events": "normalized_events.json",
            "subject_timelines": "subject_timelines.json",
            "findings": "findings.json",
            "report": "report.md",
        },
    )
    (output_dir / "agent_run.json").write_text(
        json.dumps(run.to_dict(), indent=2, sort_keys=True),
        encoding="utf-8",
    )
    return run


def fake_user_activity_workflow_runner(**kwargs) -> AgentRun:
    run = fake_workflow_runner(**kwargs)
    case_id = kwargs["case_id"]
    output_dir = kwargs["output_dir"]
    target = r"C:\Users\analyst\Documents\ProjectAlpha\design.docx"
    events = [
        {
            "artifact_family": "registry_user_activity",
            "artifact_id": "prep_ntuser",
            "artifact_type": "recentdocs",
            "case_id": case_id,
            "event_id": "ua_recentdocs_1",
            "event_type": "registry_recent_document_candidate",
            "evidence_refs": ["prep_ntuser"],
            "metadata": {
                "artifact_family": "registry_user_activity",
                "source_id": "src_disk",
                "source_role": "disk_image",
                "target": target,
            },
            "parser_name": "recmd",
            "path": target,
            "raw_record_ref": {
                "record_id": "ua_recentdocs_1",
                "row_number": 2,
                "source_path": "recmd_recentdocs.csv",
            },
            "source_tool": "RECmd",
            "subject": target,
            "timestamp_description": "registry_key_last_write",
            "timestamp_utc": "2020-11-13T20:12:00Z",
        },
        {
            "artifact_id": "prep_mft",
            "artifact_type": "mft",
            "case_id": case_id,
            "event_id": "mft_1",
            "event_type": "file_created",
            "evidence_refs": ["prep_mft"],
            "metadata": {},
            "parser_name": "mftecmd",
            "path": target,
            "raw_record_ref": {
                "record_id": "mft_1",
                "row_number": 2,
                "source_path": "mft.csv",
            },
            "source_tool": "MFTECmd",
            "subject": target,
            "timestamp_utc": "2020-11-13T20:10:00Z",
        },
    ]
    (output_dir / "normalized_events.json").write_text(
        json.dumps({"case_id": case_id, "event_count": len(events), "events": events}),
        encoding="utf-8",
    )
    coverage = json.loads((output_dir / "coverage_summary.json").read_text(encoding="utf-8"))
    coverage["normalized_events_written"] = len(events)
    coverage["registry_user_activity_gaps"] = [
        {
            "artifact_family": "registry_user_activity",
            "artifact_type": "typedpaths",
            "gap_id": "gap_typedpaths",
            "impact": "TypedPaths key did not produce rows.",
            "reason": "no_rows",
            "recommended_next_step": "Confirm whether TypedPaths exists in NTUSER.DAT.",
            "source_artifact_id": "prep_ntuser",
        }
    ]
    (output_dir / "coverage_summary.json").write_text(
        json.dumps(coverage, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    return run


def fake_multi_profile_user_activity_workflow_runner(**kwargs) -> AgentRun:
    run = fake_workflow_runner(**kwargs)
    case_id = kwargs["case_id"]
    output_dir = kwargs["output_dir"]
    manifest = read_manifest(kwargs["manifest_path"])
    ntuser_artifacts = [
        artifact
        for artifact in manifest.artifacts
        if artifact.registry_hive_type == "ntuser"
    ]
    events = []
    sorted_ntuser_artifacts = sorted(
        ntuser_artifacts,
        key=lambda item: item.profile_id or "",
    )
    for index, artifact in enumerate(sorted_ntuser_artifacts):
        target = rf"C:\Users\analyst\Documents\ProjectAlpha\design-{index}.docx"
        events.append(
            {
                "artifact_family": "registry_user_activity",
                "artifact_id": artifact.artifact_id,
                "artifact_type": "recentdocs",
                "case_id": case_id,
                "event_id": f"ua_recentdocs_{artifact.profile_id}",
                "event_type": "registry_recent_document_candidate",
                "evidence_refs": [artifact.artifact_id],
                "metadata": {
                    "artifact_family": "registry_user_activity",
                    "profile_id": artifact.profile_id,
                    "source_id": "src_disk",
                    "source_role": "disk_image",
                    "target": target,
                },
                "parser_name": "recmd",
                "path": target,
                "profile_id": artifact.profile_id,
                "raw_record_ref": {
                    "record_id": f"ua_recentdocs_{artifact.profile_id}",
                    "row_number": 2,
                    "source_path": "recmd_recentdocs.csv",
                },
                "source_tool": "RECmd",
                "subject": target,
                "timestamp_description": "registry_key_last_write",
                "timestamp_utc": "2020-11-13T20:12:00Z",
            }
        )
    (output_dir / "normalized_events.json").write_text(
        json.dumps({"case_id": case_id, "event_count": len(events), "events": events}),
        encoding="utf-8",
    )
    coverage = json.loads((output_dir / "coverage_summary.json").read_text(encoding="utf-8"))
    coverage["normalized_events_written"] = len(events)
    coverage["registry_user_activity_gaps"] = [
        {
            "artifact_family": "registry_user_activity",
            "artifact_type": "typedpaths",
            "gap_id": f"gap_typedpaths_{artifact.profile_id}",
            "impact": "TypedPaths key did not produce rows.",
            "profile_id": artifact.profile_id,
            "reason": "no_rows",
            "recommended_next_step": "Confirm whether TypedPaths exists in NTUSER.DAT.",
            "source_artifact_id": artifact.artifact_id,
        }
        for artifact in ntuser_artifacts
    ]
    (output_dir / "coverage_summary.json").write_text(
        json.dumps(coverage, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    return run


def test_cli_exposes_agent_run_case(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["agent", "run-case", "--help"])

    assert exc.value.code == 0
    help_text = capsys.readouterr().out
    assert "--artifact-manifest" in help_text
    assert "--casebook" in help_text
    assert "--output-dir" in help_text
    assert "--command" not in help_text
    assert "--shell" not in help_text


def test_run_case_loads_synthetic_case_prep_and_writes_outputs(tmp_path: Path):
    case_prep_path, _case_prep_dir, _source_root = write_case_prep(tmp_path)
    output_dir = tmp_path / "runs" / CASE_ID / "agent-run"

    result = run_case_workflow(
        artifact_manifest_path=case_prep_path,
        output_dir=output_dir,
        max_iterations=10,
        workflow_runner=fake_workflow_runner,
        clock=fixed_clock,
    )

    assert result.case_id == CASE_ID
    assert result.run.status is AgentRunStatus.COMPLETED
    for filename in (
        "agent_run.json",
        "audit.jsonl",
        "coverage_summary.json",
        "normalized_events.json",
        "subject_timelines.json",
        "findings.json",
        "report.md",
        "case_questions.json",
        "decision_trace.json",
        "gap_analysis.json",
        "performance_summary.json",
    ):
        assert (output_dir / filename).is_file()


def test_run_case_rejects_missing_artifact_manifest(tmp_path: Path):
    with pytest.raises(ValueError, match="artifact manifest does not exist"):
        run_case_workflow(
            artifact_manifest_path=tmp_path / "missing.json",
            output_dir=tmp_path / "runs" / CASE_ID / "agent-run",
            max_iterations=10,
            workflow_runner=fake_workflow_runner,
            clock=fixed_clock,
        )


def test_run_case_rejects_invalid_json(tmp_path: Path):
    manifest = tmp_path / "runs" / CASE_ID / "case-prep" / "case_prep.json"
    manifest.parent.mkdir(parents=True)
    manifest.write_text("{not-json", encoding="utf-8")

    with pytest.raises(ValueError, match="malformed artifact manifest JSON"):
        run_case_workflow(
            artifact_manifest_path=manifest,
            output_dir=tmp_path / "runs" / CASE_ID / "agent-run",
            max_iterations=10,
            workflow_runner=fake_workflow_runner,
            clock=fixed_clock,
        )


def test_run_case_rejects_cli_case_id_mismatch(tmp_path: Path):
    case_prep_path, _case_prep_dir, _source_root = write_case_prep(tmp_path)

    with pytest.raises(ValueError, match="does not match requested case_id"):
        run_case_workflow(
            case_id="wrong-case",
            artifact_manifest_path=case_prep_path,
            output_dir=tmp_path / "runs" / CASE_ID / "agent-run",
            max_iterations=10,
            workflow_runner=fake_workflow_runner,
            clock=fixed_clock,
        )


def test_run_case_accepts_case_id_from_manifest(tmp_path: Path):
    case_prep_path, _case_prep_dir, _source_root = write_case_prep(tmp_path)

    result = run_case_workflow(
        artifact_manifest_path=case_prep_path,
        output_dir=tmp_path / "runs" / CASE_ID / "agent-run",
        max_iterations=10,
        workflow_runner=fake_workflow_runner,
        clock=fixed_clock,
    )

    assert result.case_id == CASE_ID


def test_run_case_rejects_output_under_mnt_evidence(tmp_path: Path):
    case_prep_path, _case_prep_dir, _source_root = write_case_prep(tmp_path)

    with pytest.raises(ValueError, match="evidence root"):
        run_case_workflow(
            artifact_manifest_path=case_prep_path,
            output_dir=Path("/mnt/evidence/runs/rocba-standard/agent-run"),
            max_iterations=10,
            workflow_runner=fake_workflow_runner,
            clock=fixed_clock,
        )


def test_run_case_rejects_output_under_raw_source_root(tmp_path: Path):
    case_prep_path, _case_prep_dir, source_root = write_case_prep(tmp_path)

    with pytest.raises(ValueError, match="source root"):
        run_case_workflow(
            artifact_manifest_path=case_prep_path,
            output_dir=source_root / "runs" / CASE_ID / "agent-run",
            max_iterations=10,
            workflow_runner=fake_workflow_runner,
            clock=fixed_clock,
        )


def test_run_case_skips_memory_and_marks_not_assessed(tmp_path: Path):
    case_prep_path, _case_prep_dir, _source_root = write_case_prep(tmp_path)
    output_dir = tmp_path / "runs" / CASE_ID / "agent-run"

    run_case_workflow(
        artifact_manifest_path=case_prep_path,
        output_dir=output_dir,
        max_iterations=10,
        workflow_runner=fake_workflow_runner,
        clock=fixed_clock,
    )
    gap_analysis = json.loads((output_dir / "gap_analysis.json").read_text(encoding="utf-8"))

    assert gap_analysis["memory_sources"][0]["source_id"] == "src_memory"
    assert gap_analysis["memory_sources"][0]["status"] == "not_assessed"
    manifest = read_manifest(output_dir / "adapted_manifest.json")
    assert all(artifact.source_image_id != "src_memory" for artifact in manifest.artifacts)


def test_run_case_converts_available_prepared_artifacts_to_agent_manifest(tmp_path: Path):
    case_prep_path, _case_prep_dir, _source_root = write_case_prep(tmp_path)
    output_dir = tmp_path / "runs" / CASE_ID / "agent-run"

    run_case_workflow(
        artifact_manifest_path=case_prep_path,
        output_dir=output_dir,
        max_iterations=10,
        workflow_runner=fake_workflow_runner,
        clock=fixed_clock,
    )
    manifest = read_manifest(output_dir / "adapted_manifest.json")

    assert manifest.case_id == CASE_ID
    assert {artifact.artifact_type for artifact in manifest.artifacts} == {
        "amcache",
        "mft",
        "registry_hive",
    }
    assert {artifact.source_image_id for artifact in manifest.artifacts} == {"src_disk"}
    assert all(artifact.source_image_label == "rocba-cdrive.e01" for artifact in manifest.artifacts)


def test_run_case_resolves_relative_prepared_paths_for_raw_parsers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    case_prep_path, _case_prep_dir, _source_root = write_case_prep(tmp_path)
    output_dir = tmp_path / "runs" / CASE_ID / "agent-run"
    seen_paths: list[Path] = []

    def fake_parser(**kwargs) -> ParserResult:
        artifact = kwargs["artifact"]
        artifact_path = Path(artifact.path)
        seen_paths.append(artifact_path)
        assert artifact_path.is_absolute()
        assert artifact_path.is_file()
        return ParserResult(
            case_id=kwargs["case_id"],
            artifact_id=artifact.artifact_id,
            artifact_type=artifact.artifact_type,
            parser_name="fixture",
            source_tool="fixture",
            status="success",
            started_at_utc=FIXED_TIME,
            ended_at_utc=FIXED_TIME,
        )

    monkeypatch.setattr("siftguard.agent.runner.parse_mft_artifact", fake_parser)
    monkeypatch.setattr("siftguard.agent.runner.parse_registry_runkeys_artifact", fake_parser)
    monkeypatch.setattr("siftguard.agent.runner.parse_amcache_artifact", fake_parser)

    run_case_workflow(
        artifact_manifest_path=case_prep_path,
        output_dir=output_dir,
        max_iterations=10,
        clock=fixed_clock,
    )

    assert len(seen_paths) == 3
    assert all(path.is_relative_to(case_prep_path.parent.resolve()) for path in seen_paths)


def test_run_case_records_partial_parser_results_without_confirmed_claims(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    case_prep_path, _case_prep_dir, _source_root = write_case_prep(tmp_path)
    output_dir = tmp_path / "runs" / CASE_ID / "agent-run"

    def partial_parser(**kwargs) -> ParserResult:
        artifact = kwargs["artifact"]
        return ParserResult(
            case_id=kwargs["case_id"],
            artifact_id=artifact.artifact_id,
            artifact_type=artifact.artifact_type,
            parser_name="fixture",
            source_tool="fixture",
            status="partial_success",
            warnings=["fixture partial parser result"],
            started_at_utc=FIXED_TIME,
            ended_at_utc=FIXED_TIME,
        )

    monkeypatch.setattr("siftguard.agent.runner.parse_mft_artifact", partial_parser)
    monkeypatch.setattr("siftguard.agent.runner.parse_registry_runkeys_artifact", partial_parser)
    monkeypatch.setattr("siftguard.agent.runner.parse_amcache_artifact", partial_parser)

    run_case_workflow(
        artifact_manifest_path=case_prep_path,
        output_dir=output_dir,
        max_iterations=10,
        clock=fixed_clock,
    )

    coverage = json.loads((output_dir / "coverage_summary.json").read_text(encoding="utf-8"))
    findings = json.loads((output_dir / "findings.json").read_text(encoding="utf-8"))

    assert {item["parser_status"] for item in coverage["per_artifact"]} == {
        "partial_success"
    }
    assert findings["finding_count"] == 0


def test_run_case_carries_case_prep_coverage_gaps(tmp_path: Path):
    case_prep_path, _case_prep_dir, _source_root = write_case_prep(tmp_path)
    output_dir = tmp_path / "runs" / CASE_ID / "agent-run"

    run_case_workflow(
        artifact_manifest_path=case_prep_path,
        output_dir=output_dir,
        max_iterations=10,
        workflow_runner=fake_workflow_runner,
        clock=fixed_clock,
    )
    gap_analysis = json.loads((output_dir / "gap_analysis.json").read_text(encoding="utf-8"))
    coverage = json.loads((output_dir / "coverage_summary.json").read_text(encoding="utf-8"))

    assert gap_analysis["carried_forward_case_prep_gaps"][0]["gap_id"] == "gap_ntuser"
    assert coverage["case_prep"]["coverage_gaps"][0]["gap_id"] == "gap_ntuser"


def test_run_case_outputs_do_not_expose_arbitrary_shell_fields(tmp_path: Path):
    case_prep_path, _case_prep_dir, _source_root = write_case_prep(tmp_path)
    output_dir = tmp_path / "runs" / CASE_ID / "agent-run"

    run_case_workflow(
        artifact_manifest_path=case_prep_path,
        output_dir=output_dir,
        max_iterations=10,
        workflow_runner=fake_workflow_runner,
        clock=fixed_clock,
    )
    combined = "\n".join(
        (output_dir / filename).read_text(encoding="utf-8")
        for filename in (
            "agent_run.json",
            "case_questions.json",
            "decision_trace.json",
            "gap_analysis.json",
            "performance_summary.json",
        )
    ).lower()

    for forbidden in ("raw_command", "\"command\"", "\"shell\"", "\"executable\""):
        assert forbidden not in combined


def test_json_casebook_input_is_accepted(tmp_path: Path):
    case_prep_path, _case_prep_dir, _source_root = write_case_prep(tmp_path)
    casebook_path = write_casebook(tmp_path)
    output_dir = tmp_path / "runs" / CASE_ID / "agent-run"

    result = run_case_workflow(
        artifact_manifest_path=case_prep_path,
        casebook_path=casebook_path,
        output_dir=output_dir,
        max_iterations=10,
        workflow_runner=fake_workflow_runner,
        clock=fixed_clock,
    )
    gap_analysis = json.loads((output_dir / "gap_analysis.json").read_text(encoding="utf-8"))

    assert result.casebook_path == casebook_path.resolve()
    assert gap_analysis["casebook_present"] is True
    assert gap_analysis["case_questions_count"] == 1
    assert (output_dir / "case_questions.json").is_file()


def test_run_case_writes_case_question_outputs_and_report_sections(tmp_path: Path):
    case_prep_path, _case_prep_dir, _source_root = write_case_prep(tmp_path)
    output_dir = tmp_path / "runs" / CASE_ID / "agent-run"

    run_case_workflow(
        artifact_manifest_path=case_prep_path,
        casebook_path=Path("docs/casebooks/rocba-standard.json"),
        output_dir=output_dir,
        max_iterations=10,
        workflow_runner=fake_workflow_runner,
        clock=fixed_clock,
    )

    case_questions = json.loads(
        (output_dir / "case_questions.json").read_text(encoding="utf-8")
    )
    gap_analysis = json.loads((output_dir / "gap_analysis.json").read_text(encoding="utf-8"))
    decision_trace = json.loads((output_dir / "decision_trace.json").read_text(encoding="utf-8"))
    report = (output_dir / "report.md").read_text(encoding="utf-8")

    assert case_questions["casebook_id"] == CASE_ID
    assert {question["question_id"] for question in case_questions["questions"]} >= {
        "q_memory",
        "q_what_was_stolen",
        "q_where_transferred",
        "q_how_stolen",
    }
    assert {
        question["status"]
        for question in case_questions["questions"]
        if question["question_id"] in {"q_memory", "q_what_was_stolen"}
    } == {"not_assessed"}
    assert gap_analysis["case_questions"]
    assert "not_assessed" in gap_analysis["status_counts"]
    decision_ids = {decision["decision_id"] for decision in decision_trace["decisions"]}
    assert {
        "casebook_intake",
        "provenance_verification",
        "validation_strategy",
        "correction_strategy",
        "case_question_mapping",
        "finding_status_assignment",
        "unsupported_question_gap_handling",
    } <= decision_ids
    for decision in decision_trace["decisions"]:
        assert {
            "decision_id",
            "phase",
            "question",
            "available_inputs",
            "selected_action",
            "rationale",
            "expected_outputs",
            "outcome",
            "next_action",
        } <= set(decision)
    for heading in (
        "## Case Questions Summary",
        "## Supported Findings",
        "## Needs Review",
        "## User Activity Summary",
        "## File Access / Recent Document Candidates",
        "## Program Use Candidates",
        "## Typed Path / User Navigation Candidates",
        "## Parser Coverage and User-Activity Gaps",
        "## Not Assessed / Scope Gaps",
        "## Evidence Provenance Summary",
        "## Analyst Next Steps",
    ):
        assert heading in report


def test_run_case_integrates_registry_user_activity_outputs(tmp_path: Path):
    case_prep_path, _case_prep_dir, _source_root = write_case_prep(tmp_path, include_gap=False)
    mark_ntuser_available(case_prep_path)
    add_ntuser_scope_warning(case_prep_path)
    casebook_path = write_user_activity_casebook(tmp_path)
    output_dir = tmp_path / "runs" / CASE_ID / "agent-run"

    run_case_workflow(
        artifact_manifest_path=case_prep_path,
        casebook_path=casebook_path,
        output_dir=output_dir,
        max_iterations=10,
        workflow_runner=fake_user_activity_workflow_runner,
        clock=fixed_clock,
    )

    normalized = json.loads((output_dir / "normalized_events.json").read_text(encoding="utf-8"))
    findings = json.loads((output_dir / "findings.json").read_text(encoding="utf-8"))
    questions = json.loads((output_dir / "case_questions.json").read_text(encoding="utf-8"))
    gap_analysis = json.loads((output_dir / "gap_analysis.json").read_text(encoding="utf-8"))
    decision_trace = json.loads((output_dir / "decision_trace.json").read_text(encoding="utf-8"))
    report = (output_dir / "report.md").read_text(encoding="utf-8")
    actions = [event["action"] for event in read_events(output_dir / "audit.jsonl")]

    assert any(
        event.get("artifact_family") == "registry_user_activity"
        for event in normalized["events"]
    )
    categories = {
        finding.get("finding_category")
        for finding in findings["findings"]
    }
    assert "file_access_candidate" in categories
    assert any(finding["status"] == "inferred" for finding in findings["findings"])
    question_by_id = {
        question["question_id"]: question for question in questions["questions"]
    }
    assert question_by_id["q_when_activity"]["linked_evidence_refs"]
    assert question_by_id["q_what_was_stolen"]["status"] == "not_assessed"
    assert question_by_id["q_where_transferred"]["status"] == "not_assessed"
    assert question_by_id["q_how_stolen"]["status"] == "not_assessed"
    assert question_by_id["q_memory"]["status"] == "not_assessed"
    assert gap_analysis["registry_user_activity"]["status"] == "partial_scope"
    assert (
        gap_analysis["registry_user_activity"]["prepared_hive_scope_warnings"][0][
            "recommended_next_step"
        ]
        == "Extract and inventory all user profile NTUSER.DAT hives before treating "
        "user-activity coverage as complete."
    )
    assert gap_analysis["registry_user_activity"]["coverage_gaps"][0]["reason"] == "no_rows"
    decision_ids = {decision["decision_id"] for decision in decision_trace["decisions"]}
    assert {
        "registry_user_activity_profile_selected",
        "ntuser_artifact_selected",
        "user_activity_parser_execution",
        "user_activity_normalization",
        "user_activity_finding_generation",
        "user_activity_case_question_mapping",
        "user_activity_coverage_gap_handling",
    } <= decision_ids
    assert "## User Activity Summary" in report
    assert "## Parser Coverage and User-Activity Gaps" in report
    assert "partial profile coverage" in report
    assert "user_activity_analysis_completed" in actions


def test_run_case_integrates_multiple_profile_ntuser_hives(tmp_path: Path):
    case_prep_path, _case_prep_dir, _source_root = write_case_prep(tmp_path, include_gap=False)
    replace_with_profile_ntuser_artifacts(case_prep_path)
    casebook_path = write_user_activity_casebook(tmp_path)
    output_dir = tmp_path / "runs" / CASE_ID / "agent-run"

    run_case_workflow(
        artifact_manifest_path=case_prep_path,
        casebook_path=casebook_path,
        output_dir=output_dir,
        max_iterations=10,
        workflow_runner=fake_multi_profile_user_activity_workflow_runner,
        clock=fixed_clock,
    )

    normalized = json.loads((output_dir / "normalized_events.json").read_text(encoding="utf-8"))
    findings = json.loads((output_dir / "findings.json").read_text(encoding="utf-8"))
    gap_analysis = json.loads((output_dir / "gap_analysis.json").read_text(encoding="utf-8"))
    decision_trace = json.loads((output_dir / "decision_trace.json").read_text(encoding="utf-8"))
    report = (output_dir / "report.md").read_text(encoding="utf-8")

    profile_ids = {
        event.get("profile_id")
        for event in normalized["events"]
        if event.get("artifact_family") == "registry_user_activity"
    }
    assert profile_ids == {"profile-0001", "profile-0002"}
    assert all(
        finding.get("profile_ids")
        for finding in findings["findings"]
        if finding.get("artifact_family") == "registry_user_activity"
    )
    profile_coverage = gap_analysis["registry_user_activity"]["profile_coverage"]
    assert profile_coverage["status"] == "assessed"
    assert profile_coverage["discovered_profile_count"] == 2
    assert profile_coverage["available_profile_count"] == 2
    assert profile_coverage["parsed_profile_count"] == 2
    assert {
        gap.get("profile_id")
        for gap in gap_analysis["registry_user_activity"]["coverage_gaps"]
    } == {"profile-0001", "profile-0002"}
    decision_ids = {decision["decision_id"] for decision in decision_trace["decisions"]}
    assert {
        "all_user_profile_hive_discovery",
        "per_profile_hive_extraction",
        "per_profile_user_activity_parsing",
        "profile_coverage_assessment",
        "multi_profile_finding_aggregation",
    } <= decision_ids
    assert "## User Profile Hive Coverage" in report
    assert "## User Activity Summary by Profile" in report
    assert "`profile-0001`" in report
    assert "`profile-0002`" in report


def test_yaml_casebook_input_is_rejected(tmp_path: Path):
    case_prep_path, _case_prep_dir, _source_root = write_case_prep(tmp_path)
    casebook_path = tmp_path / "casebook.yaml"
    casebook_path.write_text("case_id: rocba-standard\n", encoding="utf-8")

    with pytest.raises(ValueError, match=CASEBOOK_YAML_REJECTION):
        run_case_workflow(
            artifact_manifest_path=case_prep_path,
            casebook_path=casebook_path,
            output_dir=tmp_path / "runs" / CASE_ID / "agent-run",
            max_iterations=10,
            workflow_runner=fake_workflow_runner,
            clock=fixed_clock,
        )


def test_run_case_audit_includes_lifecycle_events(tmp_path: Path):
    case_prep_path, _case_prep_dir, _source_root = write_case_prep(tmp_path)
    output_dir = tmp_path / "runs" / CASE_ID / "agent-run"

    run_case_workflow(
        artifact_manifest_path=case_prep_path,
        output_dir=output_dir,
        max_iterations=10,
        workflow_runner=fake_workflow_runner,
        clock=fixed_clock,
    )
    actions = [event["action"] for event in read_events(output_dir / "audit.jsonl")]

    for expected in (
        "run_case_started",
        "artifact_manifest_loaded",
        "provenance_checked",
        "parser_plan_selected",
        "workflow_started",
        "workflow_completed",
        "run_case_completed",
    ):
        assert expected in actions
