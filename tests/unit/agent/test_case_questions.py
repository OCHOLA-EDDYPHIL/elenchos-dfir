from __future__ import annotations

import inspect
import json
from pathlib import Path
from typing import Any

from siftguard.agent import case_questions as case_questions_module
from siftguard.agent.case_manifest_adapter import adapt_case_prep_to_evidence_manifest
from siftguard.agent.case_questions import evaluate_case_questions
from siftguard.agent.casebook import Casebook, casebook_from_dict, load_casebook

CASE_ID = "rocba-standard"
CASEBOOK_PATH = Path("docs/casebooks/rocba-standard.json")


def write_case_prep(tmp_path: Path) -> Path:
    case_prep_dir = tmp_path / "runs" / CASE_ID / "case-prep"
    for relative, payload in {
        "extracted/mft/$MFT": b"mft",
        "extracted/registry/SOFTWARE": b"software",
        "extracted/amcache/Amcache.hve": b"amcache",
    }.items():
        path = case_prep_dir / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
    payload = {
        "case_id": CASE_ID,
        "coverage_gaps": [],
        "created_at": "2026-01-01T00:00:00Z",
        "output_dir": f"runs/{CASE_ID}/case-prep",
        "prepared_artifacts": [
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
        ],
        "source_set_id": "srcset_rocba",
        "sources": [
            {
                "analysis_scope": "primary",
                "display_name": "synthetic-disk.e01",
                "hash_status": "not_requested",
                "kind": "ewf_e01",
                "role": "disk_image",
                "sanitized_path": "synthetic-disk.e01",
                "sha256": None,
                "size_bytes": 10,
                "source_id": "src_disk",
                "source_ref": "synthetic-disk.e01",
                "status": "available",
            },
            {
                "analysis_scope": "out_of_scope_for_final_submission",
                "display_name": "synthetic-memory.raw",
                "hash_status": "not_requested",
                "kind": "raw",
                "role": "memory_image",
                "sanitized_path": "memory/synthetic-memory.raw",
                "sha256": None,
                "size_bytes": 20,
                "source_id": "src_memory",
                "source_ref": "memory/synthetic-memory.raw",
                "status": "staged_not_analyzed",
            },
        ],
        "status": "completed",
        "warnings": [],
    }
    path = case_prep_dir / "case_prep.json"
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    return path


def event(
    *,
    event_id: str,
    artifact_id: str,
    artifact_type: str,
    parser_name: str,
    event_type: str,
    timestamp: str,
    path: str,
    row_number: int,
) -> dict[str, Any]:
    return {
        "artifact_id": artifact_id,
        "artifact_type": artifact_type,
        "case_id": CASE_ID,
        "confidence": "tool_reported",
        "event_id": event_id,
        "event_type": event_type,
        "evidence_refs": [artifact_id],
        "parser_name": parser_name,
        "path": path,
        "raw_record_ref": {"row_number": row_number, "source_path": f"{parser_name}.csv"},
        "source_tool": parser_name,
        "status": "normalized",
        "subject": path,
        "timestamp_description": "synthetic",
        "timestamp_utc": timestamp,
    }


def case_context(tmp_path: Path) -> tuple[Casebook, Any]:
    casebook = load_casebook(CASEBOOK_PATH, case_id=CASE_ID)
    adapted = adapt_case_prep_to_evidence_manifest(
        case_prep_path=write_case_prep(tmp_path),
        requested_case_id=CASE_ID,
    )
    return casebook, adapted


def profile_casebook(*, keywords: list[str]) -> Casebook:
    payload = json.loads(CASEBOOK_PATH.read_text(encoding="utf-8"))
    payload["triage_profile"] = {
        "keywords": keywords,
        "sensitive_paths": [],
        "file_extensions": [],
    }
    return casebook_from_dict(payload)


def question_by_id(payload: dict[str, Any], question_id: str) -> dict[str, Any]:
    for question in payload["questions"]:
        if question["question_id"] == question_id:
            return question
    raise AssertionError(f"missing question {question_id}")


def test_engine_has_no_rocba_specific_hardcoded_candidate_marker():
    source = inspect.getsource(case_questions_module).casefold()

    assert "srl" not in source


def test_case_question_output_is_deterministic(tmp_path: Path):
    casebook, adapted = case_context(tmp_path)
    rows = [
        event(
            event_id="evt_amcache",
            artifact_id="prep_amcache",
            artifact_type="amcache",
            parser_name="amcacheparser",
            event_type="amcache_execution",
            timestamp="2026-01-01T00:00:00Z",
            path="C:/ProgramData/srl-tool.exe",
            row_number=2,
        ),
        event(
            event_id="evt_mft",
            artifact_id="prep_mft",
            artifact_type="mft",
            parser_name="mftecmd",
            event_type="file_created",
            timestamp="2026-01-01T00:05:00Z",
            path="C:/Projects/SRL/srl-tool.exe",
            row_number=3,
        ),
    ]

    first = evaluate_case_questions(
        casebook=casebook,
        adapted=adapted,
        normalized_events=rows,
        findings=[],
        created_at="2026-01-01T00:00:00Z",
    )
    second = evaluate_case_questions(
        casebook=casebook,
        adapted=adapted,
        normalized_events=list(reversed(rows)),
        findings=[],
        created_at="2026-01-01T00:00:00Z",
    )

    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)


def test_unsupported_questions_become_not_assessed(tmp_path: Path):
    casebook, adapted = case_context(tmp_path)
    result = evaluate_case_questions(
        casebook=casebook,
        adapted=adapted,
        normalized_events=[],
        findings=[],
        created_at="2026-01-01T00:00:00Z",
    )

    for question_id in (
        "q_memory",
        "q_what_was_stolen",
        "q_where_transferred",
        "q_how_stolen",
    ):
        question = question_by_id(result, question_id)
        assert question["status"] == "not_assessed"
        assert question["gaps"]


def test_casebook_profile_keywords_prioritize_candidates_generically(tmp_path: Path):
    _casebook, adapted = case_context(tmp_path)
    result = evaluate_case_questions(
        casebook=profile_casebook(keywords=["apollo"]),
        adapted=adapted,
        normalized_events=[
            event(
                event_id="evt_unmatched",
                artifact_id="prep_mft",
                artifact_type="mft",
                parser_name="mftecmd",
                event_type="file_created",
                timestamp="2020-11-13T14:00:00Z",
                path="C:/Temp/random.tmp",
                row_number=1,
            ),
            event(
                event_id="evt_profile_keyword",
                artifact_id="prep_mft",
                artifact_type="mft",
                parser_name="mftecmd",
                event_type="file_created",
                timestamp="2020-11-13T15:00:00Z",
                path="C:/Temp/apollo-plan.tmp",
                row_number=2,
            ),
        ],
        findings=[],
        created_at="2026-01-01T00:00:00Z",
    )

    question = question_by_id(result, "q_project_file_candidates")
    assert question["status"] == "needs_review"
    assert [ref["event_id"] for ref in question["linked_evidence_refs"]] == [
        "evt_profile_keyword"
    ]
    assert question_by_id(result, "q_what_was_stolen")["status"] == "not_assessed"
    assert question_by_id(result, "q_where_transferred")["status"] == "not_assessed"
    assert question_by_id(result, "q_how_stolen")["status"] == "not_assessed"
    assert question_by_id(result, "q_memory")["status"] == "not_assessed"


def test_single_weak_artifact_is_needs_review_not_inferred_or_confirmed(tmp_path: Path):
    casebook, adapted = case_context(tmp_path)
    result = evaluate_case_questions(
        casebook=casebook,
        adapted=adapted,
        normalized_events=[
            event(
                event_id="evt_mft",
                artifact_id="prep_mft",
                artifact_type="mft",
                parser_name="mftecmd",
                event_type="file_created",
                timestamp="2020-11-13T15:00:00Z",
                path="C:/Projects/SRL/design.docx",
                row_number=2,
            )
        ],
        findings=[],
        created_at="2026-01-01T00:00:00Z",
    )

    question = question_by_id(result, "q_project_file_candidates")
    assert question["status"] == "needs_review"
    assert question["linked_evidence_refs"]
    assert question["source_provenance_refs"][0]["source_id"] == "src_disk"


def test_multiple_independent_supported_artifacts_may_infer(tmp_path: Path):
    casebook, adapted = case_context(tmp_path)
    result = evaluate_case_questions(
        casebook=casebook,
        adapted=adapted,
        normalized_events=[
            event(
                event_id="evt_mft",
                artifact_id="prep_mft",
                artifact_type="mft",
                parser_name="mftecmd",
                event_type="file_created",
                timestamp="2026-01-01T00:00:00Z",
                path="C:/Projects/SRL/srl-tool.exe",
                row_number=2,
            ),
            event(
                event_id="evt_amcache",
                artifact_id="prep_amcache",
                artifact_type="amcache",
                parser_name="amcacheparser",
                event_type="amcache_execution",
                timestamp="2026-01-01T00:05:00Z",
                path="C:/Projects/SRL/srl-tool.exe",
                row_number=3,
            ),
        ],
        findings=[],
        created_at="2026-01-01T00:00:00Z",
    )

    assert question_by_id(result, "q_program_presence_execution")["status"] == "inferred"


def test_confirmed_requires_strict_threshold_and_evidence_refs(tmp_path: Path):
    casebook, adapted = case_context(tmp_path)
    result = evaluate_case_questions(
        casebook=casebook,
        adapted=adapted,
        normalized_events=[
            event(
                event_id="evt_mft",
                artifact_id="prep_mft",
                artifact_type="mft",
                parser_name="mftecmd",
                event_type="file_created",
                timestamp="2020-11-13T15:00:00Z",
                path="C:/Projects/SRL/srl-tool.exe",
                row_number=2,
            ),
            event(
                event_id="evt_amcache",
                artifact_id="prep_amcache",
                artifact_type="amcache",
                parser_name="amcacheparser",
                event_type="amcache_execution",
                timestamp="2020-11-13T15:05:00Z",
                path="C:/Projects/SRL/srl-tool.exe",
                row_number=3,
            ),
        ],
        findings=[],
        created_at="2026-01-01T00:00:00Z",
    )

    question = question_by_id(result, "q_when_activity")
    assert question["status"] == "confirmed"
    assert len(question["linked_evidence_refs"]) == 2
    assert {ref["artifact_id"] for ref in question["linked_evidence_refs"]} == {
        "prep_amcache",
        "prep_mft",
    }


def test_rejected_finding_maps_question_to_rejected(tmp_path: Path):
    casebook, adapted = case_context(tmp_path)
    result = evaluate_case_questions(
        casebook=casebook,
        adapted=adapted,
        normalized_events=[],
        findings=[
            {
                "finding_id": "F-REJECTED-001",
                "status": "rejected",
                "evidence_refs": [
                    {
                        "artifact_id": "prep_software",
                        "parser": "recmd",
                        "source": "registry_hive",
                    }
                ],
            }
        ],
        created_at="2026-01-01T00:00:00Z",
    )

    question = question_by_id(result, "q_persistence")
    assert question["status"] == "rejected"
    assert question["linked_finding_ids"] == ["F-REJECTED-001"]
